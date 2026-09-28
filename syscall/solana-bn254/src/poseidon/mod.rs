//! Poseidon hash implementation using the Fr scalar field.
//!
//! Uses sparse matrices for partial rounds and scalar or AVX-512 IFMA
//! arithmetic selected by the compile target and state width.
//!
//! # Hybrid Execution Architecture
//! - Partial Rounds: A scalar S-box updates `state[0]`. Built-in sparse matrix
//!   products use IFMA lanes where available; custom tables use scalar arithmetic.
//! - Full Rounds: The target and width select scalar or eight-lane SIMD layers.

use crate::backend::{Backend, Fr, MontgomeryBackend, U256};

pub mod constants;
mod scalar;

#[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
mod packed;
#[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
mod simd;

/// Sparse matrix representation for Poseidon partial rounds.
///
/// Precomputing the MDS matrix transitions into a sparse vector form reduces
/// the `O(T^2)` dense matrix multiplication down to an `O(T)` sparse matrix
/// computation.
///
/// `row` is the matrix's first row; `col[i]` for `i >= 1` is the entry at
/// `[i][0]`. All other entries are the identity, and `col[0]` is unused.
#[derive(Clone, Debug)]
pub struct SparseMatrix<const T: usize> {
    pub row: [U256; T],
    pub col: [U256; T],
}

/// Constants required for Poseidon execution over a state of width `T`.
///
/// # Layout
/// `round_constants` holds exactly `T * full_rounds + partial_rounds` elements
/// in Montgomery form, ordered as `T` per full round in the first half, then one
/// per partial round, then `T` per full round in the second half.
///
/// The factorization follows the optimized Poseidon construction: the final full
/// round of the first half applies `pre_sparse_matrix` in place of `mds_matrix`,
/// and each partial round applies its own `SparseMatrix`. See
/// [`constants`] for the default circom-compatible parameters.
pub struct PoseidonConstants<const T: usize> {
    pub full_rounds: usize,
    pub partial_rounds: usize,
    pub round_constants: &'static [U256],
    pub mds_matrix: &'static [[U256; T]; T],
    pub pre_sparse_matrix: &'static [[U256; T]; T],
    pub sparse_matrices: &'static [SparseMatrix<T>],
}

/// Computes the scalar Poseidon S-box (`x^5`) with two squares and one multiplication.
#[inline(always)]
pub fn sbox(x: &U256) -> U256 {
    type B = Backend<Fr>;
    let x2 = B::sqr(x);
    let x4 = B::sqr(&x2);
    B::mul(&x4, x)
}

/// Computes 8 Poseidon S-boxes simultaneously utilizing AVX-512 vectorization.
///
/// The state is processed in groups of eight; the final group may be partly filled.
#[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn apply_sbox_simd<const T: usize>(state: &mut [U256; T]) {
    use crate::backend::avx512::{
        math::sbox_8x,
        pack::{pack_8x, unpack_8x_into},
    };
    let mut i = 0;

    // Process state in chunks of 8 to saturate the SIMD lanes
    while i < T {
        let chunk_size = core::cmp::min(8, T - i);
        let mut chunk = [U256::zero(); 8];
        chunk[..chunk_size].copy_from_slice(&state[i..i + chunk_size]);

        unsafe {
            let packed = pack_8x(&chunk);
            let sboxed = sbox_8x(&packed);
            unpack_8x_into(&sboxed, &mut chunk);
        }

        state[i..i + chunk_size].copy_from_slice(&chunk[..chunk_size]);
        i += chunk_size;
    }
}

/// Computes a dense Matrix-Vector multiplication using AVX-512 Column-Accumulation.
///
/// Instead of computing rows sequentially (`T^2` multiplications), we broadcast
/// the scalar `state[j]`, pack the Matrix Column `j` into a SIMD vector, and execute
/// parallel multiplications.
///
/// # Input criteria
/// Every element of `state` and of `mds` must be a fully reduced Montgomery-form
/// field element (`x < Fr::MODULUS`). Packed multiplication and addition both
/// return canonical residues. Accumulate a complete output chunk before
/// unpacking it into the scalar representation.
#[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn apply_dense_matrix_simd<const T: usize>(state: &mut [U256; T], mds: &[[U256; T]; T]) {
    use crate::backend::avx512::{
        math::{sum_of_products_8x, sum_products_8x},
        pack::{broadcast, pack_8x, unpack_8x_into},
    };
    let columns = packed::dense(mds);
    let mut new_state = [U256::zero(); T];
    let mut i = 0;
    while i < T {
        let chunk_size = core::cmp::min(8, T - i);
        let sum = if let Some(columns) = columns {
            // Built-in tables have T<=13 and canonical R260 coefficients.
            unsafe {
                sum_products_8x::<T>(|j| (broadcast(&state[j]), columns[(i / 8) * T + j].load()))
            }
        } else {
            // Caller-provided matrices remain in R256 and use the generic
            // chunked kernel. Built-in R260 tables use the specialized path above.
            let inputs = state.map(|value| unsafe { broadcast(&value) });
            let columns = core::array::from_fn(|j| {
                let mut column = [U256::zero(); 8];
                for (k, word) in column[..chunk_size].iter_mut().enumerate() {
                    *word = mds[i + k][j];
                }
                unsafe { pack_8x(&column) }
            });
            unsafe { sum_of_products_8x(&inputs, &columns) }
        };
        let mut chunk = [U256::zero(); 8];
        unsafe { unpack_8x_into(&sum, &mut chunk) };
        new_state[i..i + chunk_size].copy_from_slice(&chunk[..chunk_size]);
        i += chunk_size;
    }
    *state = new_state;
}

/// Branchlessly executes a dense matrix multiplication on the scalar state.
#[cfg(not(all(target_arch = "x86_64", target_feature = "avx512ifma")))]
#[inline(always)]
fn apply_dense_matrix<const T: usize>(state: &mut [U256; T], m: &[[U256; T]; T]) {
    let new_state = core::array::from_fn(|i| scalar::sum_products(&m[i], state));
    *state = new_state;
}

/// Computes only the first output of a dense matrix multiplication.
#[inline(always)]
fn apply_dense_matrix_row0<const T: usize>(state: &mut [U256; T], m: &[[U256; T]; T]) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
    if simd::use_simd_row0::<T>() {
        if let Some(value) = unsafe { simd::matrix_row0(state, m) } {
            state[0] = value;
            return;
        }
    }
    state[0] = scalar::sum_products(&m[0], state);
}

/// Executes an `O(T)` sparse matrix multiplication on the scalar state.
#[inline(always)]
fn apply_sparse_matrix<const T: usize>(state: &mut [U256; T], m: &SparseMatrix<T>) {
    type B = Backend<Fr>;
    let first_word = scalar::sum_products(&m.row, state);
    let prev_first = state[0];
    state[0] = first_word;
    for (i, state_val) in state.iter_mut().enumerate().skip(1) {
        let term = B::mul(&m.col[i], &prev_first);
        *state_val = B::add(state_val, &term);
    }
}

/// Multiplies the sparse row and column terms in one stream of IFMA lanes.
/// The first T terms form the row dot product; the remaining T-1 terms update
/// the column. In particular, widths 2..=4 use only one vector multiplication.
#[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn apply_sparse_matrix_simd<const T: usize>(
    state: &mut [U256; T],
    coefficients: &[packed::Packed],
) {
    use crate::backend::avx512::{
        math::mul_fixed_8x,
        pack::{pack_8x, unpack_8x_into},
    };
    type B = Backend<Fr>;
    let previous_first = state[0];
    let mut first_word = U256::zero();
    for (chunk_index, coefficient) in coefficients.iter().enumerate() {
        let first = chunk_index * 8;
        let count = core::cmp::min(8, 2 * T - 1 - first);
        let mut terms = [U256::zero(); 8];
        // Gather every input before updating any coordinates. Since row terms
        // precede column terms, an updated column is never a later row input.
        for (lane, term) in terms[..count].iter_mut().enumerate() {
            let index = first + lane;
            *term = if index < T {
                state[index]
            } else {
                previous_first
            };
        }
        unsafe {
            let product = mul_fixed_8x(&pack_8x(&terms), &coefficient.load());
            unpack_8x_into(&product, &mut terms);
        }
        for (lane, term) in terms[..count].iter().enumerate() {
            let index = first + lane;
            if index < T {
                first_word = if index == 0 {
                    *term
                } else {
                    B::add(&first_word, term)
                };
            } else {
                let index = index - T + 1;
                state[index] = B::add(&state[index], term);
            }
        }
    }
    state[0] = first_word;
}

/// Applies one S-box in scalar full rounds.
///
/// Keep this call separate to discourage vectorizing across state elements.
#[cfg(not(all(target_arch = "x86_64", target_feature = "avx512ifma")))]
#[inline(never)]
fn apply_sbox_scalar(state_val: &mut U256) {
    *state_val = sbox(state_val);
}

/// Applies the S-box to every state element, routing to SIMD where available.
#[inline(always)]
fn sbox_layer<const T: usize>(state: &mut [U256; T]) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
    unsafe {
        apply_sbox_simd(state);
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx512ifma")))]
    for state_val in state.iter_mut() {
        if cfg!(target_arch = "x86_64") && (T == 4 || T == 8) {
            apply_sbox_scalar(state_val);
        } else {
            *state_val = sbox(state_val);
        }
    }
}

/// Applies a dense matrix to the state, routing to SIMD where available.
#[inline(always)]
fn dense_layer<const T: usize>(state: &mut [U256; T], m: &[[U256; T]; T]) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
    unsafe {
        apply_dense_matrix_simd(state, m);
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx512ifma")))]
    apply_dense_matrix(state, m);
}

/// Executes the Poseidon permutation on a state already in Montgomery form.
///
/// Every element of `state` must be a fully reduced Montgomery-form field
/// element (`x < Fr::MODULUS`), per the `MontgomeryBackend` contract.
pub fn poseidon<const T: usize>(state: [U256; T], constants: &PoseidonConstants<T>) -> [U256; T] {
    poseidon_inner::<T, false>(state, constants)
}

/// Applies the partial rounds between the packed full-round halves.
#[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
#[inline(always)]
fn partial_rounds<const T: usize>(
    state: &mut [U256; T],
    constants: &PoseidonConstants<T>,
    mut rc_idx: usize,
) {
    type B = Backend<Fr>;
    let rc = constants.round_constants;
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
    let packed_sparse = packed::sparse(constants.sparse_matrices);
    // --- Middle: Partial Rounds ---
    // Only state[0] receives an S-box. The independent matrix products can
    // share IFMA lanes, while the single S-box stays scalar.
    for sparse_idx in 0..constants.partial_rounds {
        state[0] = B::add(&state[0], &rc[rc_idx]);
        rc_idx += 1;
        state[0] = sbox(&state[0]);
        #[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
        if let Some(matrices) = packed_sparse {
            let stride = (2 * T - 1).div_ceil(8);
            unsafe {
                apply_sparse_matrix_simd(
                    state,
                    &matrices[sparse_idx * stride..(sparse_idx + 1) * stride],
                );
            }
        } else {
            apply_sparse_matrix(state, &constants.sparse_matrices[sparse_idx]);
        }
        #[cfg(not(all(target_arch = "x86_64", target_feature = "avx512ifma")))]
        apply_sparse_matrix(state, &constants.sparse_matrices[sparse_idx]);
    }
}

/// With `HASH_ONLY`, only the returned `state[0]` is a valid output coordinate.
fn poseidon_inner<const T: usize, const HASH_ONLY: bool>(
    mut state: [U256; T],
    constants: &PoseidonConstants<T>,
) -> [U256; T] {
    type B = Backend<Fr>;
    let half_full = constants.full_rounds / 2;
    let rc = constants.round_constants;
    debug_assert_eq!(
        rc.len(),
        T * constants.full_rounds + constants.partial_rounds
    );
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
    if unsafe { simd::permutation::<T, HASH_ONLY>(&mut state, constants) } {
        return state;
    }
    let mut rc_idx = 0;
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
    let packed_sparse = packed::sparse(constants.sparse_matrices);

    // --- First Half: Full Rounds ---
    // The final round applies `pre_sparse_matrix`, setting up the sparse
    // factorization that the partial rounds rely on.
    for round in 0..half_full {
        for state_val in state.iter_mut() {
            *state_val = B::add(state_val, &rc[rc_idx]);
            rc_idx += 1;
        }
        sbox_layer(&mut state);
        if round + 1 == half_full {
            dense_layer(&mut state, constants.pre_sparse_matrix);
        } else {
            dense_layer(&mut state, constants.mds_matrix);
        }
    }

    // --- Middle: Partial Rounds ---
    // Only state[0] receives an S-box. The independent matrix products can
    // share IFMA lanes, while the single S-box stays scalar.
    for sparse_idx in 0..constants.partial_rounds {
        state[0] = B::add(&state[0], &rc[rc_idx]);
        rc_idx += 1;
        state[0] = sbox(&state[0]);
        #[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
        if let Some(matrices) = packed_sparse {
            let stride = (2 * T - 1).div_ceil(8);
            unsafe {
                apply_sparse_matrix_simd(
                    &mut state,
                    &matrices[sparse_idx * stride..(sparse_idx + 1) * stride],
                );
            }
        } else {
            apply_sparse_matrix(&mut state, &constants.sparse_matrices[sparse_idx]);
        }
        #[cfg(not(all(target_arch = "x86_64", target_feature = "avx512ifma")))]
        apply_sparse_matrix(&mut state, &constants.sparse_matrices[sparse_idx]);
    }

    // --- Second Half: Full Rounds ---
    for round in 0..half_full {
        for state_val in state.iter_mut() {
            *state_val = B::add(state_val, &rc[rc_idx]);
            rc_idx += 1;
        }
        sbox_layer(&mut state);
        if HASH_ONLY && round + 1 == half_full {
            apply_dense_matrix_row0(&mut state, constants.mds_matrix);
        } else {
            dense_layer(&mut state, constants.mds_matrix);
        }
    }

    state
}

/// Hashes `T - 1` field elements under the circom-compatible Poseidon
/// construction: a zero capacity element in `state[0]`, the inputs in
/// `state[1..]`, one permutation, and `state[0]` as the digest.
///
/// Inputs are Montgomery-form field elements. Returns `None` if
/// `inputs.len() != T - 1`, or if any input is not fully reduced —
/// an unreduced input would otherwise alias the value congruent to it,
/// so `MODULUS` and `0` would hash identically.
pub fn hash<const T: usize>(inputs: &[U256], constants: &PoseidonConstants<T>) -> Option<U256> {
    if inputs.len() + 1 != T {
        return None;
    }
    if !inputs.iter().all(Backend::<Fr>::is_reduced) {
        return None;
    }
    let mut state = [U256::zero(); T];
    state[1..].copy_from_slice(inputs);
    Some(poseidon_inner::<T, true>(state, constants)[0])
}
