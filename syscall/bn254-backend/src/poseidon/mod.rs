//! Poseidon hash implementation using the Fr scalar field.
//!
//! Includes optimized scalar execution routes using sparse matrices
//! for partial rounds, alongside an AVX-512 IFMA batched execution route
//! for maximum throughput on supporting hardware.
//!
//! # Hybrid Execution Architecture
//! - Partial Rounds: Uses strictly scalar logic. Because only the first element
//!   `state[0]` receives an S-box, parallelization provides no benefit here.
//! - Full Rounds: On CPUs supporting `AVX-512 IFMA`, selected at run time,
//!   the full rounds route to an 8-way batched SIMD engine.

use crate::backend::{Backend, Fr, MontgomeryBackend, U256};

pub mod constants;

/// Sparse matrix representation for Poseidon partial rounds.
///
/// Precomputing the MDS matrix transitions into a sparse vector form reduces
/// the `O(T^2)` dense matrix multiplication down to an `O(T)` sparse matrix
/// computation, saving massive Compute Units on-chain.
///
/// `row` is the matrix's first row; `col[i]` for `i >= 1` is the entry at
/// `[i][0]`. All other entries are the identity, and `col[0]` is unused.
struct SparseMatrix<const T: usize> {
    row: [U256; T],
    col: [U256; T],
}

/// Constants required for Poseidon execution over a state of width `T`.
///
/// The fields are private, so the only instances are the generated
/// circom-compatible parameters in [`constants`] and the permutation can rely
/// on their layout.
pub struct PoseidonConstants<const T: usize> {
    full_rounds: usize,
    partial_rounds: usize,
    /// Exactly `T * full_rounds + partial_rounds` elements in Montgomery form,
    /// ordered as `T` per full round in the first half, then one per partial
    /// round, then `T` per full round in the second half.
    round_constants: &'static [U256],
    mds_matrix: &'static [[U256; T]; T],
    /// The factorization follows the optimized Poseidon construction: the
    /// final full round of the first half applies this matrix in place of
    /// `mds_matrix`.
    pre_sparse_matrix: &'static [[U256; T]; T],
    /// Exactly `partial_rounds` matrices, one applied by each partial round.
    sparse_matrices: &'static [SparseMatrix<T>],
}

/// Computes the scalar Poseidon S-box (`x^5`) using exactly 3 inlined multiplications.
///
/// `x` must be a fully reduced Montgomery-form field element
/// (`x < Fr::MODULUS`), per the `MontgomeryBackend` contract.
#[inline(always)]
pub fn sbox(x: &U256) -> U256 {
    type B = Backend<Fr>;
    let x2 = B::sqr(x);
    let x4 = B::sqr(&x2);
    B::mul(&x4, x)
}

/// Packs lanes from memory LLVM cannot see through. Rebuilding them from the
/// caller's scalars can stall LLVM's X86 backend indefinitely in some generic
/// Poseidon instances, depending on inlining.
#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn pack_opaque(lanes: &[U256; 8]) -> crate::backend::avx512::FieldElement8x52 {
    unsafe { crate::backend::avx512::pack::pack_8x(core::hint::black_box(lanes)) }
}

/// Computes 8 Poseidon S-boxes simultaneously utilizing AVX-512 vectorization.
///
/// The state is dynamically chunked in groups of 8. This guarantees full utilization
/// of the SIMD registers for large state widths.
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn apply_sbox_simd<const T: usize>(state: &mut [U256; T]) {
    use crate::backend::avx512::{math::sbox_8x, pack::unpack_8x_into};
    let mut i = 0;

    // Process state in chunks of 8 to saturate the SIMD lanes
    while i < T {
        let chunk_size = core::cmp::min(8, T - i);
        let mut chunk = [U256::zero(); 8];
        chunk[..chunk_size].copy_from_slice(&state[i..i + chunk_size]);

        unsafe {
            let packed = pack_opaque(&chunk);
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
/// field element (`x < Fr::MODULUS`).
#[cfg(target_arch = "x86_64")]
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn apply_dense_matrix_simd<const T: usize>(state: &mut [U256; T], mds: &[[U256; T]; T]) {
    use crate::backend::avx512::{
        math::sum_of_products_8x,
        pack::{broadcast, unpack_8x_into},
    };

    let inputs = state.map(|value| unsafe { broadcast(&value) });
    let mut new_state = [U256::zero(); T];
    let mut i = 0;
    while i < T {
        let chunk_size = core::cmp::min(8, T - i);
        let columns = core::array::from_fn(|j| {
            let mut col_chunk = [U256::zero(); 8];
            for (k, word) in col_chunk[..chunk_size].iter_mut().enumerate() {
                *word = mds[i + k][j];
            }
            unsafe { pack_opaque(&col_chunk) }
        });

        let mut chunk = [U256::zero(); 8];
        unsafe { unpack_8x_into(&sum_of_products_8x(&inputs, &columns), &mut chunk) };
        new_state[i..i + chunk_size].copy_from_slice(&chunk[..chunk_size]);
        i += chunk_size;
    }
    *state = new_state;
}

/// Branchlessly executes a dense matrix multiplication on the scalar state.
#[inline(always)]
fn apply_dense_matrix<const T: usize>(state: &mut [U256; T], m: &[[U256; T]; T]) {
    type B = Backend<Fr>;
    let input = *state;
    for (value, row) in state.iter_mut().zip(m) {
        *value = B::sum_of_products(row, &input);
    }
}

/// Computes only the first output of a dense matrix multiplication.
#[inline(always)]
fn apply_dense_matrix_row0<const T: usize>(state: &mut [U256; T], m: &[[U256; T]; T]) {
    state[0] = Backend::<Fr>::sum_of_products(&m[0], state);
}

/// Executes an `O(T)` sparse matrix multiplication on the scalar state.
#[inline(always)]
fn apply_sparse_matrix<const T: usize>(state: &mut [U256; T], m: &SparseMatrix<T>) {
    type B = Backend<Fr>;
    let prev_first = state[0];
    state[0] = B::sum_of_products(&m.row, state);

    // Identity operations scaled by the sparse column vector
    for (i, state_val) in state.iter_mut().enumerate().skip(1) {
        let term = B::mul(&m.col[i], &prev_first);
        *state_val = B::add(state_val, &term);
    }
}

/// Applies one S-box in scalar full rounds.
///
/// Keep this call separate to discourage vectorizing across state elements.
#[inline(never)]
fn apply_sbox_scalar(state_val: &mut U256) {
    *state_val = sbox(state_val);
}

/// Applies the S-box to every state element, routing to SIMD where available.
#[inline(always)]
fn sbox_layer<const T: usize, const IFMA: bool>(state: &mut [U256; T]) {
    #[cfg(target_arch = "x86_64")]
    if IFMA {
        // SAFETY: IFMA instances run only on CPUs with the IFMA kernels.
        unsafe { apply_sbox_simd(state) };
        return;
    }
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
fn dense_layer<const T: usize, const IFMA: bool>(state: &mut [U256; T], m: &[[U256; T]; T]) {
    #[cfg(target_arch = "x86_64")]
    if IFMA {
        // SAFETY: IFMA instances run only on CPUs with the IFMA kernels.
        unsafe { apply_dense_matrix_simd(state, m) };
        return;
    }
    apply_dense_matrix(state, m);
}

/// Executes the Poseidon permutation on a state already in Montgomery form.
///
/// Every element of `state` must be a fully reduced Montgomery-form field
/// element (`x < Fr::MODULUS`), per the `MontgomeryBackend` contract.
pub fn poseidon<const T: usize>(state: [U256; T], constants: &PoseidonConstants<T>) -> [U256; T] {
    permute::<T, false>(state, constants)
}

/// Runs the IFMA permutation when the CPU supports it, else the scalar one.
/// The single-input width measured faster on the scalar path.
#[inline(always)]
fn permute<const T: usize, const HASH_ONLY: bool>(
    state: [U256; T],
    constants: &PoseidonConstants<T>,
) -> [U256; T] {
    #[cfg(target_arch = "x86_64")]
    if T > 2 && crate::backend::cpu::has_ifma() {
        // SAFETY: the CPU supports every feature the IFMA instance enables.
        return unsafe { poseidon_ifma::<T, HASH_ONLY>(state, constants) };
    }
    poseidon_inner::<T, HASH_ONLY, false>(state, constants)
}

/// Compiles the IFMA instance, including its inlined scalar code, with the
/// vector features enabled.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn poseidon_ifma<const T: usize, const HASH_ONLY: bool>(
    state: [U256; T],
    constants: &PoseidonConstants<T>,
) -> [U256; T] {
    poseidon_inner::<T, HASH_ONLY, true>(state, constants)
}

/// With `HASH_ONLY`, only the returned `state[0]` is a valid output coordinate.
/// `IFMA` instances may only run on CPUs with the IFMA kernels.
#[inline(always)]
fn poseidon_inner<const T: usize, const HASH_ONLY: bool, const IFMA: bool>(
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
    let mut rc_idx = 0;

    // --- First Half: Full Rounds ---
    // The final round applies `pre_sparse_matrix`, setting up the sparse
    // factorization that the partial rounds rely on.
    for round in 0..half_full {
        for state_val in state.iter_mut() {
            *state_val = B::add(state_val, &rc[rc_idx]);
            rc_idx += 1;
        }
        sbox_layer::<T, IFMA>(&mut state);
        if round + 1 == half_full {
            dense_layer::<T, IFMA>(&mut state, constants.pre_sparse_matrix);
        } else {
            dense_layer::<T, IFMA>(&mut state, constants.mds_matrix);
        }
    }

    // --- Middle: Partial Rounds ---
    // Kept strictly scalar because only state[0] receives the S-box computation,
    // rendering SIMD parallelization overhead highly inefficient here.
    for sparse_matrix in &constants.sparse_matrices[..constants.partial_rounds] {
        state[0] = B::add(&state[0], &rc[rc_idx]);
        rc_idx += 1;
        state[0] = sbox(&state[0]);
        apply_sparse_matrix(&mut state, sparse_matrix);
    }

    // --- Second Half: Full Rounds ---
    for round in 0..half_full {
        for state_val in state.iter_mut() {
            *state_val = B::add(state_val, &rc[rc_idx]);
            rc_idx += 1;
        }
        sbox_layer::<T, IFMA>(&mut state);
        if HASH_ONLY && round + 1 == half_full {
            apply_dense_matrix_row0(&mut state, constants.mds_matrix);
        } else {
            dense_layer::<T, IFMA>(&mut state, constants.mds_matrix);
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
    Some(permute::<T, true>(state, constants)[0])
}

/// Hashes 1 to 12 inputs of 32 little-endian bytes with the default
/// parameters in [`constants`] and returns the little-endian digest, as the
/// `sol_poseidon` syscall does.
///
/// Returns `None` for any other number of inputs, an input of any other
/// length, or an input that is not below the field modulus.
pub fn hash_le_bytes(inputs: &[&[u8]]) -> Option<[u8; 32]> {
    hash_bytes::<false>(inputs)
}

fn hash_bytes<const BIG_ENDIAN: bool>(inputs: &[&[u8]]) -> Option<[u8; 32]> {
    use constants::*;
    type B = Backend<Fr>;
    let mut elements = [U256::zero(); 12];
    let elements = elements.get_mut(..inputs.len())?;
    for (element, input) in elements.iter_mut().zip(inputs) {
        let chunks = <&[u8; 32]>::try_from(*input).ok()?.as_chunks::<8>().0;
        let value = U256::new(core::array::from_fn(|i| {
            if BIG_ENDIAN {
                u64::from_be_bytes(chunks[3 - i])
            } else {
                u64::from_le_bytes(chunks[i])
            }
        }));
        if !B::is_reduced(&value) {
            return None;
        }
        *element = B::to_mont(&value);
    }
    let digest = match elements.len() {
        1 => hash(elements, &BN254_X5_T2),
        2 => hash(elements, &BN254_X5_T3),
        3 => hash(elements, &BN254_X5_T4),
        4 => hash(elements, &BN254_X5_T5),
        5 => hash(elements, &BN254_X5_T6),
        6 => hash(elements, &BN254_X5_T7),
        7 => hash(elements, &BN254_X5_T8),
        8 => hash(elements, &BN254_X5_T9),
        9 => hash(elements, &BN254_X5_T10),
        10 => hash(elements, &BN254_X5_T11),
        11 => hash(elements, &BN254_X5_T12),
        12 => hash(elements, &BN254_X5_T13),
        _ => None,
    }?;
    let limbs = B::from_mont(&digest).0;
    let mut bytes = [0; 32];
    for (i, chunk) in bytes.as_chunks_mut::<8>().0.iter_mut().enumerate() {
        let encoded = if BIG_ENDIAN {
            limbs[3 - i].to_be_bytes()
        } else {
            limbs[i].to_le_bytes()
        };
        chunk.copy_from_slice(&encoded);
    }
    Some(bytes)
}

/// Hashes the same inputs in big-endian byte order and returns the
/// big-endian digest.
pub fn hash_be_bytes(inputs: &[&[u8]]) -> Option<[u8; 32]> {
    hash_bytes::<true>(inputs)
}

#[cfg(test)]
mod tests {
    use super::{constants::*, *};
    use ark_bn254::Fr as ArkFr;
    use ark_ff::{Field as _, PrimeField};
    use rand::{RngExt, SeedableRng, rngs::StdRng};
    use std::{boxed::Box, vec::Vec};

    /// Two full rounds isolate the pre-sparse and final dense matrices. All
    /// expected arithmetic and Montgomery conversions use arkworks.
    fn check_custom_matrices<const T: usize>() {
        let radix = ArkFr::from(2u64).pow([256u64]);
        let to_raw = |v: ArkFr| U256::new((v * radix).into_bigint().0);
        let mds: [[ArkFr; T]; T] = core::array::from_fn(|i| {
            core::array::from_fn(|j| -ArkFr::from((i * T + j + 1) as u64))
        });
        let pre_sparse: [[ArkFr; T]; T] =
            core::array::from_fn(|i| core::array::from_fn(|j| ArkFr::from((i + 3 * j + 2) as u64)));
        let rc: Vec<ArkFr> = (1..=2 * T).map(|i| ArkFr::from(i as u64)).collect();
        // The parameter type requires static references, so leak each custom
        // table.
        let constants = PoseidonConstants {
            full_rounds: 2,
            partial_rounds: 0,
            round_constants: Box::leak(
                rc.iter()
                    .copied()
                    .map(to_raw)
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ),
            mds_matrix: Box::leak(Box::new(mds.map(|row| row.map(to_raw)))),
            pre_sparse_matrix: Box::leak(Box::new(pre_sparse.map(|row| row.map(to_raw)))),
            sparse_matrices: &[],
        };
        let mut rng = StdRng::seed_from_u64(0x6d61_7472_6978_7631 ^ T as u64);
        for case in 0..12 {
            let mut state: [ArkFr; T] = core::array::from_fn(|i| match case {
                0 => ArkFr::from(0u64),
                1 => ArkFr::from((i + 1) as u64),
                2 => -ArkFr::from(1u64),
                _ => ArkFr::from_le_bytes_mod_order(&rng.random::<[u8; 32]>()),
            });
            state[0] = ArkFr::from(0u64);
            let mut expected = state;
            for (round, matrix) in [&pre_sparse, &mds].into_iter().enumerate() {
                for (i, value) in expected.iter_mut().enumerate() {
                    *value = (*value + rc[round * T + i]).pow([5u64]);
                }
                expected = core::array::from_fn(|i| {
                    expected.iter().zip(&matrix[i]).map(|(x, m)| *x * m).sum()
                });
            }
            let state = state.map(to_raw);
            let expected = expected.map(to_raw);
            assert_eq!(
                poseidon(state, &constants),
                expected,
                "width {T}, case {case}"
            );
            assert_eq!(
                hash(&state[1..], &constants),
                Some(expected[0]),
                "width {T}, case {case}"
            );
        }
    }

    macro_rules! width_suite {
        ($name:ident, $t:literal, $params:ident) => {
            mod $name {
                use super::*;

                /// The permutation indexes `round_constants` linearly and panics on a
                /// short table; pin the layout the generator promises.
                #[test]
                fn constant_layout() {
                    let params: &PoseidonConstants<$t> = &$params;
                    assert_eq!(params.full_rounds, 8);
                    assert_eq!(
                        params.round_constants.len(),
                        $t * params.full_rounds + params.partial_rounds
                    );
                    assert_eq!(params.sparse_matrices.len(), params.partial_rounds);
                }

                #[test]
                fn custom_matrices_match_arkworks() {
                    check_custom_matrices::<$t>();
                }
            }
        };
    }

    width_suite!(t2, 2, BN254_X5_T2);
    width_suite!(t3, 3, BN254_X5_T3);
    width_suite!(t4, 4, BN254_X5_T4);
    width_suite!(t5, 5, BN254_X5_T5);
    width_suite!(t6, 6, BN254_X5_T6);
    width_suite!(t7, 7, BN254_X5_T7);
    width_suite!(t8, 8, BN254_X5_T8);
    width_suite!(t9, 9, BN254_X5_T9);
    width_suite!(t10, 10, BN254_X5_T10);
    width_suite!(t11, 11, BN254_X5_T11);
    width_suite!(t12, 12, BN254_X5_T12);
    width_suite!(t13, 13, BN254_X5_T13);

    #[test]
    fn custom_matrices_with_three_vector_chunks() {
        check_custom_matrices::<17>();
    }
}
