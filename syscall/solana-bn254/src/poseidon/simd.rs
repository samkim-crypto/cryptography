//! Keep built-in full rounds in the IFMA lane layout.

use super::{PoseidonConstants, packed};
use crate::backend::{
    U256,
    avx512::{
        math::{add_8x, sbox_8x, sum_products_8x},
        pack::{pack_8x, unpack_8x_into},
        types::FieldElement8x52,
    },
};
use core::arch::x86_64::{_mm512_permutexvar_epi64, _mm512_set1_epi64};

#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn pack_state<const T: usize>(state: &[U256; T]) -> [FieldElement8x52; 2] {
    let mut packed = [FieldElement8x52::zero(); 2];
    for (i, values) in state.chunks(8).enumerate() {
        let mut chunk = [U256::zero(); 8];
        chunk[..values.len()].copy_from_slice(values);
        packed[i] = unsafe { pack_8x(&chunk) };
    }
    packed
}

#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn unpack_state<const T: usize>(packed: &[FieldElement8x52; 2], state: &mut [U256; T]) {
    for (i, values) in state.chunks_mut(8).enumerate() {
        let mut chunk = [U256::zero(); 8];
        unsafe { unpack_8x_into(&packed[i], &mut chunk) };
        values.copy_from_slice(&chunk[..values.len()]);
    }
}

#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn dense<const T: usize>(
    state: &[FieldElement8x52; 2],
    matrix: &[packed::Packed],
) -> [FieldElement8x52; 2] {
    let mut out = [FieldElement8x52::zero(); 2];
    for chunk in 0..T.div_ceil(8) {
        out[chunk] = unsafe {
            sum_products_8x::<T>(|j| {
                let source = &state[j / 8];
                let lane = _mm512_set1_epi64((j % 8) as i64);
                let broadcast = FieldElement8x52 {
                    l0: _mm512_permutexvar_epi64(lane, source.l0),
                    l1: _mm512_permutexvar_epi64(lane, source.l1),
                    l2: _mm512_permutexvar_epi64(lane, source.l2),
                    l3: _mm512_permutexvar_epi64(lane, source.l3),
                    l4: _mm512_permutexvar_epi64(lane, source.l4),
                };
                (broadcast, matrix[chunk * T + j].load())
            })
        };
    }
    out
}

#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn sbox_layer<const T: usize>(
    state: &mut [FieldElement8x52; 2],
    rc: &[packed::Packed],
    round: usize,
) {
    for chunk in 0..T.div_ceil(8) {
        unsafe {
            let sum = add_8x(&state[chunk], &rc[round * T.div_ceil(8) + chunk].load());
            state[chunk] = sbox_8x(&sum);
        }
    }
}

/// Widths with measured complete-hash gains from IFMA final-row products.
pub(super) const fn use_simd_row0<const T: usize>() -> bool {
    matches!(T, 4 | 5 | 8 | 9 | 12)
}

/// Computes the first dense output from an already packed canonical state.
/// Row coefficients are in R260; each product is canonical before the scalar
/// horizontal sum. The table lookup limits T to 2..=13.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn row0<const T: usize>(state: &[FieldElement8x52; 2], row: &[packed::Packed]) -> U256 {
    use crate::backend::avx512::{math::mul_fixed_8x, pack::unpack_8x};
    use crate::backend::{Backend, Fr, MontgomeryBackend};
    let mut sum = U256::zero();
    for chunk in 0..T.div_ceil(8) {
        let terms = unsafe { unpack_8x(&mul_fixed_8x(&state[chunk], &row[chunk].load())) };
        for (lane, term) in terms[..core::cmp::min(8, T - 8 * chunk)].iter().enumerate() {
            sum = if chunk == 0 && lane == 0 {
                *term
            } else {
                Backend::<Fr>::add(&sum, term)
            };
        }
    }
    sum
}

/// A custom matrix keeps the scalar dot product; no state changes on a miss.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub(super) unsafe fn matrix_row0<const T: usize>(
    state: &[U256; T],
    matrix: &[[U256; T]; T],
) -> Option<U256> {
    let row = packed::first_row(matrix)?;
    Some(unsafe { row0::<T>(&pack_state(state), row) })
}

/// Returns false before changing state unless the built-in full-round tables
/// apply. Their identity/count checks restrict T to 2..=13 and eight full rounds,
/// so the two vector chunks suffice. Custom parameters keep the general path.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub(super) unsafe fn permutation<const T: usize, const HASH_ONLY: bool>(
    state: &mut [U256; T],
    constants: &PoseidonConstants<T>,
) -> bool {
    // Narrow states and width six retain the measured scalar boundary path.
    if T < 5 || T == 6 {
        return false;
    }
    let Some(rc) = packed::full_round_constants(constants) else {
        return false;
    };
    let Some(mds) = packed::dense(constants.mds_matrix) else {
        return false;
    };
    let Some(pre) = packed::dense(constants.pre_sparse_matrix) else {
        return false;
    };
    unsafe {
        let mut vectors = pack_state(state);
        for round in 0..4 {
            sbox_layer::<T>(&mut vectors, rc, round);
            vectors = dense::<T>(&vectors, if round == 3 { pre } else { mds });
        }
        unpack_state(&vectors, state);
        super::partial_rounds(state, constants, 4 * T);
        vectors = pack_state(state);
        for round in 4..8 {
            sbox_layer::<T>(&mut vectors, rc, round);
            if HASH_ONLY && round == 7 {
                if use_simd_row0::<T>() {
                    // dense() above already established built-in matrix identity.
                    let row = packed::first_row(constants.mds_matrix).unwrap();
                    state[0] = row0::<T>(&vectors, row);
                } else {
                    unpack_state(&vectors, state);
                    super::apply_dense_matrix_row0(state, constants.mds_matrix);
                }
                return true;
            }
            vectors = dense::<T>(&vectors, mds);
        }
        unpack_state(&vectors, state);
    }
    true
}
