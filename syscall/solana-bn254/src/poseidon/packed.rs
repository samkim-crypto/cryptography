//! Built-in Poseidon tables in the IFMA lane layout.
//!
//! Derived at compile time from the public scalar tables. Custom parameter
//! tables continue through the runtime packing path.

use super::constants::*;
use super::{PoseidonConstants, SparseMatrix};
use crate::backend::{Field, Fr, U256, avx512::types::FieldElement8x52};
use core::arch::x86_64::_mm512_load_si512;

#[derive(Clone, Copy)]
#[repr(C, align(64))]
pub(super) struct Packed([[u64; 8]; 5]);

impl Packed {
    #[inline]
    #[target_feature(enable = "avx512f")]
    pub(super) unsafe fn load(&self) -> FieldElement8x52 {
        // Each limb starts at a 64-byte boundary. Load the named fields rather
        // than relying on the repr(Rust) layout of FieldElement8x52.
        unsafe {
            FieldElement8x52 {
                l0: _mm512_load_si512(self.0[0].as_ptr().cast()),
                l1: _mm512_load_si512(self.0[1].as_ptr().cast()),
                l2: _mm512_load_si512(self.0[2].as_ptr().cast()),
                l3: _mm512_load_si512(self.0[3].as_ptr().cast()),
                l4: _mm512_load_si512(self.0[4].as_ptr().cast()),
            }
        }
    }
}

const fn limbs(x: U256) -> [u64; 5] {
    const MASK: u64 = (1 << 52) - 1;
    [
        x.0[0] & MASK,
        ((x.0[0] >> 52) | (x.0[1] << 12)) & MASK,
        ((x.0[1] >> 40) | (x.0[2] << 24)) & MASK,
        ((x.0[2] >> 28) | (x.0[3] << 36)) & MASK,
        x.0[3] >> 16,
    ]
}

/// Converts a canonical fixed coefficient from R256 to R260 at compile time.
/// Four modular doublings keep every intermediate below r. Each integer sum
/// is below 2r < 2^255, so no carry beyond the four limbs is discarded.
const fn coefficient(mut x: U256) -> U256 {
    let mut step = 0;
    while step < 4 {
        let mut sum = [0; 4];
        let mut carry = 0;
        let mut i = 0;
        while i < 4 {
            let value = 2 * x.0[i] as u128 + carry;
            sum[i] = value as u64;
            carry = value >> 64;
            i += 1;
        }
        assert!(carry == 0);
        let mut difference = [0; 4];
        let mut borrow = false;
        i = 0;
        while i < 4 {
            let (word, b1) = sum[i].overflowing_sub(Fr::MODULUS.0[i]);
            let (word, b2) = word.overflowing_sub(borrow as u64);
            difference[i] = word;
            borrow = b1 || b2;
            i += 1;
        }
        x = U256::new(if borrow { sum } else { difference });
        step += 1;
    }
    x
}

const fn matrix<const T: usize, const N: usize>(m: &[[U256; T]; T]) -> [Packed; N] {
    assert!(N == T.div_ceil(8) * T);
    let mut packed = [Packed([[0; 8]; 5]); N];
    let mut row = 0;
    while row < T {
        let mut col = 0;
        while col < T {
            let value = limbs(coefficient(m[row][col]));
            let index = (row / 8) * T + col;
            let mut limb = 0;
            while limb < 5 {
                packed[index].0[limb][row % 8] = value[limb];
                limb += 1;
            }
            col += 1;
        }
        row += 1;
    }
    packed
}

const fn first_row_table<const T: usize, const N: usize>(m: &[[U256; T]; T]) -> [Packed; N] {
    assert!(N == T.div_ceil(8));
    let mut packed = [Packed([[0; 8]; 5]); N];
    let mut col = 0;
    while col < T {
        let value = limbs(coefficient(m[0][col]));
        let mut limb = 0;
        while limb < 5 {
            packed[col / 8].0[limb][col % 8] = value[limb];
            limb += 1;
        }
        col += 1;
    }
    packed
}

const fn sparse_tables<const T: usize, const N: usize>(
    matrices: &[SparseMatrix<T>],
) -> [Packed; N] {
    let stride = (2 * T - 1).div_ceil(8);
    assert!(N == stride * matrices.len());
    let mut packed = [Packed([[0; 8]; 5]); N];
    let mut round = 0;
    while round < matrices.len() {
        let mut term = 0;
        while term < 2 * T - 1 {
            let value = if term < T {
                matrices[round].row[term]
            } else {
                matrices[round].col[term - T + 1]
            };
            let value = limbs(coefficient(value));
            let index = round * stride + term / 8;
            let mut limb = 0;
            while limb < 5 {
                packed[index].0[limb][term % 8] = value[limb];
                limb += 1;
            }
            term += 1;
        }
        round += 1;
    }
    packed
}

const fn full_rounds<const T: usize, const N: usize>(p: &PoseidonConstants<T>) -> [Packed; N] {
    assert!(p.full_rounds == 8 && N == 8 * T.div_ceil(8));
    let mut packed = [Packed([[0; 8]; 5]); N];
    let mut round = 0;
    while round < 8 {
        let offset = round * T + if round >= 4 { p.partial_rounds } else { 0 };
        let mut row = 0;
        while row < T {
            // Additive constants stay in the state's R256 representation.
            let value = limbs(p.round_constants[offset + row]);
            let index = round * T.div_ceil(8) + row / 8;
            let mut limb = 0;
            while limb < 5 {
                packed[index].0[limb][row % 8] = value[limb];
                limb += 1;
            }
            row += 1;
        }
        round += 1;
    }
    packed
}

macro_rules! tables {
    ($(($module:ident, $t:literal, $params:ident)),+ $(,)?) => {
        $(mod $module {
            use super::*;
            pub(super) static MDS: [Packed; $t.div_ceil(8) * $t] =
                matrix($params.mds_matrix);
            pub(super) static PRE: [Packed; $t.div_ceil(8) * $t] =
                matrix($params.pre_sparse_matrix);
            pub(super) static SPARSE: [Packed; $params.partial_rounds * (2 * $t - 1).div_ceil(8)] =
                sparse_tables($params.sparse_matrices);
            pub(super) static MDS_ROW0: [Packed; $t.div_ceil(8)] = first_row_table($params.mds_matrix);
            pub(super) static PRE_ROW0: [Packed; $t.div_ceil(8)] = first_row_table($params.pre_sparse_matrix);
            pub(super) static RC: [Packed; 8 * $t.div_ceil(8)] = full_rounds(&$params);
        })+

        #[inline]
        pub(super) fn dense<const T: usize>(m: &[[U256; T]; T]) -> Option<&'static [Packed]> {
            let address = m.as_ptr().cast::<()>();
            match T {
                $($t => {
                    if core::ptr::eq(address, $params.mds_matrix.as_ptr().cast::<()>()) {
                        Some(&$module::MDS)
                    } else if core::ptr::eq(address, $params.pre_sparse_matrix.as_ptr().cast::<()>()) {
                        Some(&$module::PRE)
                    } else {
                        None
                    }
                },)+
                _ => None,
            }
        }

        #[inline]
        pub(super) fn first_row<const T: usize>(m: &[[U256; T]; T]) -> Option<&'static [Packed]> {
            let address = m.as_ptr().cast::<()>();
            match T {
                $($t => {
                    if core::ptr::eq(address, $params.mds_matrix.as_ptr().cast::<()>()) {
                        Some(&$module::MDS_ROW0)
                    } else if core::ptr::eq(address, $params.pre_sparse_matrix.as_ptr().cast::<()>()) {
                        Some(&$module::PRE_ROW0)
                    } else {
                        None
                    }
                },)+
                _ => None,
            }
        }

        #[inline]
        pub(super) fn sparse<const T: usize>(m: &[SparseMatrix<T>]) -> Option<&'static [Packed]> {
            match T {
                $($t if m.len() == $params.sparse_matrices.len()
                    && core::ptr::eq(m.as_ptr().cast::<()>(), $params.sparse_matrices.as_ptr().cast::<()>())
                    => Some(&$module::SPARSE),)+
                _ => None,
            }
        }

        #[inline]
        pub(super) fn full_round_constants<const T: usize>(p: &PoseidonConstants<T>) -> Option<&'static [Packed]> {
            match T {
                $($t if p.full_rounds == $params.full_rounds
                    && p.partial_rounds == $params.partial_rounds
                    && core::ptr::eq(p.round_constants, $params.round_constants)
                    => Some(&$module::RC),)+
                _ => None,
            }
        }
    };
}

tables!(
    (t2, 2usize, BN254_X5_T2),
    (t3, 3usize, BN254_X5_T3),
    (t4, 4usize, BN254_X5_T4),
    (t5, 5usize, BN254_X5_T5),
    (t6, 6usize, BN254_X5_T6),
    (t7, 7usize, BN254_X5_T7),
    (t8, 8usize, BN254_X5_T8),
    (t9, 9usize, BN254_X5_T9),
    (t10, 10usize, BN254_X5_T10),
    (t11, 11usize, BN254_X5_T11),
    (t12, 12usize, BN254_X5_T12),
    (t13, 13usize, BN254_X5_T13),
);
