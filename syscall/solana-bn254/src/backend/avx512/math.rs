//! High-throughput Montgomery CIOS IFMA Arithmetic.

#![allow(unused_unsafe)]
#![allow(unsafe_op_in_unsafe_fn)]

use super::types::FieldElement8x52;
use crate::backend::{Fr, portable::PortableBackend};
use core::arch::x86_64::*;

// Mathematically pre-computed 52-bit modulus constants for the BN254 Fr field.
const FR_MOD_L0: i64 = 0x1f593f0000001;
const FR_MOD_L1: i64 = 0x4879b9709143e;
const FR_MOD_L2: i64 = 0x181585d2833e8;
const FR_MOD_L3: i64 = 0xa029b85045b68;
const FR_MOD_L4: i64 = 0x30644e72e131;

// The Montgomery Inverse Multiplier for 52-bit limbs: `(-MODULUS^-1) mod 2^52`
const FR_INV_52: i64 = 0x1f593efffffff;

/// Unreduced Parallel Addition.
///
/// Because IFMA math logically isolates results within a 52-bit boundary inside a
/// 64-bit accumulator lane, we naturally gain 12 bits of headroom. This function
/// can be called ~4,096 times consecutively before an overflow is mathematically
/// possible, making it extremely efficient for massive MDS matrix multiplications.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub unsafe fn add_lazy(a: &FieldElement8x52, b: &FieldElement8x52) -> FieldElement8x52 {
    FieldElement8x52 {
        l0: _mm512_add_epi64(a.l0, b.l0),
        l1: _mm512_add_epi64(a.l1, b.l1),
        l2: _mm512_add_epi64(a.l2, b.l2),
        l3: _mm512_add_epi64(a.l3, b.l3),
        l4: _mm512_add_epi64(a.l4, b.l4),
    }
}

/// Adds eight pairs of fully reduced Fr residues and returns canonical results.
///
/// Both operands must have normalized 52-bit limbs and represent values below
/// p. Their sum is below 2p < 2^255. Each limb sum, including a carry of at
/// most one, is below 2^53, so 64-bit lanes cannot overflow. Normalize the
/// carries before the single conditional modulus subtraction.
///
/// Addition preserves the external R = 2^256 Montgomery representation.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub(crate) unsafe fn add_8x(a: &FieldElement8x52, b: &FieldElement8x52) -> FieldElement8x52 {
    let mask_52 = _mm512_set1_epi64(0xFFFFFFFFFFFFF);
    let sum = add_lazy(a, b);
    let s1 = _mm512_add_epi64(sum.l1, _mm512_srli_epi64(sum.l0, 52));
    let s2 = _mm512_add_epi64(sum.l2, _mm512_srli_epi64(s1, 52));
    let s3 = _mm512_add_epi64(sum.l3, _mm512_srli_epi64(s2, 52));
    let s4 = _mm512_add_epi64(sum.l4, _mm512_srli_epi64(s3, 52));
    let normalized = FieldElement8x52 {
        l0: _mm512_and_si512(sum.l0, mask_52),
        l1: _mm512_and_si512(s1, mask_52),
        l2: _mm512_and_si512(s2, mask_52),
        l3: _mm512_and_si512(s3, mask_52),
        // The complete sum is below 2^255, so this limb is below 2^47.
        l4: s4,
    };
    cond_sub_modulus(&normalized)
}

/// Multiplies each lane by `2^4`, renormalizing to 52-bit limbs.
///
/// Used to reconcile Montgomery radices: five 52-bit CIOS iterations divide by
/// `2^260`, while the rest of the crate represents field elements with `R = 2^256`.
///
/// The input must be below `2^256`, which keeps the scaled result inside the
/// 260-bit window spanned by five limbs, so no significant bits are discarded.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn scale_by_16(x: &FieldElement8x52) -> FieldElement8x52 {
    let mask_52 = _mm512_set1_epi64(0xFFFFFFFFFFFFF);

    let s0 = _mm512_slli_epi64(x.l0, 4);
    let s1 = _mm512_slli_epi64(x.l1, 4);
    let s2 = _mm512_slli_epi64(x.l2, 4);
    let s3 = _mm512_slli_epi64(x.l3, 4);
    let s4 = _mm512_slli_epi64(x.l4, 4);

    let mut out = FieldElement8x52::zero();

    let carry0 = _mm512_srli_epi64(s0, 52);
    out.l0 = _mm512_and_si512(s0, mask_52);

    let s1 = _mm512_add_epi64(s1, carry0);
    let carry1 = _mm512_srli_epi64(s1, 52);
    out.l1 = _mm512_and_si512(s1, mask_52);

    let s2 = _mm512_add_epi64(s2, carry1);
    let carry2 = _mm512_srli_epi64(s2, 52);
    out.l2 = _mm512_and_si512(s2, mask_52);

    let s3 = _mm512_add_epi64(s3, carry2);
    let carry3 = _mm512_srli_epi64(s3, 52);
    out.l3 = _mm512_and_si512(s3, mask_52);

    let s4 = _mm512_add_epi64(s4, carry3);
    out.l4 = _mm512_and_si512(s4, mask_52);

    out
}

/// Subtracts the modulus from every lane whose value is at least the modulus.
///
/// Yields a fully reduced result provided the input is below `2r`. This is what
/// lets a packed result be handed back to the scalar backend, whose `add` and
/// `sub` assume both operands are already below the modulus.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn cond_sub_modulus(x: &FieldElement8x52) -> FieldElement8x52 {
    let mask_52 = _mm512_set1_epi64(0xFFFFFFFFFFFFF);
    let [mod0, mod1, mod2, mod3, mod4] = modulus_8x().limbs();

    // Compute `x - MODULUS`, rippling the borrow across the 52-bit limbs. Each
    // limb difference lands in `(-2^52, 2^52)`, so its sign bit is exactly the
    // borrow out of that limb.
    let d0 = _mm512_sub_epi64(x.l0, mod0);
    let borrow0 = _mm512_maskz_set1_epi64(_mm512_movepi64_mask(d0), -1);

    let d1 = _mm512_add_epi64(_mm512_sub_epi64(x.l1, mod1), borrow0);
    let borrow1 = _mm512_maskz_set1_epi64(_mm512_movepi64_mask(d1), -1);

    let d2 = _mm512_add_epi64(_mm512_sub_epi64(x.l2, mod2), borrow1);
    let borrow2 = _mm512_maskz_set1_epi64(_mm512_movepi64_mask(d2), -1);

    let d3 = _mm512_add_epi64(_mm512_sub_epi64(x.l3, mod3), borrow2);
    let borrow3 = _mm512_maskz_set1_epi64(_mm512_movepi64_mask(d3), -1);

    let d4 = _mm512_add_epi64(_mm512_sub_epi64(x.l4, mod4), borrow3);

    // A borrow out of the top limb means `x < MODULUS`; keep the original lane.
    let underflow = _mm512_movepi64_mask(d4);

    FieldElement8x52 {
        l0: _mm512_mask_blend_epi64(underflow, _mm512_and_si512(d0, mask_52), x.l0),
        l1: _mm512_mask_blend_epi64(underflow, _mm512_and_si512(d1, mask_52), x.l1),
        l2: _mm512_mask_blend_epi64(underflow, _mm512_and_si512(d2, mask_52), x.l2),
        l3: _mm512_mask_blend_epi64(underflow, _mm512_and_si512(d3, mask_52), x.l3),
        l4: _mm512_mask_blend_epi64(underflow, _mm512_and_si512(d4, mask_52), x.l4),
    }
}

/// Computes an 8-way parallel Montgomery Multiplication for the BN254 Fr field.
///
/// Implements a fully unrolled CIOS (Coarsely Integrated Operand Scanning) algorithm.
/// Because IFMA tracks sums in a 64-bit accumulator, cross-product carries are
/// strictly contained within the active iteration and do not require ripple logic
/// between intermediate multiplies.
///
/// # Montgomery domain
/// Five 52-bit CIOS iterations divide by `2^260`, but field elements throughout
/// this crate are represented with `R = 2^256`. Pre-scaling `a` by `2^4` moves the
/// product back into the `2^256` domain. The correction is applied to the input
/// rather than the result because the CIOS reduction absorbs the extra magnitude
/// for free: correcting the output instead would require reducing a value as
/// large as `32r`.
///
/// # Contract
/// Both operands must be fully reduced (`< MODULUS`) Montgomery-form values, as
/// required by `MontgomeryBackend`. The result is fully reduced.
///
/// The operands are not symmetric in cost: `a` is scaled, `b` is not.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub unsafe fn mul_8x(a: &FieldElement8x52, b: &FieldElement8x52) -> FieldElement8x52 {
    mul_core::<true>(a, b)
}

/// Multiplies canonical residues with a fixed coefficient already in R=2^260.
///
/// The state stays in R=2^256: (xR256)(cR260)/R260 = xcR256. Both integer
/// operands are below r, with normalized limbs. The coefficient is 16*c mod r,
/// not an unreduced shift. REDC is below 2r and one subtraction suffices.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub(crate) unsafe fn mul_fixed_8x(a: &FieldElement8x52, b: &FieldElement8x52) -> FieldElement8x52 {
    mul_core::<false>(a, b)
}

// This private kernel also accepts normalized inputs below 2r for x^5.
// With radix correction, 16ab < 64r^2 < r*2^260 because 4r < 2^256.
// Thus its final subtraction still returns a canonical result. Public wrappers
// retain their canonical-input contracts.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn mul_core<const CORRECT_RADIX: bool>(
    a: &FieldElement8x52,
    b: &FieldElement8x52,
) -> FieldElement8x52 {
    // 64-bit accumulators holding the in-flight summation.
    let mut t = [_mm512_setzero_si512(); 6];

    // Radix correction, see the note above.
    let a_scaled = if CORRECT_RADIX { scale_by_16(a) } else { *a };

    // CIOS Algorithm: Loop is fully unrolled by the LLVM compiler.
    for ai in a_scaled.limbs() {
        mac_row_8x(&mut t, ai, b);
        reduce_limb_8x(&mut t);
        t = [t[1], t[2], t[3], t[4], t[5], _mm512_setzero_si512()];
    }

    canonical_8x(&t)
}

/// # Safety
/// Requires AVX-512F, AVX-512DQ and AVX-512 IFMA, plus canonical Fr operands
/// with normalized 52-bit limbs.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub unsafe fn sum_of_products_8x<const N: usize>(
    a: &[FieldElement8x52; N],
    b: &[FieldElement8x52; N],
) -> FieldElement8x52 {
    const LAZY_TERMS: usize = PortableBackend::<Fr>::LAZY_TERMS;
    // Nine IFMA halves per column per product keep chunk columns below 2^59.
    const { assert!(LAZY_TERMS * 9 < 1 << 7) };
    let mut sum = None;
    for (k, a) in a.chunks(LAZY_TERMS).enumerate() {
        let mut w = [_mm512_setzero_si512(); 10];
        for (x, y) in a.iter().zip(&b[k * LAZY_TERMS..]) {
            for (i, xi) in x.limbs().into_iter().enumerate() {
                mac_row_8x(&mut w[i..], xi, y);
            }
        }
        let chunk = montgomery_reduce_8x(w);
        sum = Some(match sum {
            Some(sum) => add_8x(&sum, &chunk),
            None => chunk,
        });
    }
    sum.unwrap_or_else(FieldElement8x52::zero)
}

// Helpers rely on the module-wide IFMA cfg because `#[target_feature]` rules out `inline(always)`.
#[inline(always)]
unsafe fn modulus_8x() -> FieldElement8x52 {
    FieldElement8x52 {
        l0: _mm512_set1_epi64(FR_MOD_L0),
        l1: _mm512_set1_epi64(FR_MOD_L1),
        l2: _mm512_set1_epi64(FR_MOD_L2),
        l3: _mm512_set1_epi64(FR_MOD_L3),
        l4: _mm512_set1_epi64(FR_MOD_L4),
    }
}

/// Operand limbs contribute only their low 52 bits.
#[inline(always)]
unsafe fn mac_row_8x(t: &mut [__m512i], s: __m512i, v: &FieldElement8x52) {
    for (k, vk) in v.limbs().into_iter().enumerate() {
        t[k] = _mm512_madd52lo_epu64(t[k], s, vk);
        t[k + 1] = _mm512_madd52hi_epu64(t[k + 1], s, vk);
    }
}

/// The low 52 bits of `t[0]` cancel, with the remaining carry in `t[1]`.
#[inline(always)]
unsafe fn reduce_limb_8x(t: &mut [__m512i]) {
    let m = _mm512_madd52lo_epu64(_mm512_setzero_si512(), t[0], _mm512_set1_epi64(FR_INV_52));
    mac_row_8x(t, m, &modulus_8x());
    t[1] = _mm512_add_epi64(t[1], _mm512_srli_epi64(t[0], 52));
}

/// Maps columns `w < MODULUS * 2^256`, each below `2^59`, to canonical `w * R^-1`.
#[inline(always)]
unsafe fn montgomery_reduce_8x(mut w: [__m512i; 10]) -> FieldElement8x52 {
    // Five 52-bit steps divide by 2^260 = 2^4 * R.
    for column in &mut w {
        *column = _mm512_slli_epi64(*column, 4);
    }
    for i in 0..5 {
        reduce_limb_8x(&mut w[i..]);
    }
    canonical_8x(&w[5..])
}

/// Maps unnormalized limbs `t[..5]` of a value below `2 * MODULUS` to its canonical residue.
#[inline(always)]
unsafe fn canonical_8x(t: &[__m512i]) -> FieldElement8x52 {
    let mask_52 = _mm512_set1_epi64(0xFFFFFFFFFFFFF);
    let mut out = FieldElement8x52::zero();

    let carry0 = _mm512_srli_epi64(t[0], 52);
    out.l0 = _mm512_and_si512(t[0], mask_52);

    let t1_new = _mm512_add_epi64(t[1], carry0);
    let carry1 = _mm512_srli_epi64(t1_new, 52);
    out.l1 = _mm512_and_si512(t1_new, mask_52);

    let t2_new = _mm512_add_epi64(t[2], carry1);
    let carry2 = _mm512_srli_epi64(t2_new, 52);
    out.l2 = _mm512_and_si512(t2_new, mask_52);

    let t3_new = _mm512_add_epi64(t[3], carry2);
    let carry3 = _mm512_srli_epi64(t3_new, 52);
    out.l3 = _mm512_and_si512(t3_new, mask_52);

    let t4_new = _mm512_add_epi64(t[4], carry3);
    out.l4 = _mm512_and_si512(t4_new, mask_52);

    // CIOS leaves the result below `2r`, not below `r`. The scalar backend's
    // `add` performs a single conditional subtraction and therefore requires
    // both operands to be fully reduced, so normalize before returning.
    cond_sub_modulus(&out)
}

/// Fuses up to thirteen eight-lane products with one R260 Montgomery reduction.
///
/// Both operands have canonical, normalized limbs; coefficients in R260
/// preserve the state's R256 domain. For N<=13, sum(a*b)<13r^2<r*2^260,
/// so REDC returns below 2r. A column receives fewer than 140 product/reduction
/// halves plus small carries; bounding it by 256*2^52 keeps every u64 lane safe.
/// Normalize limbs before the final canonical subtraction.
/// Shared reduction of sums of products: <https://eprint.iacr.org/2022/367>.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub(crate) unsafe fn sum_products_8x<const N: usize>(
    mut operands: impl FnMut(usize) -> (FieldElement8x52, FieldElement8x52),
) -> FieldElement8x52 {
    assert!(N > 0 && N <= 13);
    let mut t = [_mm512_setzero_si512(); 10];
    for k in 0..N {
        let (a, b) = operands(k);
        let a = [a.l0, a.l1, a.l2, a.l3, a.l4];
        let b = [b.l0, b.l1, b.l2, b.l3, b.l4];
        for i in 0..5 {
            for j in 0..5 {
                t[i + j] = _mm512_madd52lo_epu64(t[i + j], a[i], b[j]);
                t[i + j + 1] = _mm512_madd52hi_epu64(t[i + j + 1], a[i], b[j]);
            }
        }
    }
    let inv = _mm512_set1_epi64(FR_INV_52);
    let modulus = [
        _mm512_set1_epi64(FR_MOD_L0),
        _mm512_set1_epi64(FR_MOD_L1),
        _mm512_set1_epi64(FR_MOD_L2),
        _mm512_set1_epi64(FR_MOD_L3),
        _mm512_set1_epi64(FR_MOD_L4),
    ];
    macro_rules! reduce_limb {
        ($i:expr) => {{
            let m = _mm512_madd52lo_epu64(_mm512_setzero_si512(), t[$i], inv);
            for j in 0..5 {
                t[$i + j] = _mm512_madd52lo_epu64(t[$i + j], m, modulus[j]);
                t[$i + j + 1] = _mm512_madd52hi_epu64(t[$i + j + 1], m, modulus[j]);
            }
            t[$i + 1] = _mm512_add_epi64(t[$i + 1], _mm512_srli_epi64(t[$i], 52));
        }};
    }
    reduce_limb!(0);
    reduce_limb!(1);
    reduce_limb!(2);
    reduce_limb!(3);
    reduce_limb!(4);
    for i in 5..9 {
        t[i + 1] = _mm512_add_epi64(t[i + 1], _mm512_srli_epi64(t[i], 52));
    }
    let mask = _mm512_set1_epi64(0xFFFFFFFFFFFFF);
    cond_sub_modulus(&FieldElement8x52 {
        l0: _mm512_and_si512(t[5], mask),
        l1: _mm512_and_si512(t[6], mask),
        l2: _mm512_and_si512(t[7], mask),
        l3: _mm512_and_si512(t[8], mask),
        l4: t[9],
    })
}

/// Squares eight Fr residues below 2r in the external R=2^256 domain.
///
/// Symmetric products follow Drucker and Gueron, section 3, equation (1):
/// <https://eprint.iacr.org/2018/335>. Five diagonal products and ten distinct
/// cross products replace the general multiply's 25 ordered products.
///
/// Square 4a so REDC's division by 2^260 produces a^2/2^256. For a<2r,
/// 16a^2 < 64r^2 < r*2^260 because 4r < 2^256. REDC stays below 2r;
/// CANONICAL selects the final subtraction. Lazy output is confined to x^5.
/// All multiplicands have normalized 52-bit limbs. Each accumulator
/// receives at most ten product halves, ten reduction halves, and small carries,
/// staying below 32*2^52 < 2^64. Both output modes have normalized limbs.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
unsafe fn square_8x<const CANONICAL: bool>(x: &FieldElement8x52) -> FieldElement8x52 {
    let mask = _mm512_set1_epi64(0xFFFFFFFFFFFFF);
    // The two carry bits occupy positions disjoint from each shifted limb.
    let a = [
        _mm512_and_si512(_mm512_slli_epi64(x.l0, 2), mask),
        _mm512_or_si512(
            _mm512_and_si512(_mm512_slli_epi64(x.l1, 2), mask),
            _mm512_srli_epi64(x.l0, 50),
        ),
        _mm512_or_si512(
            _mm512_and_si512(_mm512_slli_epi64(x.l2, 2), mask),
            _mm512_srli_epi64(x.l1, 50),
        ),
        _mm512_or_si512(
            _mm512_and_si512(_mm512_slli_epi64(x.l3, 2), mask),
            _mm512_srli_epi64(x.l2, 50),
        ),
        _mm512_or_si512(_mm512_slli_epi64(x.l4, 2), _mm512_srli_epi64(x.l3, 50)),
    ];
    let mut t = [_mm512_setzero_si512(); 10];
    macro_rules! cross {
        ($i:expr, $j:expr) => {{
            t[$i + $j] = _mm512_madd52lo_epu64(t[$i + $j], a[$i], a[$j]);
            t[$i + $j + 1] = _mm512_madd52hi_epu64(t[$i + $j + 1], a[$i], a[$j]);
        }};
    }
    cross!(0, 1);
    cross!(0, 2);
    cross!(0, 3);
    cross!(0, 4);
    cross!(1, 2);
    cross!(1, 3);
    cross!(1, 4);
    cross!(2, 3);
    cross!(2, 4);
    cross!(3, 4);
    for limb in &mut t {
        *limb = _mm512_slli_epi64(*limb, 1);
    }
    for i in 0..5 {
        t[2 * i] = _mm512_madd52lo_epu64(t[2 * i], a[i], a[i]);
        t[2 * i + 1] = _mm512_madd52hi_epu64(t[2 * i + 1], a[i], a[i]);
    }
    let inv = _mm512_set1_epi64(FR_INV_52);
    let modulus = [
        _mm512_set1_epi64(FR_MOD_L0),
        _mm512_set1_epi64(FR_MOD_L1),
        _mm512_set1_epi64(FR_MOD_L2),
        _mm512_set1_epi64(FR_MOD_L3),
        _mm512_set1_epi64(FR_MOD_L4),
    ];
    macro_rules! reduce_limb {
        ($i:expr) => {{
            let m = _mm512_madd52lo_epu64(_mm512_setzero_si512(), t[$i], inv);
            for j in 0..5 {
                t[$i + j] = _mm512_madd52lo_epu64(t[$i + j], m, modulus[j]);
                t[$i + j + 1] = _mm512_madd52hi_epu64(t[$i + j + 1], m, modulus[j]);
            }
            // The canceled low 52 bits are zero; retain the whole carry.
            t[$i + 1] = _mm512_add_epi64(t[$i + 1], _mm512_srli_epi64(t[$i], 52));
        }};
    }
    reduce_limb!(0);
    reduce_limb!(1);
    reduce_limb!(2);
    reduce_limb!(3);
    reduce_limb!(4);
    for i in 5..9 {
        t[i + 1] = _mm512_add_epi64(t[i + 1], _mm512_srli_epi64(t[i], 52));
    }
    let out = FieldElement8x52 {
        l0: _mm512_and_si512(t[5], mask),
        l1: _mm512_and_si512(t[6], mask),
        l2: _mm512_and_si512(t[7], mask),
        l3: _mm512_and_si512(t[8], mask),
        // REDC's <2r bound puts the top limb below 2^47.
        l4: t[9],
    };
    if CANONICAL {
        cond_sub_modulus(&out)
    } else {
        out
    }
}

/// Executes the Poseidon S-box (`x^5`) on 8 independent field elements simultaneously.
///
/// The two squares keep normalized residues below 2r. The final multiplication
/// restores canonical output. This removes two conditional modulus subtractions
/// without relaxing the public canonical-input/output contract.
#[inline]
#[target_feature(enable = "avx512f,avx512ifma,avx512dq")]
pub unsafe fn sbox_8x(x: &FieldElement8x52) -> FieldElement8x52 {
    let x2 = square_8x::<false>(x);
    let x4 = square_8x::<false>(&x2);
    mul_core::<true>(&x4, x)
}

#[cfg(test)]
mod tests {
    use super::add_8x;
    use crate::backend::U256;
    use crate::backend::avx512::pack::{pack_8x, unpack_8x};
    use ark_bn254::Fr as ArkFr;
    use ark_ff::{BigInt, PrimeField};
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    fn as_ark(value: U256) -> ArkFr {
        ArkFr::from_bigint(BigInt(value.0)).expect("reduced test operand")
    }

    fn raw(value: ArkFr) -> U256 {
        U256::new(value.into_bigint().0)
    }

    fn random_raw(rng: &mut StdRng) -> U256 {
        raw(ArkFr::from_le_bytes_mod_order(&rng.random::<[u8; 32]>()))
    }

    #[test]
    fn packed_dot_boundaries_random_terms_and_chains_match_arkworks() {
        use ark_ff::Field as _;
        use core::arch::x86_64::_mm512_storeu_si512;

        fn check<const N: usize>() {
            let inverse = ArkFr::from(2u64).pow([260]).inverse().unwrap();
            let mut rng = StdRng::seed_from_u64(0x646f_745f_6966_6d61 ^ N as u64);
            let mut previous = [U256::zero(); 8];
            for case in 0..256 {
                let mut value = |index: usize| match case {
                    0 => U256::zero(),
                    1 => raw(-ArkFr::from(1u64)),
                    2 => {
                        if index % 2 == 0 {
                            U256::zero()
                        } else {
                            raw(-ArkFr::from(1u64))
                        }
                    }
                    3..=38 => {
                        let bit = [1u64, 51, 52, 63, 64, 103, 104, 155, 156, 207, 208, 253]
                            [(case - 3) / 3];
                        raw(
                            ArkFr::from(2u64).pow([bit]) + ArkFr::from((index % 3) as u64)
                                - ArkFr::from(1u64),
                        )
                    }
                    _ => random_raw(&mut rng),
                };
                let mut a: [[U256; 8]; N] =
                    core::array::from_fn(|k| core::array::from_fn(|lane| value(k + lane)));
                let b: [[U256; 8]; N] =
                    core::array::from_fn(|k| core::array::from_fn(|lane| value(k + 2 * lane)));
                if case >= 64 {
                    a[0] = previous;
                }
                let packed =
                    unsafe { super::sum_products_8x::<N>(|k| (pack_8x(&a[k]), pack_8x(&b[k]))) };
                for (i, limb) in [packed.l0, packed.l1, packed.l2, packed.l3, packed.l4]
                    .into_iter()
                    .enumerate()
                {
                    let mut words = [0u64; 8];
                    unsafe { _mm512_storeu_si512(words.as_mut_ptr().cast(), limb) };
                    assert!(
                        words
                            .iter()
                            .all(|&word| word < (1u64 << if i == 4 { 48 } else { 52 }))
                    );
                }
                let actual = unsafe { unpack_8x(&packed) };
                for lane in 0..8 {
                    let expected: ArkFr = (0..N)
                        .map(|k| as_ark(a[k][lane]) * as_ark(b[k][lane]) * inverse)
                        .sum();
                    assert_eq!(
                        actual[lane],
                        raw(expected),
                        "N={N}, case={case}, lane={lane}"
                    );
                }
                previous = actual;
            }
        }
        check::<1>();
        check::<2>();
        check::<4>();
        check::<8>();
        check::<13>();
    }

    #[test]
    fn fixed_radix_products_match_arkworks() {
        use ark_ff::Field as _;
        use core::arch::x86_64::_mm512_storeu_si512;

        let inverse = ArkFr::from(2u64).pow([260]).inverse().unwrap();
        let check = |a: [U256; 8], b: [U256; 8]| {
            let packed = unsafe { super::mul_fixed_8x(&pack_8x(&a), &pack_8x(&b)) };
            for (i, limb) in [packed.l0, packed.l1, packed.l2, packed.l3, packed.l4]
                .into_iter()
                .enumerate()
            {
                let mut words = [0u64; 8];
                unsafe { _mm512_storeu_si512(words.as_mut_ptr().cast(), limb) };
                // The top-limb bound also rules out bits lost by unpacking.
                let bound = 1u64 << if i == 4 { 48 } else { 52 };
                assert!(words.iter().all(|&word| word < bound));
            }
            let actual = unsafe { unpack_8x(&packed) };
            for lane in 0..8 {
                assert_eq!(
                    actual[lane],
                    raw(as_ark(a[lane]) * as_ark(b[lane]) * inverse)
                );
            }
            actual
        };

        let one = ArkFr::from(1u64);
        let mut boundary = [U256::zero(); 48];
        boundary[1] = raw(one);
        boundary[2] = raw(-one);
        for (i, bit) in [
            1u64, 51, 52, 53, 63, 64, 103, 104, 127, 128, 155, 156, 207, 208, 253,
        ]
        .into_iter()
        .enumerate()
        {
            let power = ArkFr::from(2u64).pow([bit]);
            for (j, value) in [power - one, power, power + one].into_iter().enumerate() {
                boundary[3 + 3 * i + j] = raw(value);
            }
        }
        for i in 0..boundary.len() {
            for j in 0..boundary.len() {
                check(
                    core::array::from_fn(|lane| boundary[(i + lane) % boundary.len()]),
                    core::array::from_fn(|lane| boundary[(j + 3 * lane) % boundary.len()]),
                );
            }
        }
        let mut rng = StdRng::seed_from_u64(0x7261_6469_7832_3630);
        for _ in 0..512 {
            check(
                core::array::from_fn(|_| random_raw(&mut rng)),
                core::array::from_fn(|_| random_raw(&mut rng)),
            );
        }
        for _ in 0..32 {
            let mut a = core::array::from_fn(|_| random_raw(&mut rng));
            let b = core::array::from_fn(|_| random_raw(&mut rng));
            for _ in 0..64 {
                a = check(a, b);
            }
        }
    }

    fn check_add(a: [U256; 8], b: [U256; 8]) {
        let actual = unsafe { unpack_8x(&add_8x(&pack_8x(&a), &pack_8x(&b))) };
        for lane in 0..8 {
            // Exact raw equality checks reduction as well as the residue class.
            assert_eq!(
                actual[lane],
                raw(as_ark(a[lane]) + as_ark(b[lane])),
                "lane {lane}: a={:?}, b={:?}",
                a[lane],
                b[lane]
            );
        }
    }

    #[test]
    fn packed_add_boundary_values_match_arkworks() {
        let mut values = [U256::zero(); 48];
        let one = ArkFr::from(1u64);
        values[1] = raw(one);
        values[2] = raw(-one);
        // Exercise the packing boundaries as well as the highest usable bits.
        for (i, bit) in [
            1usize, 51, 52, 53, 103, 104, 105, 155, 156, 157, 207, 208, 209, 252, 253,
        ]
        .into_iter()
        .enumerate()
        {
            let mut limbs = [0u64; 4];
            limbs[bit / 64] = 1u64 << (bit % 64);
            let power = as_ark(U256::new(limbs));
            for (j, value) in [power - one, power, power + one].into_iter().enumerate() {
                values[3 + 3 * i + j] = raw(value);
            }
        }
        for i in 0..values.len() {
            for j in 0..values.len() {
                // Distinct lane operands also exercise mixed reduction masks.
                check_add(
                    core::array::from_fn(|lane| values[(i + lane) % values.len()]),
                    core::array::from_fn(|lane| values[(j + 3 * lane) % values.len()]),
                );
            }
        }
    }

    #[test]
    fn packed_add_seeded_inputs_match_arkworks() {
        let mut rng = StdRng::seed_from_u64(0x7061_636b_6164_6431);
        // 4096 independent lane pairs.
        for _ in 0..512 {
            check_add(
                core::array::from_fn(|_| random_raw(&mut rng)),
                core::array::from_fn(|_| random_raw(&mut rng)),
            );
        }
    }

    #[test]
    fn packed_add_chains_match_arkworks() {
        let mut rng = StdRng::seed_from_u64(0x7061_636b_6368_6169);
        for chain in 0..64 {
            let start = core::array::from_fn(|_| random_raw(&mut rng));
            let mut actual = unsafe { pack_8x(&start) };
            let mut expected = start.map(as_ark);
            for step in 0..64 {
                let addend = core::array::from_fn(|_| random_raw(&mut rng));
                actual = unsafe { add_8x(&actual, &pack_8x(&addend)) };
                let result = unsafe { unpack_8x(&actual) };
                for lane in 0..8 {
                    expected[lane] += as_ark(addend[lane]);
                    assert_eq!(
                        result[lane],
                        raw(expected[lane]),
                        "chain {chain}, step {step}, lane {lane}"
                    );
                }
            }
        }
    }

    #[test]
    fn packed_square_boundaries_random_inputs_and_chains_match_arkworks() {
        use super::square_8x;
        use ark_ff::Field as _;
        use std::vec;

        fn check(actual: &super::FieldElement8x52, expected: [ArkFr; 8]) {
            // Check normalization before unpacking so discarded carry bits cannot
            // hide a broken private representation contract.
            for limb in [actual.l0, actual.l1, actual.l2, actual.l3, actual.l4] {
                let lanes: [u64; 8] = unsafe { core::mem::transmute(limb) };
                assert!(lanes.iter().all(|&word| word < (1 << 52)));
            }
            assert_eq!(unsafe { unpack_8x(actual) }, expected.map(raw));
        }

        let radix = ArkFr::from(2u64).pow([256]);
        let inverse = radix.inverse().unwrap();
        let one = ArkFr::from(1u64);
        let mut boundaries = vec![U256::zero(), raw(one), raw(-one), raw(radix)];
        for bit in [
            1usize, 50, 51, 52, 53, 63, 64, 103, 104, 127, 128, 155, 156, 191, 192, 207, 208, 252,
            253,
        ] {
            let mut words = [0; 4];
            words[bit / 64] = 1u64 << (bit % 64);
            let power = as_ark(U256::new(words));
            boundaries.extend([raw(power - one), raw(power), raw(power + one)]);
        }
        for start in 0..boundaries.len() {
            let inputs = core::array::from_fn(|lane| boundaries[(start + lane) % boundaries.len()]);
            let expected = inputs.map(|value| as_ark(value).square() * inverse);
            check(&unsafe { square_8x::<true>(&pack_8x(&inputs)) }, expected);
        }
        let mut rng = StdRng::seed_from_u64(0x7371_7561_7265_3532);
        for _ in 0..512 {
            let inputs = core::array::from_fn(|_| random_raw(&mut rng));
            let expected = inputs.map(|value| as_ark(value).square() * inverse);
            check(&unsafe { square_8x::<true>(&pack_8x(&inputs)) }, expected);
        }
        for _ in 0..64 {
            let inputs = core::array::from_fn(|_| random_raw(&mut rng));
            let mut actual = unsafe { pack_8x(&inputs) };
            let mut expected = inputs.map(as_ark);
            for _ in 0..64 {
                actual = unsafe { square_8x::<true>(&actual) };
                expected = expected.map(|value| value.square() * inverse);
                check(&actual, expected);
            }
        }
    }
    #[test]
    fn lazy_packed_square_bounds_and_sbox_match_integer_oracle() {
        use crate::backend::{Field as _, Fr};
        use ark_ff::{BigInteger, Field as _};
        use num_bigint::BigUint;
        use std::vec;

        fn integer(value: U256) -> BigUint {
            BigUint::from_bytes_le(&BigInt(value.0).to_bytes_le())
        }
        fn words(value: &BigUint) -> U256 {
            let digits = value.to_u64_digits();
            assert!(digits.len() <= 4);
            let mut limbs = [0; 4];
            limbs[..digits.len()].copy_from_slice(&digits);
            U256::new(limbs)
        }
        fn check_lanes(value: &super::FieldElement8x52) -> [U256; 8] {
            for (i, limb) in [value.l0, value.l1, value.l2, value.l3, value.l4]
                .into_iter()
                .enumerate()
            {
                let lanes: [u64; 8] = unsafe { core::mem::transmute(limb) };
                assert!(
                    lanes
                        .iter()
                        .all(|&word| word < (1u64 << if i == 4 { 47 } else { 52 }))
                );
            }
            unsafe { unpack_8x(value) }
        }
        let r = integer(Fr::MODULUS);
        let twice_r = &r * 2u8;
        let inverse = integer(raw(ArkFr::from(2u64).pow([256]).inverse().unwrap()));
        let inverse4 = inverse.pow(4) % &r;
        let check = |inputs: [U256; 8]| {
            let square = unsafe { super::square_8x::<false>(&pack_8x(&inputs)) };
            for (actual, input) in check_lanes(&square).into_iter().zip(inputs) {
                let actual = integer(actual);
                let input = integer(input);
                assert!(actual < twice_r);
                assert_eq!(actual % &r, &input * &input * &inverse % &r);
            }
            let canonical = inputs.map(|x| words(&(integer(x) % &r)));
            let sbox = unsafe { super::sbox_8x(&pack_8x(&canonical)) };
            for (actual, input) in check_lanes(&sbox).into_iter().zip(canonical) {
                let expected = integer(input).modpow(&BigUint::from(5u8), &r) * &inverse4 % &r;
                assert_eq!(actual, words(&expected));
            }
        };
        let mut boundaries = vec![
            BigUint::from(0u8),
            BigUint::from(1u8),
            &r - 1u8,
            r.clone(),
            &r + 1u8,
            &twice_r - 2u8,
            &twice_r - 1u8,
        ];
        for bit in [
            1usize, 50, 51, 52, 53, 63, 64, 103, 104, 127, 128, 155, 156, 191, 192, 207, 208, 252,
            253, 254,
        ] {
            let power = BigUint::from(1u8) << bit;
            boundaries.extend([&power - 1u8, power.clone(), &power + 1u8]);
        }
        for start in 0..boundaries.len() {
            check(core::array::from_fn(|lane| {
                words(&boundaries[(start + lane) % boundaries.len()])
            }));
        }
        let mut rng = StdRng::seed_from_u64(0x6c61_7a79_6966_6d61);
        for _ in 0..512 {
            check(core::array::from_fn(|_| {
                words(&(integer(U256::new(rng.random())) % &twice_r))
            }));
        }
        let inputs = core::array::from_fn(|lane| words(&(&twice_r - (lane as u8 + 1))));
        let mut state = unsafe { pack_8x(&inputs) };
        let mut expected = inputs.map(integer);
        for _ in 0..128 {
            state = unsafe { super::square_8x::<false>(&state) };
            expected = expected.map(|x| &x * &x * &inverse % &r);
            for (actual, want) in check_lanes(&state).into_iter().zip(&expected) {
                let actual = integer(actual);
                assert!(actual < twice_r);
                assert_eq!(actual % &r, *want);
            }
        }
    }
}
