//! Bounded Fr sums of products for Poseidon matrix rows.
//!
//! The shared Montgomery-reduction idea follows Longa:
//! <https://eprint.iacr.org/2022/367>. This implementation uses chunks of four.
//! With W=2^64 and r the Fr modulus, each integrated step preserves
//! t < sum(b[k])+r <= 5r < R=2^256. Its pre-shift numerator is below WR,
//! so five limbs suffice, including all top carries. After four steps,
//! sum(a[k]*b[k]) < 4r^2 < rR gives REDC < 2r; one subtraction suffices.

use crate::backend::{Backend, Field, Fr, MontgomeryBackend, U256};

const _: () = assert!(Fr::MODULUS.0[3] < u64::MAX / 5);

#[inline(always)]
fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let value = a as u128 + b as u128 * c as u128 + carry as u128;
    (value as u64, (value >> 64) as u64)
}

/// Both arrays contain canonical raw R256 residues. Returns a canonical dot.
#[inline(always)]
pub(super) fn sum_products<const T: usize>(a: &[U256; T], b: &[U256; T]) -> U256 {
    type B = Backend<Fr>;
    let mut sum = U256::zero();
    for start in (0..T).step_by(4) {
        let end = core::cmp::min(start + 4, T);
        let value = if end - start == 1 {
            B::mul(&a[start], &b[start])
        } else {
            let mut t = [0u64; 5];
            for i in 0..4 {
                for k in start..end {
                    let mut carry = 0;
                    for j in 0..4 {
                        (t[j], carry) = mac(t[j], a[k].0[i], b[k].0[j], carry);
                    }
                    t[4] += carry;
                }
                let m = t[0].wrapping_mul(Fr::INV);
                let (_, carry) = mac(t[0], m, Fr::MODULUS.0[0], 0);
                let (r0, carry) = mac(t[1], m, Fr::MODULUS.0[1], carry);
                let (r1, carry) = mac(t[2], m, Fr::MODULUS.0[2], carry);
                let (r2, carry) = mac(t[3], m, Fr::MODULUS.0[3], carry);
                // The invariant bounds this top-limb addition below W.
                t = [r0, r1, r2, t[4] + carry, 0];
            }
            let mut difference = [0; 4];
            let mut borrow = false;
            for i in 0..4 {
                let (word, b1) = t[i].overflowing_sub(Fr::MODULUS.0[i]);
                let (word, b2) = word.overflowing_sub(borrow as u64);
                difference[i] = word;
                borrow = b1 || b2;
            }
            let mask = 0u64.wrapping_sub(borrow as u64);
            U256::new(core::array::from_fn(|i| {
                (t[i] & mask) | (difference[i] & !mask)
            }))
        };
        sum = if start == 0 {
            value
        } else {
            B::add(&sum, &value)
        };
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr as ArkFr;
    use ark_ff::{BigInt, Field as _, PrimeField};
    use rand::{RngExt, SeedableRng, rngs::StdRng};

    fn check<const T: usize>() {
        let mut rng = StdRng::seed_from_u64(0x646f_745f_6672_5f34 ^ T as u64);
        let inverse = ArkFr::from(2u64).pow([256]).inverse().unwrap();
        for case in 0..512 {
            let mut value = |index: usize| match case {
                0 => ArkFr::from(0u64),
                1 => -ArkFr::from(1u64),
                2..=28 => {
                    let bit = [1u64, 63, 64, 127, 128, 191, 192, 252, 253][(case - 2) / 3];
                    let power = ArkFr::from(2u64).pow([bit]);
                    power + ArkFr::from((index % 3) as u64) - ArkFr::from(1u64)
                }
                _ => ArkFr::from_le_bytes_mod_order(&rng.random::<[u8; 32]>()),
            };
            let a: [U256; T] = core::array::from_fn(|i| U256::new(value(i).into_bigint().0));
            let b: [U256; T] = core::array::from_fn(|i| U256::new(value(i + 1).into_bigint().0));
            let expected: ArkFr = a
                .iter()
                .zip(&b)
                .map(|(a, b)| {
                    ArkFr::from_bigint(BigInt(a.0)).unwrap()
                        * ArkFr::from_bigint(BigInt(b.0)).unwrap()
                        * inverse
                })
                .sum();
            assert_eq!(
                sum_products(&a, &b),
                U256::new(expected.into_bigint().0),
                "T={T}, case={case}"
            );
        }
    }

    #[test]
    fn scalar_dot_boundaries_and_random_terms_match_arkworks() {
        check::<0>();
        check::<1>();
        check::<2>();
        check::<3>();
        check::<4>();
        check::<5>();
        check::<8>();
        check::<13>();
        check::<17>();
    }
}
