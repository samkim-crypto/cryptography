//! Variable-time Jacobi symbol modulo \\(p = 2^{255} - 19\\), for public data:
//! Stein's binary GCD, as in Algorithm 1 of <https://eprint.iacr.org/2020/972>
//! without the inversion coefficients, tracking the sign of the symbol.

use super::field::FieldElement51;

/// \\(p = 2^{255} - 19\\) as little-endian 64-bit limbs.
const P: [u64; 4] = [
    0xffff_ffff_ffff_ffed,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x7fff_ffff_ffff_ffff,
];

/// Whether `a < b`.
#[inline(always)]
fn lt(a: &[u64; 4], b: &[u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// `a - b`, and whether it borrows.
#[inline(always)]
fn sub(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut r = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (x, b1) = a[i].overflowing_sub(b[i]);
        let (x, b2) = x.overflowing_sub(borrow as u64);
        r[i] = x;
        borrow = b1 | b2;
    }
    (r, borrow)
}

/// Whether `x` is a square modulo \\(p\\), zero included.
pub(crate) fn is_square_vartime(x: &FieldElement51) -> bool {
    let bytes = x.to_bytes();
    let mut a = [0u64; 4];
    for (limb, chunk) in a.iter_mut().zip(bytes.chunks_exact(8)) {
        *limb = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
    }
    let mut b = P;
    // Bit 0 is the parity of the sign flips.
    let mut flips = 0u64;
    while a.iter().any(|&limb| limb != 0) {
        if a[0] & 1 == 0 {
            for i in 0..3 {
                a[i] = (a[i] >> 1) | (a[i + 1] << 63);
            }
            a[3] >>= 1;
            // (2 | b) = -1 when b is 3 or 5 mod 8.
            flips ^= (b[0] >> 1) ^ (b[0] >> 2);
        } else {
            if lt(&a, &b) {
                core::mem::swap(&mut a, &mut b);
                // Reciprocity: -1 when both are 3 mod 4.
                flips ^= (a[0] & b[0]) >> 1;
            }
            a = sub(&a, &b).0;
        }
    }
    flips & 1 == 0
}
