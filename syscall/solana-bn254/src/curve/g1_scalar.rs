use crate::curve::g1::G1Projective;

/// Extracts the 5-bit Window NAF (Non-Adjacent Form) of a 256-bit scalar.
/// Returns a zero-allocated fixed array of coefficients in [-15, 15] (odd
/// only) and the exact length of the resulting NAF representation.
pub fn wnaf_5(scalar: &[u64; 4]) -> ([i8; 257], usize) {
    let mut wnaf = [0i8; 257];
    // Extend to 5 limbs to safely catch carries from unreduced scalars.
    let mut k = [scalar[0], scalar[1], scalar[2], scalar[3], 0u64];
    let mut len = 0;

    // Execute until all 5 limbs are exactly zero.
    while k[0] != 0 || k[1] != 0 || k[2] != 0 || k[3] != 0 || k[4] != 0 {
        if k[0] & 1 == 1 {
            // Extract the bottom 5 bits (values 0..31)
            let mut val = (k[0] & 31) as i8;
            if val > 16 {
                val -= 32; // Map into range [-15, 15]
            }
            wnaf[len] = val;

            if val > 0 {
                // `val` is the exact bottom 5 bits of `k[0]`, so `k[0] >= val`
                // is guaranteed. No borrow rippling is required across limbs.
                k[0] -= val as u64;
            } else {
                // Addition may ripple a carry across the 5 limbs.
                let mut carry = (-val) as u64;
                for limb in &mut k {
                    let (res, c) = limb.overflowing_add(carry);
                    *limb = res;
                    carry = c as u64;
                    if carry == 0 {
                        break;
                    }
                }
            }
        } else {
            wnaf[len] = 0;
        }
        len += 1;

        // Shift the 320-bit scalar right by 1 bit across limb boundaries.
        let mut carry = 0;
        for i in (0..5).rev() {
            let next_carry = k[i] << 63;
            k[i] = (k[i] >> 1) | carry;
            carry = next_carry;
        }
    }

    (wnaf, len)
}

impl G1Projective {
    /// Multiplies the point by a 256-bit scalar using 5-bit window NAF.
    /// Aggressively optimized for minimum Solana Compute Units.
    pub fn mul_scalar(&self, scalar: &[u64; 4]) -> Self {
        let (wnaf, len) = wnaf_5(scalar);

        if len == 0 {
            return Self::infinity();
        }

        // Precompute table for w=5: 1P, 3P, 5P, 7P, 9P, 11P, 13P, 15P
        let mut precomp = [*self; 8];
        let p2 = self.double();

        for i in 1..8 {
            precomp[i] = precomp[i - 1].add(&p2);
        }

        let mut res = Self::infinity();
        let mut found_nonzero = false;

        // Traverse the NAF from most significant to least significant bit
        for i in (0..len).rev() {
            if found_nonzero {
                res = res.double();
            }

            let wi = wnaf[i];
            if wi != 0 {
                let is_negative = wi < 0;
                let abs_wi = if is_negative { -wi } else { wi };

                // Map absolute value to table index: 1->0, 3->1, 5->2, ...
                let idx = (abs_wi as usize) / 2;

                // Uses your `neg()` method already defined in `g1.rs`
                let to_add = if is_negative {
                    precomp[idx].neg()
                } else {
                    precomp[idx]
                };

                if !found_nonzero {
                    found_nonzero = true;
                    res = to_add;
                } else {
                    res = res.add(&to_add);
                }
            }
        }

        res
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::g1::G1Affine;

    #[test]
    fn test_wnaf_5_computation() {
        // Scalar = 315 (binary: 100111011)
        let scalar = [315, 0, 0, 0];
        let (wnaf, len) = wnaf_5(&scalar);

        // Mathematically reconstruct the scalar to verify exactness.
        let mut reconstructed: i64 = 0;
        for i in 0..len {
            reconstructed += (wnaf[i] as i64) * (1 << i);
        }
        assert_eq!(reconstructed, 315);
    }

    #[test]
    fn test_wnaf_max_scalar() {
        // Test with maximum 256-bit scalar to ensure no overflow panics.
        let max_scalar = [u64::MAX; 4];
        let (wnaf, len) = wnaf_5(&max_scalar);

        assert_eq!(len, 257);
        assert_eq!(wnaf[0], -1);
        assert_eq!(wnaf[256], 1);
    }

    #[test]
    fn test_mul_scalar_basic() {
        let g_aff = G1Affine::generator();
        let g = G1Projective::from_affine(&g_aff);

        // 1. Identity Check
        let zero = [0, 0, 0, 0];
        let res_zero = g.mul_scalar(&zero);
        assert!(res_zero.is_infinity());

        // 2. Multiply by 2
        let two = [2, 0, 0, 0];
        let res_two = g.mul_scalar(&two);
        assert_eq!(res_two.to_affine(), g.double().to_affine());

        // 3. Multiply by 15
        let fifteen = [15, 0, 0, 0];
        let res_fifteen = g.mul_scalar(&fifteen);

        // Manual 15*G via doubling and adding: 8G + 4G + 2G + 1G
        let g2 = g.double();
        let g4 = g2.double();
        let g8 = g4.double();
        let expected = g8.add(&g4).add(&g2).add(&g);

        assert_eq!(res_fifteen.to_affine(), expected.to_affine());
    }
}
