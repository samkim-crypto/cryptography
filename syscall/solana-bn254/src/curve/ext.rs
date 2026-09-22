//! BN254 Extension Fields (Fq2, Fq6, Fq12)
//!
//! Highly optimized towering arithmetic using Karatsuba and Toom-Cook methods.
//! Built for public-data operations inside the Solana SVM.

use crate::backend::{Backend, Fq, MontgomeryBackend, U256};

/// An element in the quadratic extension field Fq2 = Fq[u] / (u^2 + 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fq2 {
    pub c0: U256,
    pub c1: U256,
}

impl Fq2 {
    #[inline(always)]
    pub const fn zero() -> Self {
        Self {
            c0: U256::zero(),
            c1: U256::zero(),
        }
    }

    #[inline(always)]
    pub fn one() -> Self {
        type B = Backend<Fq>;
        Self {
            c0: B::to_mont(&U256::one()),
            c1: U256::zero(),
        }
    }

    #[inline(always)]
    pub fn add(&self, other: &Self) -> Self {
        type B = Backend<Fq>;
        Self {
            c0: B::add(&self.c0, &other.c0),
            c1: B::add(&self.c1, &other.c1),
        }
    }

    #[inline(always)]
    pub fn sub(&self, other: &Self) -> Self {
        type B = Backend<Fq>;
        Self {
            c0: B::sub(&self.c0, &other.c0),
            c1: B::sub(&self.c1, &other.c1),
        }
    }

    #[inline(always)]
    pub fn double(&self) -> Self {
        type B = Backend<Fq>;
        Self {
            c0: B::add(&self.c0, &self.c0),
            c1: B::add(&self.c1, &self.c1),
        }
    }

    #[inline(always)]
    pub fn neg(&self) -> Self {
        type B = Backend<Fq>;
        Self {
            c0: B::neg(&self.c0),
            c1: B::neg(&self.c1),
        }
    }

    #[inline(always)]
    pub fn conjugate(&self) -> Self {
        type B = Backend<Fq>;
        Self {
            c0: self.c0,
            c1: B::neg(&self.c1),
        }
    }

    /// Karatsuba multiplication for Fq2.
    /// (a0+a1*u)(b0+b1*u) = (a0*b0 - a1*b1) + ((a0+a1)(b0+b1) - a0*b0 - a1*b1)u
    pub fn mul(&self, other: &Self) -> Self {
        type B = Backend<Fq>;
        let v0 = B::mul(&self.c0, &other.c0);
        let v1 = B::mul(&self.c1, &other.c1);

        let t0 = B::add(&self.c0, &self.c1);
        let t1 = B::add(&other.c0, &other.c1);
        let t2 = B::mul(&t0, &t1);

        let t3 = B::sub(&t2, &v0);
        let c1 = B::sub(&t3, &v1);
        let c0 = B::sub(&v0, &v1); // u^2 = -1

        Self { c0, c1 }
    }

    /// Complex squaring for Fq2: (c0 + c1*u)^2 = (c0+c1)(c0-c1) + 2*c0*c1*u
    pub fn sqr(&self) -> Self {
        type B = Backend<Fq>;
        let a0_plus_a1 = B::add(&self.c0, &self.c1);
        let a0_minus_a1 = B::sub(&self.c0, &self.c1);
        let c0 = B::mul(&a0_plus_a1, &a0_minus_a1);

        let a0_a1 = B::mul(&self.c0, &self.c1);
        let c1 = B::add(&a0_a1, &a0_a1);

        Self { c0, c1 }
    }

    /// Inverts an Fq2 element: (c0 - c1*u) / (c0^2 + c1^2).
    pub fn invert(&self) -> Self {
        type B = Backend<Fq>;
        let t0 = B::sqr(&self.c0);
        let t1 = B::sqr(&self.c1);
        let t2 = B::add(&t0, &t1);

        // Relies on your Fq::invert seamlessly matching Backend field traits
        let inv = Fq::invert(&t2);

        let c0 = B::mul(&self.c0, &inv);
        let c1_neg = B::neg(&self.c1);
        let c1 = B::mul(&c1_neg, &inv);

        Self { c0, c1 }
    }

    /// Multiplies by the non-residue xi = 9 + u.
    /// Operates purely via structural additions to save compute units.
    pub fn mul_by_xi(&self) -> Self {
        type B = Backend<Fq>;
        // 9x = x + 8x
        let d0 = B::add(&self.c0, &self.c0);
        let q0 = B::add(&d0, &d0);
        let o0 = B::add(&q0, &q0);
        let n0 = B::add(&o0, &self.c0);

        let d1 = B::add(&self.c1, &self.c1);
        let q1 = B::add(&d1, &d1);
        let o1 = B::add(&q1, &q1);
        let n1 = B::add(&o1, &self.c1);

        // (c0 + c1*u) * (9 + u) = (9*c0 - c1) + (c0 + 9*c1)*u
        let c0 = B::sub(&n0, &self.c1);
        let c1 = B::add(&self.c0, &n1);

        Self { c0, c1 }
    }
}

/// An element in the sextic extension field Fq6 = Fq2[v] / (v^3 - xi).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fq6 {
    pub c0: Fq2,
    pub c1: Fq2,
    pub c2: Fq2,
}

impl Fq6 {
    #[inline(always)]
    pub const fn zero() -> Self {
        Self {
            c0: Fq2::zero(),
            c1: Fq2::zero(),
            c2: Fq2::zero(),
        }
    }

    #[inline(always)]
    pub fn one() -> Self {
        Self {
            c0: Fq2::one(),
            c1: Fq2::zero(),
            c2: Fq2::zero(),
        }
    }

    #[inline(always)]
    pub fn add(&self, other: &Self) -> Self {
        Self {
            c0: self.c0.add(&other.c0),
            c1: self.c1.add(&other.c1),
            c2: self.c2.add(&other.c2),
        }
    }

    #[inline(always)]
    pub fn sub(&self, other: &Self) -> Self {
        Self {
            c0: self.c0.sub(&other.c0),
            c1: self.c1.sub(&other.c1),
            c2: self.c2.sub(&other.c2),
        }
    }

    #[inline(always)]
    pub fn double(&self) -> Self {
        Self {
            c0: self.c0.double(),
            c1: self.c1.double(),
            c2: self.c2.double(),
        }
    }

    #[inline(always)]
    pub fn neg(&self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
            c2: self.c2.neg(),
        }
    }

    /// Toom-Cook / Karatsuba degree-3 multiplication.
    pub fn mul(&self, other: &Self) -> Self {
        let v0 = self.c0.mul(&other.c0);
        let v1 = self.c1.mul(&other.c1);
        let v2 = self.c2.mul(&other.c2);

        let t0 = self.c1.add(&self.c2).mul(&other.c1.add(&other.c2));
        let t0 = t0.sub(&v1).sub(&v2);

        let t1 = self.c0.add(&self.c1).mul(&other.c0.add(&other.c1));
        let t1 = t1.sub(&v0).sub(&v1);

        let t2 = self.c0.add(&self.c2).mul(&other.c0.add(&other.c2));
        let t2 = t2.sub(&v0).sub(&v2);

        let c0 = v0.add(&t0.mul_by_xi());
        let c1 = t1.add(&v2.mul_by_xi());
        let c2 = t2.add(&v1);

        Self { c0, c1, c2 }
    }

    /// Highly optimized Squaring for Fq6.
    pub fn sqr(&self) -> Self {
        let v0 = self.c0.sqr();
        let v1 = self.c1.sqr();
        let v2 = self.c2.sqr();

        let t0 = self.c1.mul(&self.c2);
        let t0 = t0.add(&t0);

        let t1 = self.c0.mul(&self.c1);
        let t1 = t1.add(&t1);

        let t2 = self.c0.mul(&self.c2);
        let t2 = t2.add(&t2);

        let c0 = v0.add(&t0.mul_by_xi());
        let c1 = t1.add(&v2.mul_by_xi());
        let c2 = t2.add(&v1);

        Self { c0, c1, c2 }
    }

    /// Inverts an Fq6 element.
    pub fn invert(&self) -> Self {
        let v0 = self.c0.sqr();
        let v1 = self.c1.sqr();
        let v2 = self.c2.sqr();

        let t0 = self.c1.mul(&self.c2);
        let t1 = self.c0.mul(&self.c1);
        let t2 = self.c0.mul(&self.c2);

        let a = v0.sub(&t0.mul_by_xi());
        let b = v2.mul_by_xi().sub(&t1);
        let c = v1.sub(&t2);

        let f0 = self.c0.mul(&a);
        let f1 = self.c2.mul(&b).mul_by_xi();
        let f2 = self.c1.mul(&c).mul_by_xi();
        let f = f0.add(&f1).add(&f2);

        let f_inv = f.invert();

        Self {
            c0: a.mul(&f_inv),
            c1: b.mul(&f_inv),
            c2: c.mul(&f_inv),
        }
    }

    /// Multiplies by the non-residue v structurally.
    #[inline(always)]
    pub fn mul_by_v(&self) -> Self {
        Self {
            c0: self.c2.mul_by_xi(),
            c1: self.c0,
            c2: self.c1,
        }
    }
}

/// An element in the dodecic extension field Fq12 = Fq6[w] / (w^2 - v).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fq12 {
    pub c0: Fq6,
    pub c1: Fq6,
}

impl Fq12 {
    #[inline(always)]
    pub const fn zero() -> Self {
        Self {
            c0: Fq6::zero(),
            c1: Fq6::zero(),
        }
    }

    #[inline(always)]
    pub fn one() -> Self {
        Self {
            c0: Fq6::one(),
            c1: Fq6::zero(),
        }
    }

    #[inline(always)]
    pub fn add(&self, other: &Self) -> Self {
        Self {
            c0: self.c0.add(&other.c0),
            c1: self.c1.add(&other.c1),
        }
    }

    #[inline(always)]
    pub fn sub(&self, other: &Self) -> Self {
        Self {
            c0: self.c0.sub(&other.c0),
            c1: self.c1.sub(&other.c1),
        }
    }

    #[inline(always)]
    pub fn double(&self) -> Self {
        Self {
            c0: self.c0.double(),
            c1: self.c1.double(),
        }
    }

    #[inline(always)]
    pub fn neg(&self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }

    /// Karatsuba multiplication for Fq12.
    pub fn mul(&self, other: &Self) -> Self {
        let v0 = self.c0.mul(&other.c0);
        let v1 = self.c1.mul(&other.c1);

        let t0 = self.c0.add(&self.c1);
        let t1 = other.c0.add(&other.c1);
        let t2 = t0.mul(&t1).sub(&v0).sub(&v1);

        let c0 = v0.add(&v1.mul_by_v());
        let c1 = t2;

        Self { c0, c1 }
    }

    /// Squaring for Fq12.
    pub fn sqr(&self) -> Self {
        let v0 = self.c0.sqr();
        let v1 = self.c1.sqr();

        let t = self.c0.mul(&self.c1);
        let c1 = t.add(&t);

        let c0 = v0.add(&v1.mul_by_v());

        Self { c0, c1 }
    }

    /// Inverts an Fq12 element.
    pub fn invert(&self) -> Self {
        let v0 = self.c0.sqr();
        let v1 = self.c1.sqr();
        let v1_v = v1.mul_by_v();

        let f = v0.sub(&v1_v);
        let f_inv = f.invert();

        Self {
            c0: self.c0.mul(&f_inv),
            c1: self.c1.neg().mul(&f_inv),
        }
    }

    /// Conjugates an Fq12 element (maps w -> -w).
    #[inline(always)]
    pub fn conjugate(&self) -> Self {
        Self {
            c0: self.c0,
            c1: self.c1.neg(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fq2_algebra() {
        let one = Fq2::one();
        let two = one.double();
        let four = two.sqr();
        let four_mul = two.mul(&two);

        assert_eq!(four, four_mul);

        let inv = two.invert();
        let expected = two.mul(&inv);
        assert_eq!(expected, one);
    }

    #[test]
    fn test_fq6_fq12_basics() {
        let a = Fq6::one();
        let b = Fq6::zero();
        assert_eq!(a.mul(&b), Fq6::zero());

        let c = Fq12::one();
        assert_eq!(c.sqr(), c);
        assert_eq!(c.invert(), c);
    }
}
