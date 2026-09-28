//! Native Montgomery multiplication for Fq and Fr.
//!
//! The dual ADX carry-chain schedule is adapted from Firedancer; `adx.S`
//! records the pinned source, license and changes to the assembly interface.

use crate::backend::{Field, U256};

/// Inputs are canonical Fr residues or private Fq operands below 2q.
/// The output is a canonical R=2^256 residue in the same field.
#[inline(always)]
pub(super) fn mul<F: Field>(a: &U256, b: &U256) -> U256 {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: enabled only for Linux x86_64 with ADX/BMI2. Each input pointer
    // references four initialized u64 limbs. The assembly reads those limbs,
    // restores all undeclared registers and its stack pointer, and writes only
    // its own temporary stack below the 128-byte red zone. The four result
    // registers are declared outputs; flags and scratch registers are clobbered.
    // Thus pure+readonly permits elimination of unused field products.
    // The private caller proves a,b<2q. Since 4q<R, ab<qR, each CIOS step
    // stays below b+q<3q<R and one final subtraction yields a value below q.
    // For Fr, a,b<r and 2r<R give the stronger bounds ab<rR and
    // each step below b+r<2r<R. The generic entry point dispatches here only
    // for these two moduli; other Field implementations retain portable CIOS.
    unsafe {
        core::arch::asm!(
            include_str!("adx.S"),
            inout("rsi") a.0.as_ptr() => r2,
            inout("rdx") b.0.as_ptr() => r1,
            in("rcx") F::MODULUS.0.as_ptr(),
            inout("r8") F::INV => r3,
            out("rax") r0,
            out("r9") _, out("r10") _, out("r11") _,
            options(pure, readonly, att_syntax),
        );
    }
    U256::new([r0, r1, r2, r3])
}
