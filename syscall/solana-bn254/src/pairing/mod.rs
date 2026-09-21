//! Checked BN254 optimal-Ate pairings for public data.
//!
//! Values match the Arkworks 0.5 BN254 pairing convention; see
//! `docs/pairing.md` for the final-exponent normalization.
//! The implementation is variable-time, allocation-free and `no_std`.
//! Multi-pairing accepts arbitrary input length using bounded batches.

use crate::{g1, g2, gt::Gt};

pub(crate) mod final_exp;
mod miller;

/// Computes a pairing, checking G2 subgroup membership even when G1 is identity.
///
/// G1's validated type already establishes subgroup membership. G2's affine
/// type only establishes the curve equation, so a nonmember returns `None`.
pub fn pairing(p: &g1::Affine, q: &g2::Affine) -> Option<Gt> {
    multi_pairing(core::iter::once((p, q)))
}

/// Computes the product of pairings, with one final exponentiation.
///
/// Each G2 point is subgroup-checked before identity pairs are skipped. A
/// cancelling or identity prefix never hides an invalid later point. Empty
/// input returns identity. There is no limit on the number of input pairs.
/// The iterator is consumed in bounded chunks before validation, so an invalid
/// point may be followed by other consumed inputs from its chunk. Validation
/// stops on failure; inputs in later chunks need not be consumed or checked.
///
/// Point state for at most 32 active pairs is kept on the stack (6.5 KiB on
/// 64-bit targets), borrowing the caller's immutable affine points.
/// Bounded subgroup validation shares one normalization inverse and adds
/// 8.75 KiB of declared buffers at this batch size, plus arithmetic temporaries.
/// Miller squarings are shared within each batch; batch results are multiplied
/// before final exponentiation. No prepared tables or heap allocation are used.
pub fn multi_pairing<'a>(
    pairs: impl IntoIterator<Item = (&'a g1::Affine, &'a g2::Affine)>,
) -> Option<Gt> {
    let value = miller::multi_miller_loop(pairs)?;
    final_exp::final_exponentiation(value.0).map(Gt::from_final_exponentiation)
}

/// Checks whether a pairing product is identity, with the same validation as
/// [`multi_pairing`]. Empty input returns `Some(true)`; invalid G2 returns `None`.
pub fn pairing_product_is_one<'a>(
    pairs: impl IntoIterator<Item = (&'a g1::Affine, &'a g2::Affine)>,
) -> Option<bool> {
    multi_pairing(pairs).map(|value| value.is_identity())
}

#[cfg(test)]
#[path = "../../tests/common/tower.rs"]
mod oracle;
