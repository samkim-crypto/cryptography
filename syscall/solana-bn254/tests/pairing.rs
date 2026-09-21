use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fq12 as ArkFq12, Fr as ArkFr, G1Affine, G2Affine,
};
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_ff::{BigInteger, Field as _, PrimeField};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::{
    backend::{Fq2, U256},
    g1, g2,
    gt::Gt,
    pairing::{multi_pairing, pairing, pairing_product_is_one},
};
use std::sync::LazyLock;

#[path = "fixtures/pairing.rs"]
mod fixtures;

static RADIX: LazyLock<ArkFq> = LazyLock::new(|| ArkFq::from(2).pow([256]));

fn raw(value: ArkFq) -> U256 {
    U256::new((value * *RADIX).into_bigint().0)
}

fn ours1(value: G1Affine) -> g1::Affine {
    if value.infinity {
        g1::Affine::IDENTITY
    } else {
        g1::Affine::from_montgomery(raw(value.x), raw(value.y)).unwrap()
    }
}

fn ours2(value: G2Affine) -> g2::Affine {
    let coefficient = |v: ArkFq2| Fq2::from_montgomery(raw(v.c0), raw(v.c1)).unwrap();
    if value.infinity {
        g2::Affine::IDENTITY
    } else {
        g2::Affine::from_montgomery(coefficient(value.x), coefficient(value.y)).unwrap()
    }
}

fn check(actual: Gt, expected: ArkFq12) {
    for (a, b) in actual
        .to_fq12()
        .to_coefficients()
        .into_iter()
        .zip([expected.c0, expected.c1])
    {
        for (a, b) in a.to_coefficients().into_iter().zip([b.c0, b.c1, b.c2]) {
            assert_eq!(a.to_montgomery(), (raw(b.c0), raw(b.c1)));
        }
    }
}

#[test]
fn generator_identity_and_signs_match_arkworks() {
    let p = G1Affine::generator();
    let q = G2Affine::generator();
    let expected = Bn254::pairing(p, q).0;
    let actual = pairing(&ours1(p), &ours2(q)).unwrap();
    assert!(!actual.is_identity());
    check(actual, expected);
    for (p, q) in [
        (-p, q),
        (p, -q),
        (-p, -q),
        (G1Affine::identity(), q),
        (p, G2Affine::identity()),
        (G1Affine::identity(), G2Affine::identity()),
    ] {
        check(
            pairing(&ours1(p), &ours2(q)).unwrap(),
            Bn254::pairing(p, q).0,
        );
    }
    assert_eq!(pairing(&ours1(-p), &ours2(q)), Some(actual.inverse()));
    assert_eq!(multi_pairing(core::iter::empty()), Some(Gt::IDENTITY));
    assert_eq!(
        multi_pairing(core::iter::from_fn(|| None)),
        Some(Gt::IDENTITY)
    );
    assert_eq!(pairing_product_is_one(core::iter::empty()), Some(true));
}

#[test]
fn seeded_pairings_and_bilinearity_match_exact_values() {
    let p = G1Affine::generator();
    let q = G2Affine::generator();
    let base = pairing(&ours1(p), &ours2(q)).unwrap();
    let mut rng = StdRng::seed_from_u64(0x7061_6972_7365_7631);
    for _ in 0..64 {
        let a = rng.random::<[u64; 4]>();
        let b = rng.random::<[u64; 4]>();
        let pa = p.mul_bigint(a).into_affine();
        let qb = q.mul_bigint(b).into_affine();
        let actual = pairing(&ours1(pa), &ours2(qb)).unwrap();
        check(actual, Bn254::pairing(pa, qb).0);
        let a = ArkFr::from_le_bytes_mod_order(&ark_ff::BigInt(a).to_bytes_le());
        let b = ArkFr::from_le_bytes_mod_order(&ark_ff::BigInt(b).to_bytes_le());
        assert_eq!(actual, base.pow(&U256::new((a * b).into_bigint().0)));
    }
}

#[test]
fn multi_pairing_matches_singles_across_batch_boundaries() {
    let mut rng = StdRng::seed_from_u64(0x7061_6972_6d75_7631);
    let reference: Vec<_> = (0..65)
        .map(|_| {
            (
                G1Affine::generator()
                    .mul_bigint(rng.random::<[u64; 4]>())
                    .into_affine(),
                G2Affine::generator()
                    .mul_bigint(rng.random::<[u64; 4]>())
                    .into_affine(),
            )
        })
        .collect();
    let pairs: Vec<_> = reference
        .iter()
        .map(|&(p, q)| (ours1(p), ours2(q)))
        .collect();
    let singles: Vec<_> = pairs.iter().map(|(p, q)| pairing(p, q).unwrap()).collect();
    for count in [0, 1, 2, 3, 4, 8, 15, 16, 17, 31, 32, 33, 48, 49, 63, 64, 65] {
        let actual = multi_pairing(pairs[..count].iter().map(|(p, q)| (p, q))).unwrap();
        let expected = Bn254::multi_pairing(
            reference[..count].iter().map(|p| p.0),
            reference[..count].iter().map(|p| p.1),
        )
        .0;
        check(actual, expected);
        assert_eq!(
            actual,
            singles[..count]
                .iter()
                .copied()
                .fold(Gt::IDENTITY, |a, b| a * b)
        );
        assert_eq!(
            pairing_product_is_one(pairs[..count].iter().map(|(p, q)| (p, q))),
            Some(actual.is_identity())
        );
    }
}

#[test]
fn identities_and_cancellation_span_batches() {
    let p = ours1(G1Affine::generator());
    let q = ours2(G2Affine::generator());
    for count in [15, 16, 17, 31, 32, 33, 63, 64, 65] {
        let mut pairs = vec![(p, q); count];
        // Cancellation partners deliberately fall in subsequent batches.
        pairs.extend(vec![(-p, q); count]);
        pairs.insert(0, (g1::Affine::IDENTITY, q));
        for position in [16, 32, 64] {
            if position <= pairs.len() {
                pairs.insert(position, (p, g2::Affine::IDENTITY));
            }
        }
        pairs.push((g1::Affine::IDENTITY, g2::Affine::IDENTITY));
        assert_eq!(
            multi_pairing(pairs.iter().map(|(p, q)| (p, q))),
            Some(Gt::IDENTITY)
        );
        assert_eq!(
            pairing_product_is_one(pairs.iter().map(|(p, q)| (p, q))),
            Some(true)
        );
    }
}

fn non_subgroup() -> G2Affine {
    for i in 0..1024u64 {
        if let Some(point) =
            G2Affine::get_point_from_x_unchecked(ArkFq2::new(ArkFq::from(i), ArkFq::ONE), false)
        {
            let torsion = point.mul_bigint(ArkFr::MODULUS).into_affine();
            if !torsion.infinity {
                assert!(!torsion.mul_bigint(ArkFr::MODULUS).into_affine().infinity);
                return torsion;
            }
        }
    }
    panic!("no non-subgroup fixture");
}

#[test]
fn nonmembers_are_rejected_despite_identity_or_cancelling_prefixes() {
    let p = ours1(G1Affine::generator());
    let q = ours2(G2Affine::generator());
    let torsion = non_subgroup();
    for bad in [
        torsion,
        (torsion.into_group() + G2Affine::generator()).into_affine(),
    ] {
        assert!(!bad.mul_bigint(ArkFr::MODULUS).into_affine().infinity);
        let bad = ours2(bad);
        for p_bad in [p, g1::Affine::IDENTITY] {
            assert_eq!(pairing(&p_bad, &bad), None);
            for count in [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65] {
                for position in [0, count / 2, count] {
                    let mut pairs: Vec<_> = (0..count)
                        .map(|i| (if i % 2 == 0 { p } else { -p }, q))
                        .collect();
                    pairs.insert(position, (p_bad, bad));
                    // Hide the iterator's length: the first pair and later
                    // invalid points must still pass through validation.
                    let mut inputs = pairs.iter().map(|(p, q)| (p, q));
                    assert_eq!(multi_pairing(core::iter::from_fn(|| inputs.next())), None);
                    assert_eq!(
                        pairing_product_is_one(pairs.iter().map(|(p, q)| (p, q))),
                        None
                    );
                }
            }
        }
    }
}

fn decode(input: &[u8], big_endian: bool) -> Option<Vec<(g1::Affine, g2::Affine)>> {
    if !input.len().is_multiple_of(192) {
        return None;
    }
    input
        .as_chunks::<192>()
        .0
        .iter()
        .map(|bytes| {
            let p = &bytes[..64].try_into().unwrap();
            let q = &bytes[64..].try_into().unwrap();
            Some(if big_endian {
                (g1::Affine::from_be_bytes(p)?, g2::Affine::from_be_bytes(q)?)
            } else {
                (g1::Affine::from_le_bytes(p)?, g2::Affine::from_le_bytes(q)?)
            })
        })
        .collect()
}

#[test]
fn saved_byte_fixtures_match_the_pairing_engine_in_both_endiannesses() {
    for fixture in fixtures::fixtures() {
        for (be, bytes) in [(false, &fixture.le), (true, &fixture.be)] {
            // Decoding intentionally does not check G2 subgroup membership:
            // the production pairing boundary must reject those fixtures.
            let actual = decode(bytes, be)
                .and_then(|pairs| pairing_product_is_one(pairs.iter().map(|(p, q)| (p, q))));
            assert_eq!(actual, fixture.expected, "{} be={be}", fixture.name);
        }
    }
}
