//! Full byte-call benchmark fixtures and the core API adapter.
//!
//! The adapter includes allocation, decoding, subgroup validation, pairing,
//! final exponentiation and Boolean encoding in every timed call. It is a
//! benchmark adapter, not a replacement for the versioned syscall API.

use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup as _, BigInteger, PrimeField};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::{g1, g2, pairing::pairing_product_is_one};

pub const SEED: u64 = 0x7061_6972_6265_6e31;
pub const FIXTURES_PER_CASE: usize = 4;
pub const PAIR_COUNTS: [usize; 15] = [0, 1, 2, 3, 4, 8, 15, 16, 17, 31, 32, 33, 63, 64, 65];

#[derive(Clone, Copy, Debug)]
pub enum Order {
    Be,
    Le,
}

impl Order {
    pub fn name(self) -> &'static str {
        match self {
            Self::Be => "be",
            Self::Le => "le",
        }
    }
}

pub fn output(value: bool, order: Order) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[match order {
        Order::Be => 31,
        Order::Le => 0,
    }] = u8::from(value);
    bytes
}

/// Includes the Vec needed to hold decoded points for the borrowed-pair API.
/// No decoded points, prepared lines, subgroup results or final exponents are
/// reused between calls.
#[inline(never)]
pub fn full_call(input: &[u8], order: Order) -> Option<[u8; 32]> {
    if !input.len().is_multiple_of(192) {
        return None;
    }
    let mut pairs = Vec::with_capacity(input.len() / 192);
    for bytes in input.as_chunks::<192>().0 {
        let p_bytes = bytes[..64].try_into().unwrap();
        let q_bytes = bytes[64..].try_into().unwrap();
        let (p, q) = match order {
            Order::Be => (
                g1::Affine::from_be_bytes(p_bytes)?,
                g2::Affine::from_be_bytes(q_bytes)?,
            ),
            Order::Le => (
                g1::Affine::from_le_bytes(p_bytes)?,
                g2::Affine::from_le_bytes(q_bytes)?,
            ),
        };
        pairs.push((p, q));
    }
    Some(output(
        pairing_product_is_one(pairs.iter().map(|(p, q)| (p, q)))?,
        order,
    ))
}

pub struct Fixture {
    pub bytes: Vec<u8>,
    pub expected: [u8; 32],
}

pub struct Case {
    pub name: String,
    pub order: Order,
    pub fixtures: Vec<Fixture>,
}

fn encode(pairs: &[(G1Affine, G2Affine)], order: Order) -> Vec<u8> {
    let mut bytes = vec![0; 192 * pairs.len()];
    for ((p, q), chunk) in pairs.iter().zip(bytes.as_chunks_mut::<192>().0) {
        if !p.infinity {
            chunk[..32].copy_from_slice(&p.x.into_bigint().to_bytes_le());
            chunk[32..64].copy_from_slice(&p.y.into_bigint().to_bytes_le());
        }
        if !q.infinity {
            for (value, out) in [q.x.c0, q.x.c1, q.y.c0, q.y.c1]
                .into_iter()
                .zip(chunk[64..].as_chunks_mut::<32>().0)
            {
                out.copy_from_slice(&value.into_bigint().to_bytes_le());
            }
        }
        if matches!(order, Order::Be) {
            chunk[..32].reverse();
            chunk[32..64].reverse();
            chunk[64..128].reverse();
            chunk[128..].reverse();
        }
    }
    bytes
}

pub fn cases() -> Vec<Case> {
    let mut rng = StdRng::seed_from_u64(SEED);
    let mut pools: Vec<Vec<_>> = (0..FIXTURES_PER_CASE)
        .map(|_| {
            (0..32)
                .map(|_| {
                    let a = Fr::from_le_bytes_mod_order(&rng.random::<[u8; 32]>());
                    let b = Fr::from_le_bytes_mod_order(&rng.random::<[u8; 32]>());
                    assert_ne!(a, Fr::ZERO);
                    assert_ne!(b, Fr::ZERO);
                    let p = G1Affine::generator()
                        .mul_bigint(a.into_bigint())
                        .into_affine();
                    let q = G2Affine::generator()
                        .mul_bigint(b.into_bigint())
                        .into_affine();
                    ((p, q), a * b)
                })
                .collect()
        })
        .collect();
    // Build every original 32-pair pool before extending them, so the seeded
    // fixtures for existing counts keep exactly the same inputs.
    for pool in &mut pools {
        let a = Fr::from_le_bytes_mod_order(&rng.random::<[u8; 32]>());
        let b = Fr::from_le_bytes_mod_order(&rng.random::<[u8; 32]>());
        assert_ne!(a, Fr::ZERO);
        assert_ne!(b, Fr::ZERO);
        let p = G1Affine::generator()
            .mul_bigint(a.into_bigint())
            .into_affine();
        let q = G2Affine::generator()
            .mul_bigint(b.into_bigint())
            .into_affine();
        pool.push(((p, q), a * b));
    }
    // Extend only after all original 33-pair pools have been generated, so
    // every pre-existing byte fixture remains exactly the same.
    for pool in &mut pools {
        for _ in pool.len()..65 {
            let a = Fr::from_le_bytes_mod_order(&rng.random::<[u8; 32]>());
            let b = Fr::from_le_bytes_mod_order(&rng.random::<[u8; 32]>());
            assert_ne!(a, Fr::ZERO);
            assert_ne!(b, Fr::ZERO);
            let p = G1Affine::generator()
                .mul_bigint(a.into_bigint())
                .into_affine();
            let q = G2Affine::generator()
                .mul_bigint(b.into_bigint())
                .into_affine();
            pool.push(((p, q), a * b));
        }
    }
    let mut result = Vec::new();
    for count in PAIR_COUNTS {
        for order in [Order::Be, Order::Le] {
            let fixtures = pools
                .iter()
                .map(|pool| {
                    let pairs: Vec<_> = pool[..count].iter().map(|x| x.0).collect();
                    let sum = pool[..count].iter().fold(Fr::ZERO, |sum, x| sum + x.1);
                    Fixture {
                        bytes: encode(&pairs, order),
                        expected: output(sum == Fr::ZERO, order),
                    }
                })
                .collect();
            result.push(Case {
                name: format!("seeded_{count}"),
                order,
                fixtures,
            });
        }
    }
    for name in ["repeated_16", "cancelling_2", "identity_mixed_4"] {
        for order in [Order::Be, Order::Le] {
            let fixtures = pools
                .iter()
                .map(|pool| {
                    let (p, q) = pool[0].0;
                    let (pairs, is_one) = match name {
                        "repeated_16" => (vec![(p, q); 16], pool[0].1 * Fr::from(16) == Fr::ZERO),
                        "cancelling_2" => (vec![(p, q), (-p, q)], true),
                        "identity_mixed_4" => (
                            vec![
                                (G1Affine::identity(), q),
                                (p, G2Affine::identity()),
                                (p, q),
                                (-p, q),
                            ],
                            true,
                        ),
                        _ => unreachable!(),
                    };
                    Fixture {
                        bytes: encode(&pairs, order),
                        expected: output(is_one, order),
                    }
                })
                .collect();
            result.push(Case {
                name: name.to_owned(),
                order,
                fixtures,
            });
        }
    }
    result
}
