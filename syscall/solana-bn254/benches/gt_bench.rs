//! Complete Gt::pow calls on validated target-group inputs, including any table setup.
//! Arkworks uses generic Fq12::pow on the same ordinary 256-bit integer.

use ark_bn254::{
    Bn254, Fq as ArkFq, Fq2 as ArkFq2, Fq6 as ArkFq6, Fq12 as ArkFq12, Fr, G1Affine, G2Affine,
};
use ark_ec::{AffineRepr, pairing::Pairing};
use ark_ff::{Field as _, PrimeField};
use criterion::{Criterion, criterion_group, criterion_main};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::{
    backend::{Fq2, Fq6, Fq12, U256},
    gt::Gt,
};
use std::{hint::black_box, time::Duration};

fn ours(value: ArkFq12, radix: ArkFq) -> Fq12 {
    let raw = |v: ArkFq| U256::new((v * radix).into_bigint().0);
    let fq2 = |v: ArkFq2| Fq2::from_montgomery(raw(v.c0), raw(v.c1)).unwrap();
    let fq6 = |v: ArkFq6| Fq6::new(fq2(v.c0), fq2(v.c1), fq2(v.c2));
    Fq12::new(fq6(value.c0), fq6(value.c1))
}

fn bench_gt(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0x6774_706f_7762_7631);
    let generator = Bn254::pairing(G1Affine::generator(), G2Affine::generator()).0;
    let radix = ArkFq::from(2).pow([256]);
    let bases: [_; 4] = core::array::from_fn(|_| {
        let value = generator.pow(rng.random::<[u64; 4]>());
        assert_ne!(value, ArkFq12::ONE);
        (Gt::from_fq12(ours(value, radix)).unwrap(), value)
    });
    let random64: [[u64; 4]; 4] =
        core::array::from_fn(|_| [rng.random::<u64>() | (1 << 63), 0, 0, 0]);
    let random256: [[u64; 4]; 4] = core::array::from_fn(|_| {
        let mut value = rng.random::<[u64; 4]>();
        value[3] |= 1 << 63;
        value
    });
    let r = Fr::MODULUS.0;
    let mut below = r;
    below[0] -= 1;
    let mut above = r;
    above[0] += 1;
    let cases = [
        ("zero", [[0; 4]; 4]),
        ("one", [[1, 0, 0, 0]; 4]),
        ("two", [[2, 0, 0, 0]; 4]),
        ("small_15", [[15, 0, 0, 0]; 4]),
        ("small_65537", [[65537, 0, 0, 0]; 4]),
        ("dense_64", [[u64::MAX, 0, 0, 0]; 4]),
        ("random_64", random64),
        ("bit_255", [[0, 0, 0, 1 << 63]; 4]),
        ("sparse_256", [[1, 1, 1, 1 << 63]; 4]),
        ("random_256", random256),
        ("r_minus_1", [below; 4]),
        ("r", [r; 4]),
        ("r_plus_1", [above; 4]),
        ("max_256", [[u64::MAX; 4]; 4]),
        ("identity_random_256", random256),
    ];
    let mut manifest = String::new();
    for (name, exponents) in cases {
        let inputs = if name == "identity_random_256" {
            [(Gt::IDENTITY, ArkFq12::ONE); 4]
        } else {
            bases
        };
        for (i, ((value, expected), exponent)) in inputs.iter().zip(exponents).enumerate() {
            let answer = ours(expected.pow(exponent), radix);
            assert_eq!(value.pow(&U256::new(exponent)).to_fq12(), answer);
            manifest.push_str(&format!(
                "{name}\t{i}\t{value:?}\t{exponent:?}\t{answer:?}\n"
            ));
        }
        let mut group = c.benchmark_group(format!("gt_pow_{name}"));
        let mut index = 0;
        group.bench_function("solana-bn254", |b| {
            b.iter(|| {
                let value = black_box(&inputs[index].0);
                let exponent = black_box(U256::new(exponents[index]));
                index = (index + 1) % inputs.len();
                black_box(value.pow(&exponent))
            })
        });
        let mut index = 0;
        group.bench_function("arkworks", |b| {
            b.iter(|| {
                let value = black_box(&inputs[index].1);
                let exponent = black_box(exponents[index]);
                index = (index + 1) % inputs.len();
                black_box(value.pow(exponent))
            })
        });
        group.finish();
    }
    if let Some(path) = std::env::var_os("BN254_GT_FIXTURE_MANIFEST") {
        std::fs::write(path, manifest).unwrap();
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(100)
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(5))
        .noise_threshold(0.01)
        .confidence_level(0.95)
        .significance_level(0.05);
    targets = bench_gt
}
criterion_main!(benches);
