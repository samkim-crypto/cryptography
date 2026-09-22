//! Equivalent complete byte calls, plus separately labelled decoded kernels.
//! Run through scripts/benchmark-bn254-groups.py in benchctl's remote queue.

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::{rngs::StdRng, RngExt, SeedableRng};
use solana_bn254::{backend::U256, g1, g2};
use solana_bn254_syscall::{addition::*, multiplication::*, Endianness};
use std::{hint::black_box, os::raw::c_ulong, time::Duration};

const SEED: u64 = 0x6731_6732_6265_6e31;
const POOL: usize = 8;

// Read once per fixture setup, outside every timed closure. An explicit seed
// permits confirmation on a second point/scalar pool without changing source.
fn fixture_seed() -> u64 {
    match std::env::var("BN254_GROUP_BENCH_SEED") {
        Ok(value) => match value.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).expect("hex benchmark seed"),
            None => value.parse().expect("decimal benchmark seed"),
        },
        Err(std::env::VarError::NotPresent) => SEED,
        Err(error) => panic!("invalid benchmark seed: {error}"),
    }
}

#[derive(Clone, Copy, Debug)]
enum Op {
    G1Add,
    G1Mul,
    G2Add,
    G2Mul,
}

impl Op {
    fn name(self) -> &'static str {
        match self {
            Self::G1Add => "g1_add",
            Self::G1Mul => "g1_mul",
            Self::G2Add => "g2_add",
            Self::G2Mul => "g2_mul",
        }
    }
    fn point_size(self) -> usize {
        match self {
            Self::G1Add | Self::G1Mul => 64,
            Self::G2Add | Self::G2Mul => 128,
        }
    }
    fn input_size(self) -> usize {
        self.point_size()
            + match self {
                Self::G1Add | Self::G2Add => self.point_size(),
                Self::G1Mul | Self::G2Mul => 32,
            }
    }
}

#[link(name = "firedancer_bn254", kind = "static")]
unsafe extern "C" {
    fn fd_bn254_g1_add_syscall(out: *mut u8, input: *const u8, len: c_ulong, be: i32) -> i32;
    fn fd_bn254_g1_scalar_mul_syscall(out: *mut u8, input: *const u8, len: c_ulong, be: i32)
        -> i32;
    fn fd_bn254_g2_add_syscall(out: *mut u8, input: *const u8, len: c_ulong, be: i32) -> i32;
    fn fd_bn254_g2_scalar_mul_syscall(out: *mut u8, input: *const u8, len: c_ulong, be: i32)
        -> i32;
}

// A fixed output buffer avoids adding a benchmark-only heap allocation to each
// call. G1 uses its first 64 bytes; its trailing bytes stay zero on every path.
type Output = Option<[u8; 128]>;
type Call = fn(Op, &[u8], bool) -> Output;

fn widen(bytes: [u8; 64]) -> [u8; 128] {
    let mut out = [0; 128];
    out[..64].copy_from_slice(&bytes);
    out
}

fn scalar(bytes: &[u8], be: bool) -> U256 {
    U256::new(core::array::from_fn(|i| {
        let index = if be { 3 - i } else { i };
        let chunk = bytes[8 * index..8 * (index + 1)].try_into().unwrap();
        if be {
            u64::from_be_bytes(chunk)
        } else {
            u64::from_le_bytes(chunk)
        }
    }))
}

#[inline(never)]
fn ours(op: Op, input: &[u8], be: bool) -> Output {
    let size = op.input_size();
    let padded_g1 = be && matches!(op, Op::G1Add | Op::G1Mul);
    if input.len() > size || (!padded_g1 && input.len() != size) {
        return None;
    }
    let mut padded = [0u8; 256];
    padded[..input.len()].copy_from_slice(input);
    let input = &padded[..size];
    let read_g1 = |bytes: &[u8]| {
        if be {
            g1::Affine::from_be_bytes(bytes.try_into().unwrap())
        } else {
            g1::Affine::from_le_bytes(bytes.try_into().unwrap())
        }
    };
    let read_g2 = |bytes: &[u8]| {
        if be {
            g2::Affine::from_be_bytes(bytes.try_into().unwrap())
        } else {
            g2::Affine::from_le_bytes(bytes.try_into().unwrap())
        }
    };
    match op {
        Op::G1Add | Op::G1Mul => {
            let a = read_g1(&input[..64])?;
            let result = if matches!(op, Op::G1Add) {
                a + read_g1(&input[64..])?
            } else {
                a.mul_scalar(&scalar(&input[64..], be))
            };
            Some(widen(if be {
                result.to_be_bytes()
            } else {
                result.to_le_bytes()
            }))
        }
        Op::G2Add | Op::G2Mul => {
            let a = read_g2(&input[..128])?;
            let result = if matches!(op, Op::G2Add) {
                a + read_g2(&input[128..])?
            } else {
                a.mul_scalar_checked(&scalar(&input[128..], be))?
            };
            Some(if be {
                result.to_be_bytes()
            } else {
                result.to_le_bytes()
            })
        }
    }
}

#[inline(never)]
fn ark(op: Op, input: &[u8], be: bool) -> Output {
    let order = if be { Endianness::BE } else { Endianness::LE };
    match op {
        Op::G1Add => {
            alt_bn128_versioned_g1_addition(VersionedG1Addition::V0, input, order).map(widen)
        }
        Op::G1Mul => {
            alt_bn128_versioned_g1_multiplication(VersionedG1Multiplication::V1, input, order)
                .map(widen)
        }
        Op::G2Add => alt_bn128_versioned_g2_addition(VersionedG2Addition::V0, input, order),
        Op::G2Mul => {
            alt_bn128_versioned_g2_multiplication(VersionedG2Multiplication::V0, input, order)
        }
    }
}

#[inline(never)]
fn firedancer(op: Op, input: &[u8], be: bool) -> Output {
    let mut out = [0; 128];
    let function = match op {
        Op::G1Add => fd_bn254_g1_add_syscall,
        Op::G1Mul => fd_bn254_g1_scalar_mul_syscall,
        Op::G2Add => fd_bn254_g2_add_syscall,
        Op::G2Mul => fd_bn254_g2_scalar_mul_syscall,
    };
    // SAFETY: output has at least the required 64/128 bytes; input_len is exact.
    // Firedancer copies input into its own aligned buffers before arithmetic.
    let status = unsafe {
        function(
            out.as_mut_ptr(),
            input.as_ptr(),
            input.len().try_into().unwrap(),
            i32::from(be),
        )
    };
    (status == 0).then_some(out)
}

const IMPLEMENTATIONS: [(&str, Call); 3] = [
    ("solana-bn254", ours),
    ("ark-bn254", ark),
    ("firedancer", firedancer),
];

fn g1_bytes(p: G1Affine) -> Vec<u8> {
    let mut out = vec![0; 64];
    if !p.infinity {
        out[..32].copy_from_slice(&p.x.into_bigint().to_bytes_le());
        out[32..].copy_from_slice(&p.y.into_bigint().to_bytes_le());
    }
    out
}

fn g2_bytes(p: G2Affine) -> Vec<u8> {
    let mut out = vec![0; 128];
    if !p.infinity {
        for (value, bytes) in [p.x.c0, p.x.c1, p.y.c0, p.y.c1]
            .into_iter()
            .zip(out.chunks_exact_mut(32))
        {
            bytes.copy_from_slice(&value.into_bigint().to_bytes_le());
        }
    }
    out
}

fn bytes_scalar(s: [u64; 4]) -> Vec<u8> {
    s.into_iter().flat_map(u64::to_le_bytes).collect()
}

// These fixtures are prepared before timing. Bounded random classes preserve
// the low bits of the original pool; exact classes force the named bit length.
fn crossover_scalar(name: &str, random: [u64; 4], i: usize) -> Option<[u64; 4]> {
    let bounded = |bits: usize| {
        core::array::from_fn(|limb| {
            let remaining = bits.saturating_sub(64 * limb);
            match remaining {
                0 => 0,
                1..=63 => random[limb] & ((1u64 << remaining) - 1),
                _ => random[limb],
            }
        })
    };
    if let Some(bits) = match name {
        "random16" => Some(16),
        "random32" => Some(32),
        "random48" => Some(48),
        "random80" => Some(80),
        "random112" => Some(112),
        "random144" => Some(144),
        "random160" => Some(160),
        "random176" => Some(176),
        "random224" => Some(224),
        _ => None,
    } {
        return Some(bounded(bits));
    }
    if let Some(bits) = match name {
        "exact127" => Some(127),
        "exact128" => Some(128),
        "exact129" => Some(129),
        _ => None,
    } {
        let mut scalar = bounded(bits);
        scalar[(bits - 1) / 64] |= 1 << ((bits - 1) % 64);
        return Some(scalar);
    }
    if let Some(bits) = match name {
        "sparse128" => Some(128),
        "sparse192" => Some(192),
        "sparse256" | "high_sparse" => Some(256),
        _ => None,
    } {
        let mut scalar = [1u64 << i, 0, 0, 0];
        scalar[(bits - 1) / 64] |= 1 << ((bits - 1) % 64);
        return Some(scalar);
    }
    if name == "ones_runs" {
        let bits: usize = [96, 112, 128, 160, 192, 224, 255, 256][i];
        return Some(core::array::from_fn(|limb| {
            match bits.saturating_sub(64 * limb) {
                0 => 0,
                1..=63 => (1u64 << (bits - 64 * limb)) - 1,
                _ => u64::MAX,
            }
        }));
    }
    None
}

fn order_input(op: Op, le: &[u8], be: bool) -> Vec<u8> {
    let mut out = le.to_vec();
    if be {
        let point_size = op.point_size();
        let point_count = if matches!(op, Op::G1Add | Op::G2Add) {
            2
        } else {
            1
        };
        for p in out[..point_size * point_count].chunks_exact_mut(point_size) {
            for coordinate in p.chunks_exact_mut(point_size / 2) {
                coordinate.reverse();
            }
        }
        if matches!(op, Op::G1Mul | Op::G2Mul) {
            out[point_size..].reverse();
        }
    }
    out
}

struct Case {
    op: Op,
    name: &'static str,
    inputs: Vec<Vec<u8>>,
}

fn nonmember() -> G2Affine {
    for i in 0..1024u64 {
        if let Some(p) = G2Affine::get_point_from_x_unchecked(Fq2::new(Fq::from(i), Fq::ONE), false)
        {
            let torsion = p.mul_bigint(Fr::MODULUS).into_affine();
            if !torsion.infinity {
                return torsion;
            }
        }
    }
    panic!("non-subgroup fixture");
}

fn fixtures() -> (Vec<Case>, Vec<(G1Affine, G2Affine, [u64; 4])>) {
    let mut rng = StdRng::seed_from_u64(fixture_seed());
    let pool: Vec<_> = (0..POOL)
        .map(|_| {
            let p = G1Affine::generator()
                .mul_bigint(rng.random::<[u64; 4]>())
                .into_affine();
            let q = G2Affine::generator()
                .mul_bigint(rng.random::<[u64; 4]>())
                .into_affine();
            (p, q, rng.random::<[u64; 4]>())
        })
        .collect();
    let mut cases = Vec::new();
    for op in [Op::G1Add, Op::G2Add] {
        for name in ["random", "double", "opposite", "identity"] {
            let inputs = pool
                .iter()
                .enumerate()
                .map(|(i, &(p, q, _))| {
                    if matches!(op, Op::G1Add) {
                        let other = match name {
                            "double" => p,
                            "opposite" => -p,
                            "identity" => G1Affine::identity(),
                            _ => pool[(i + 1) % POOL].0,
                        };
                        [g1_bytes(p), g1_bytes(other)].concat()
                    } else {
                        let other = match name {
                            "double" => q,
                            "opposite" => -q,
                            "identity" => G2Affine::identity(),
                            _ => pool[(i + 1) % POOL].1,
                        };
                        [g2_bytes(q), g2_bytes(other)].concat()
                    }
                })
                .collect();
            cases.push(Case { op, name, inputs });
        }
    }
    for op in [Op::G1Mul, Op::G2Mul] {
        for name in [
            "random256",
            "random192",
            "random128",
            "random96",
            "random64",
            "random16",
            "random32",
            "random48",
            "random80",
            "random112",
            "random144",
            "random160",
            "random176",
            "random224",
            "exact127",
            "exact128",
            "exact129",
            "sparse128",
            "sparse192",
            "sparse256",
            "ones_runs",
            "high_sparse",
            "sparse",
            "near_order",
            "max",
            "zero",
            "one",
        ] {
            let inputs = pool
                .iter()
                .enumerate()
                .map(|(i, &(p, q, random))| {
                    let s = match name {
                        "random192" => [random[0], random[1], random[2], 0],
                        "random128" => [random[0], random[1], 0, 0],
                        "random96" => [random[0], random[1] & 0xffff_ffff, 0, 0],
                        "random64" => [random[0], 0, 0, 0],
                        "sparse" => {
                            let mut s = [0; 4];
                            let bit = 32 * i + 7;
                            s[bit / 64] = 1 << (bit % 64);
                            s
                        }
                        "near_order" => {
                            let mut s = Fr::MODULUS.0;
                            s[0] += i as u64;
                            s[0] -= 3;
                            s
                        }
                        "max" => [u64::MAX; 4],
                        "zero" => [0; 4],
                        "one" => [1, 0, 0, 0],
                        "random256" => random,
                        _ => crossover_scalar(name, random, i).expect("known scalar class"),
                    };
                    let p = if matches!(op, Op::G1Mul) {
                        g1_bytes(p)
                    } else {
                        g2_bytes(q)
                    };
                    [p, bytes_scalar(s)].concat()
                })
                .collect();
            cases.push(Case { op, name, inputs });
        }
    }
    let torsion = nonmember();
    cases.push(Case {
        op: Op::G2Add,
        name: "full_twist",
        inputs: pool
            .iter()
            .map(|&(_, q, _)| [g2_bytes((q + torsion).into_affine()), g2_bytes(torsion)].concat())
            .collect(),
    });
    (cases, pool)
}

fn validate(cases: &[Case]) {
    let torsion = nonmember();
    let mut count = 0;
    for case in cases {
        for be in [false, true] {
            for le in &case.inputs {
                let input = order_input(case.op, le, be);
                let expected = ark(case.op, &input, be).expect("valid timing input");
                for (name, call) in IMPLEMENTATIONS {
                    assert_eq!(
                        call(case.op, &input, be),
                        Some(expected),
                        "{name} {:?} {} be={be}",
                        case.op,
                        case.name
                    );
                }
                count += 1;
            }
        }
    }
    // Contract checks are outside timing and include every scalar bit boundary.
    for op in [Op::G1Add, Op::G1Mul, Op::G2Add, Op::G2Mul] {
        let valid = cases
            .iter()
            .find(|c| c.op.name() == op.name())
            .unwrap()
            .inputs[0]
            .clone();
        let mut invalids = Vec::new();
        for coefficient in 0..op.point_size() / 32 {
            let mut bytes = valid.clone();
            bytes[32 * coefficient..32 * (coefficient + 1)]
                .copy_from_slice(&Fq::MODULUS.to_bytes_le());
            invalids.push((bytes, false));
        }
        let mut off_curve = valid.clone();
        off_curve[op.point_size() / 2..op.point_size()].fill(0);
        invalids.push((off_curve, false));
        for flag in [0x40, 0x80, 0xc0] {
            let mut bytes = valid.clone();
            bytes[op.point_size() - 1] |= flag;
            invalids.push((bytes, flag != 0xc0));
        }
        if matches!(op, Op::G2Mul) {
            for scalar in [[0; 4], [1, 0, 0, 0], Fr::MODULUS.0, [u64::MAX; 4]] {
                invalids.push(([g2_bytes(torsion), bytes_scalar(scalar)].concat(), false));
            }
        }
        for (bytes, accepted) in invalids {
            for be in [false, true] {
                let input = order_input(op, &bytes, be);
                let expected = ark(op, &input, be);
                assert_eq!(expected.is_some(), accepted, "oracle acceptance {op:?}");
                for (name, call) in IMPLEMENTATIONS {
                    assert_eq!(
                        call(op, &input, be),
                        expected,
                        "{name}: validation {op:?} be={be}"
                    );
                }
                count += 1;
            }
        }
        for be in [false, true] {
            for len in [0, 1, op.input_size() - 1, op.input_size() + 1] {
                let input = vec![0; len];
                let expected = ark(op, &input, be);
                for (name, call) in IMPLEMENTATIONS {
                    assert_eq!(
                        call(op, &input, be),
                        expected,
                        "{name}: length {len} {op:?} be={be}"
                    );
                }
            }
        }
        if matches!(op, Op::G1Mul | Op::G2Mul) {
            for bit in 0..256 {
                let mut scalar = [0; 4];
                scalar[bit / 64] = 1u64 << (bit % 64);
                let mut le = valid[..op.point_size()].to_vec();
                le.extend(bytes_scalar(scalar));
                let expected = ark(op, &le, false);
                for (name, call) in IMPLEMENTATIONS {
                    assert_eq!(
                        call(op, &le, false),
                        expected,
                        "{name}: {op:?} scalar bit {bit}"
                    );
                }
            }
        }
    }
    let seed = fixture_seed();
    eprintln!(
        "Validated {count} byte fixtures plus length/scalar boundaries across three implementations; seed={seed:#x}"
    );
}

fn bench_bytes(c: &mut Criterion) {
    let (cases, _) = fixtures();
    validate(&cases);
    for case in cases {
        let mut group = c.benchmark_group(format!("group_bytes_{}_{}", case.op.name(), case.name));
        for be in [false, true] {
            let inputs: Vec<_> = case
                .inputs
                .iter()
                .map(|le| order_input(case.op, le, be))
                .collect();
            for (name, call) in IMPLEMENTATIONS {
                let mut i = 0;
                group.bench_function(BenchmarkId::new(name, if be { "be" } else { "le" }), |b| {
                    b.iter(|| {
                        let input = &inputs[i];
                        i = (i + 1) % inputs.len();
                        black_box(call(case.op, black_box(input), be))
                    })
                });
            }
        }
        group.finish();
    }
}

fn bench_kernels(c: &mut Criterion) {
    let (_, pool) = fixtures();
    let p: Vec<_> = pool
        .iter()
        .map(|&(p, _, _)| g1::Affine::from_le_bytes(&g1_bytes(p).try_into().unwrap()).unwrap())
        .collect();
    let q: Vec<_> = pool
        .iter()
        .map(|&(_, q, _)| g2::Affine::from_le_bytes(&g2_bytes(q).try_into().unwrap()).unwrap())
        .collect();
    let torsion = nonmember();
    let raw: Vec<_> = pool
        .iter()
        .map(|&(_, q, _)| (q + torsion).into_affine())
        .collect();
    let raw_ours: Vec<_> = raw
        .iter()
        .map(|&q| g2::Affine::from_le_bytes(&g2_bytes(q).try_into().unwrap()).unwrap())
        .collect();
    for i in 0..POOL {
        assert_eq!(
            raw_ours[i]
                .mul_scalar(&U256::new(pool[i].2))
                .to_le_bytes()
                .as_slice(),
            g2_bytes(raw[i].mul_bigint(pool[i].2).into_affine())
        );
        assert!(q[i].is_in_correct_subgroup());
        assert!(!raw_ours[i].is_in_correct_subgroup());
    }
    macro_rules! kernel {
        ($name:literal, $ours:expr, $ark:expr) => {{
            let mut group = c.benchmark_group(concat!("group_kernel_", $name));
            let mut i = 0;
            group.bench_function("solana-bn254", |b| {
                b.iter(|| {
                    let j = i;
                    i = (i + 1) % POOL;
                    black_box(($ours)(black_box(j)))
                })
            });
            let mut i = 0;
            group.bench_function("ark-bn254", |b| {
                b.iter(|| {
                    let j = i;
                    i = (i + 1) % POOL;
                    black_box(($ark)(black_box(j)))
                })
            });
            group.finish();
        }};
    }
    kernel!(
        "g1_add",
        |i: usize| black_box(p[i]) + black_box(p[(i + 1) % POOL]),
        |i: usize| (black_box(pool[i].0) + black_box(pool[(i + 1) % POOL].0)).into_affine()
    );
    kernel!(
        "g2_add",
        |i: usize| black_box(q[i]) + black_box(q[(i + 1) % POOL]),
        |i: usize| (black_box(pool[i].1) + black_box(pool[(i + 1) % POOL].1)).into_affine()
    );
    kernel!(
        "g1_mul",
        |i: usize| black_box(p[i]).mul_scalar(&black_box(U256::new(pool[i].2))),
        |i: usize| black_box(pool[i].0)
            .mul_bigint(black_box(pool[i].2))
            .into_affine()
    );
    kernel!(
        "g2_raw_mul",
        |i: usize| black_box(raw_ours[i]).mul_scalar(&black_box(U256::new(pool[i].2))),
        |i: usize| black_box(raw[i])
            .mul_bigint(black_box(pool[i].2))
            .into_affine()
    );
    // Raw multiplication must retain the whole integer on full-twist points.
    // Keep scalar preparation and oracle checks outside the timed closures.
    for name in [
        "random192",
        "random128",
        "random96",
        "random64",
        "random16",
        "random32",
        "random48",
        "random80",
        "random112",
        "random144",
        "random160",
        "random176",
        "random224",
        "exact127",
        "exact128",
        "exact129",
        "sparse128",
        "sparse192",
        "sparse256",
        "ones_runs",
        "sparse",
        "high_sparse",
        "near_order",
        "max",
        "zero",
        "one",
    ] {
        let scalars: Vec<_> = pool
            .iter()
            .enumerate()
            .map(|(i, &(_, _, random))| match name {
                "random192" => [random[0], random[1], random[2], 0],
                "random128" => [random[0], random[1], 0, 0],
                "random96" => [random[0], random[1] & 0xffff_ffff, 0, 0],
                "random64" => [random[0], 0, 0, 0],
                "sparse" => {
                    let mut s = [0; 4];
                    let bit = 32 * i + 7;
                    s[bit / 64] = 1 << (bit % 64);
                    s
                }
                "high_sparse" => [1 << i, 0, 0, 1 << 63],
                "near_order" => {
                    let mut s = Fr::MODULUS.0;
                    s[0] += i as u64;
                    s[0] -= 3;
                    s
                }
                "max" => [u64::MAX; 4],
                "zero" => [0; 4],
                "one" => [1, 0, 0, 0],
                _ => crossover_scalar(name, random, i).expect("known scalar class"),
            })
            .collect();
        for i in 0..POOL {
            assert_eq!(
                raw_ours[i]
                    .mul_scalar(&U256::new(scalars[i]))
                    .to_le_bytes()
                    .as_slice(),
                g2_bytes(raw[i].mul_bigint(scalars[i]).into_affine())
            );
        }
        let mut group = c.benchmark_group(format!("group_kernel_g2_raw_mul_{name}"));
        let mut i = 0;
        group.bench_function("solana-bn254", |b| {
            b.iter(|| {
                let j = i;
                i = (i + 1) % POOL;
                black_box(black_box(raw_ours[j]).mul_scalar(&black_box(U256::new(scalars[j]))))
            })
        });
        let mut i = 0;
        group.bench_function("ark-bn254", |b| {
            b.iter(|| {
                let j = i;
                i = (i + 1) % POOL;
                black_box(
                    black_box(raw[j])
                        .mul_bigint(black_box(scalars[j]))
                        .into_affine(),
                )
            })
        });
        group.finish();
    }
    kernel!(
        "g2_subgroup_valid",
        |i: usize| black_box(q[i]).is_in_correct_subgroup(),
        |i: usize| black_box(pool[i].1).is_in_correct_subgroup_assuming_on_curve()
    );
    kernel!(
        "g2_subgroup_invalid",
        |i: usize| black_box(raw_ours[i]).is_in_correct_subgroup(),
        |i: usize| black_box(raw[i]).is_in_correct_subgroup_assuming_on_curve()
    );
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(100)
        .warm_up_time(Duration::from_secs(1)).measurement_time(Duration::from_secs(3))
        .noise_threshold(0.01).confidence_level(0.95).significance_level(0.05);
    targets = bench_bytes, bench_kernels
}
criterion_main!(benches);
