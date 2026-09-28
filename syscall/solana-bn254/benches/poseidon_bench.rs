use ark_ff::{Field as _, PrimeField};
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use light_poseidon::{PoseidonBytesHasher, PoseidonHasher};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use solana_bn254::backend::{Backend, Fr, MontgomeryBackend, U256};
use solana_bn254::poseidon::{PoseidonConstants, constants::*, hash, sbox};
use std::hint::black_box;

/// A field element represented by both arkworks and this crate.
/// Both representations correspond to the same field value.
fn random_element(rng: &mut StdRng) -> (ark_bn254::Fr, U256) {
    let f = ark_bn254::Fr::from_be_bytes_mod_order(&rng.random::<[u8; 32]>());
    (f, Backend::<Fr>::to_mont(&U256::new(f.into_bigint().0)))
}

// Rotating pools prevent one repeatedly hashed message from deciding a trial.
const POOL: usize = 8;

fn fixture_seed() -> u64 {
    std::env::var("BN254_POSEIDON_BENCH_SEED")
        .map(|value| value.parse().expect("decimal benchmark seed"))
        .unwrap_or(0x706f_7365_6964_6f6e)
}

fn encode(value: U256) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (chunk, limb) in bytes.chunks_exact_mut(8).zip(value.0) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    bytes
}

// Complete little-endian byte adapter: validate, convert, hash and serialize.
// Parameter construction is amortized for both Rust implementations; Firedancer
// uses its own compiled parameter tables. No adapter allocates its output.
fn our_bytes<const T: usize>(
    inputs: &[[u8; 32]],
    params: &PoseidonConstants<T>,
) -> Option<[u8; 32]> {
    if inputs.len() + 1 != T {
        return None;
    }
    let mut state = [U256::zero(); T];
    for (out, input) in state.iter_mut().zip(inputs) {
        let raw = U256::new(core::array::from_fn(|i| {
            u64::from_le_bytes(input[8 * i..8 * i + 8].try_into().unwrap())
        }));
        if !Backend::<Fr>::is_reduced(&raw) {
            return None;
        }
        *out = Backend::<Fr>::to_mont(&raw);
    }
    hash(&state[..T - 1], params).map(|value| encode(Backend::<Fr>::from_mont(&value)))
}

#[cfg(feature = "firedancer-bench")]
#[link(name = "firedancer_bn254", kind = "static")]
unsafe extern "C" {
    fn bn254_bench_poseidon(out: *mut u8, inputs: *const u8, count: std::os::raw::c_ulong) -> i32;
}

#[cfg(feature = "firedancer-bench")]
fn firedancer_bytes(inputs: &[[u8; 32]]) -> Option<[u8; 32]> {
    let mut out = [0; 32];
    // SAFETY: inputs contains count consecutive 32-byte elements; out is a
    // distinct initialized 32-byte buffer. The wrapper owns the C context.
    let ok = unsafe {
        bn254_bench_poseidon(out.as_mut_ptr(), inputs.as_ptr().cast(), inputs.len() as _)
    };
    (ok != 0).then_some(out)
}

fn width<const T: usize>(c: &mut Criterion, params: &PoseidonConstants<T>) {
    let count = T - 1;
    let mut rng = StdRng::seed_from_u64(fixture_seed() ^ T as u64);
    let mut ark_pool = Vec::new();
    let mut our_pool = Vec::new();
    let mut byte_pool = Vec::new();
    for _ in 0..POOL {
        let pairs: Vec<_> = (0..count).map(|_| random_element(&mut rng)).collect();
        ark_pool.push(pairs.iter().map(|(a, _)| *a).collect::<Vec<_>>());
        our_pool.push(pairs.iter().map(|(_, u)| *u).collect::<Vec<_>>());
        byte_pool.push(
            pairs
                .iter()
                .map(|(a, _)| encode(U256::new(a.into_bigint().0)))
                .collect::<Vec<_>>(),
        );
    }
    let byte_refs: Vec<Vec<&[u8]>> = byte_pool
        .iter()
        .map(|row| row.iter().map(|v| v.as_slice()).collect())
        .collect();
    let mut hasher = light_poseidon::Poseidon::<ark_bn254::Fr>::new_circom(count).unwrap();
    for i in 0..POOL {
        let expected = encode(U256::new(
            hasher.hash(&ark_pool[i]).unwrap().into_bigint().0,
        ));
        assert_eq!(
            encode(Backend::<Fr>::from_mont(
                &hash(&our_pool[i], params).unwrap()
            )),
            expected
        );
        assert_eq!(our_bytes(&byte_pool[i], params), Some(expected));
        assert_eq!(hasher.hash_bytes_le(&byte_refs[i]).unwrap(), expected);
        #[cfg(feature = "firedancer-bench")]
        assert_eq!(firedancer_bytes(&byte_pool[i]), Some(expected));
    }
    // Check canonical boundaries and malformed encodings outside timed loops.
    use solana_bn254::backend::Field;
    for bytes in [
        [0; 32],
        encode(U256::one()),
        encode(U256::new((-(ark_bn254::Fr::from(1u64))).into_bigint().0)),
        encode(Fr::MODULUS),
        [255; 32],
    ] {
        let inputs = vec![bytes; count];
        let refs: Vec<&[u8]> = inputs.iter().map(|v| v.as_slice()).collect();
        let expected = hasher.hash_bytes_le(&refs).ok();
        assert_eq!(our_bytes(&inputs, params), expected);
        #[cfg(feature = "firedancer-bench")]
        assert_eq!(firedancer_bytes(&inputs), expected);
    }
    let mut group = c.benchmark_group(format!("poseidon_typed_t{T}"));
    group.bench_function("solana-bn254", |b| {
        let mut i = 0;
        b.iter(|| {
            i = (i + 1) % POOL;
            hash(black_box(&our_pool[i]), black_box(params)).unwrap()
        })
    });
    group.bench_function("light-poseidon", |b| {
        let mut i = 0;
        b.iter(|| {
            i = (i + 1) % POOL;
            hasher.hash(black_box(&ark_pool[i])).unwrap()
        })
    });
    group.finish();
    let mut group = c.benchmark_group(format!("poseidon_bytes_t{T}"));
    group.bench_function("solana-bn254", |b| {
        let mut i = 0;
        b.iter(|| {
            i = (i + 1) % POOL;
            our_bytes(black_box(&byte_pool[i]), black_box(params)).unwrap()
        })
    });
    group.bench_function("light-poseidon", |b| {
        let mut i = 0;
        b.iter(|| {
            i = (i + 1) % POOL;
            hasher.hash_bytes_le(black_box(&byte_refs[i])).unwrap()
        })
    });
    #[cfg(feature = "firedancer-bench")]
    group.bench_function("firedancer", |b| {
        let mut i = 0;
        b.iter(|| {
            i = (i + 1) % POOL;
            firedancer_bytes(black_box(&byte_pool[i])).unwrap()
        })
    });
    group.finish();
}

macro_rules! bench_width {
    ($c:expr, $t:literal, $params:ident) => {
        width::<$t>($c, &$params)
    };
}

fn bench_poseidon(c: &mut Criterion) {
    // Solana `sol_poseidon` syscall supported parameters: state widths
    // t = 2..=13, mapping to 1..=12 inputs. Round counts now come from the
    // parameter sets themselves rather than being repeated here.
    bench_width!(c, 2, BN254_X5_T2);
    bench_width!(c, 3, BN254_X5_T3);
    bench_width!(c, 4, BN254_X5_T4);
    bench_width!(c, 5, BN254_X5_T5);
    bench_width!(c, 6, BN254_X5_T6);
    bench_width!(c, 7, BN254_X5_T7);
    bench_width!(c, 8, BN254_X5_T8);
    bench_width!(c, 9, BN254_X5_T9);
    bench_width!(c, 10, BN254_X5_T10);
    bench_width!(c, 11, BN254_X5_T11);
    bench_width!(c, 12, BN254_X5_T12);
    bench_width!(c, 13, BN254_X5_T13);
}

fn bench_scalar_arithmetic(c: &mut Criterion) {
    type B = Backend<Fr>;
    const CHAIN_LENGTH: u64 = 64;

    let mut rng = StdRng::seed_from_u64(0x6172_6974_685f_7631);
    let (ark_start, start) = random_element(&mut rng);
    let (ark_factor, factor) = random_element(&mut rng);

    // Check all four chains against arkworks before timing anything.
    let mut mul_result = start;
    let mut mul_self_result = start;
    let mut sqr_result = start;
    let mut sbox_result = start;

    let mut ark_mul = ark_start;
    let mut ark_square = ark_start;
    let mut ark_sbox = ark_start;

    for _ in 0..CHAIN_LENGTH {
        mul_result = B::mul(&mul_result, &factor);
        mul_self_result = B::mul(&mul_self_result, &mul_self_result);
        sqr_result = B::sqr(&sqr_result);
        sbox_result = sbox(&sbox_result);

        ark_mul *= ark_factor;
        ark_square = ark_square.square();
        ark_sbox = ark_sbox.pow([5u64]);
    }

    // Construct the expected Montgomery residues using arkworks alone.
    // Exact limb equality also checks that each result is fully reduced.
    let radix = ark_bn254::Fr::from(2u64).pow([256u64]);

    for (name, actual, expected) in [
        ("mul", mul_result, ark_mul),
        ("mul_self", mul_self_result, ark_square),
        ("sqr", sqr_result, ark_square),
        ("sbox", sbox_result, ark_sbox),
    ] {
        assert_eq!(
            actual,
            U256::new((expected * radix).into_bigint().0),
            "{name} chain mismatch"
        );
    }

    let mut group = c.benchmark_group("scalar_arithmetic");
    group.throughput(Throughput::Elements(CHAIN_LENGTH));

    // Every chain begins with the same inputs on every iteration.
    // Each call consumes the preceding call's result.
    // Black boxes at the chain boundaries prevent constant folding
    // and removal of the result without adding barriers between calls.

    group.bench_function("mul_chain_64", |b| {
        b.iter(|| {
            let mut value = black_box(start);
            let multiplier = black_box(factor);

            for _ in 0..CHAIN_LENGTH {
                value = B::mul(&value, &multiplier);
            }

            black_box(value)
        })
    });

    // This matches the operation used by the original sqr implementation.
    group.bench_function("mul_self_chain_64", |b| {
        b.iter(|| {
            let mut value = black_box(start);

            for _ in 0..CHAIN_LENGTH {
                value = B::mul(&value, &value);
            }

            black_box(value)
        })
    });

    group.bench_function("sqr_chain_64", |b| {
        b.iter(|| {
            let mut value = black_box(start);

            for _ in 0..CHAIN_LENGTH {
                value = B::sqr(&value);
            }

            black_box(value)
        })
    });

    // Measure two squares followed by a multiplication in their actual
    // scalar S-box context.
    group.bench_function("sbox_chain_64", |b| {
        b.iter(|| {
            let mut value = black_box(start);

            for _ in 0..CHAIN_LENGTH {
                value = sbox(&value);
            }

            black_box(value)
        })
    });

    group.finish();
}

fn bench_ifma_arithmetic(c: &mut Criterion) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512ifma"))]
    {
        use solana_bn254::backend::avx512::{
            math::sbox_8x,
            pack::{pack_8x, unpack_8x},
        };
        const CHAIN_LENGTH: u64 = 64;
        let mut rng = StdRng::seed_from_u64(fixture_seed() ^ 0x6966_6d61_7335);
        let pairs: [_; 8] = core::array::from_fn(|_| random_element(&mut rng));
        // The enclosing cfg ensures this executable requires AVX-512 IFMA.
        let start = unsafe { pack_8x(&pairs.map(|(_, value)| value)) };
        let mut actual = start;
        let mut expected = pairs.map(|(value, _)| value);
        for _ in 0..CHAIN_LENGTH {
            actual = unsafe { sbox_8x(&actual) };
            expected = expected.map(|value| value.pow([5u64]));
        }
        let radix = ark_bn254::Fr::from(2u64).pow([256u64]);
        assert_eq!(
            unsafe { unpack_8x(&actual) },
            expected.map(|value| U256::new((value * radix).into_bigint().0))
        );
        let mut group = c.benchmark_group("ifma_arithmetic");
        group.throughput(Throughput::Elements(8 * CHAIN_LENGTH));
        group.bench_function("sbox_8x_chain_64", |b| {
            b.iter(|| {
                let mut value = black_box(start);
                for _ in 0..CHAIN_LENGTH {
                    value = unsafe { sbox_8x(&value) };
                }
                black_box(value)
            })
        });
        group.finish();
    }
    #[cfg(not(all(target_arch = "x86_64", target_feature = "avx512ifma")))]
    let _ = c;
}

criterion_group!(
    benches,
    bench_poseidon,
    bench_scalar_arithmetic,
    bench_ifma_arithmetic
);
criterion_main!(benches);
