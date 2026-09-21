//! Compare complete, checked byte calls on identical deterministic fixtures.
//! Run through scripts/benchmark-bn254-pairing.py to link Firedancer.

use criterion::{BenchmarkId, Criterion, criterion_group};
use solana_bn254_syscall::{
    Endianness,
    pairing::{VersionedPairing, alt_bn128_versioned_pairing},
};
use std::{hint::black_box, os::raw::c_ulong, time::Duration};

#[path = "common/pairing.rs"]
mod support;
#[path = "../tests/fixtures/pairing.rs"]
mod validation;

#[link(name = "firedancer_bn254", kind = "static")]
unsafe extern "C" {
    fn fd_bn254_pairing_is_one_syscall(
        out: *mut u8,
        input: *const u8,
        input_len: c_ulong,
        big_endian: i32,
    ) -> i32;
}

#[inline(never)]
fn arkworks_call(input: &[u8], order: support::Order) -> Option<[u8; 32]> {
    alt_bn128_versioned_pairing(
        VersionedPairing::V1,
        input,
        match order {
            support::Order::Be => Endianness::BE,
            support::Order::Le => Endianness::LE,
        },
    )
}

#[inline(never)]
fn firedancer_call(input: &[u8], order: support::Order) -> Option<[u8; 32]> {
    let mut output = [0u8; 32];
    // SAFETY: Firedancer writes exactly 32 output bytes and reads input_len
    // input bytes. Both buffers remain live for the call and do not overlap.
    let status = unsafe {
        fd_bn254_pairing_is_one_syscall(
            output.as_mut_ptr(),
            input.as_ptr(),
            input.len().try_into().unwrap(),
            i32::from(matches!(order, support::Order::Be)),
        )
    };
    (status == 0).then_some(output)
}

type ByteCall = fn(&[u8], support::Order) -> Option<[u8; 32]>;
const IMPLEMENTATIONS: [(&str, ByteCall); 3] = [
    ("solana-bn254", support::full_call),
    ("ark-bn254", arkworks_call),
    ("firedancer", firedancer_call),
];

fn bench_pairing(c: &mut Criterion) {
    let validation = validation::fixtures();
    for fixture in &validation {
        for (order, bytes) in [
            (support::Order::Be, &fixture.be),
            (support::Order::Le, &fixture.le),
        ] {
            let expected = fixture.expected.map(|value| support::output(value, order));
            for (name, call) in IMPLEMENTATIONS {
                assert_eq!(
                    call(bytes, order),
                    expected,
                    "{name}: {} ({})",
                    fixture.name,
                    order.name(),
                );
            }
        }
    }
    let cases = support::cases();
    // Check every implementation and fixture before starting any timed work.
    for case in &cases {
        for fixture in &case.fixtures {
            for (name, call) in IMPLEMENTATIONS {
                assert_eq!(
                    call(&fixture.bytes, case.order),
                    Some(fixture.expected),
                    "{name}: {} ({})",
                    case.name,
                    case.order.name(),
                );
            }
        }
    }
    eprintln!(
        "Validated {} contract fixtures in both byte orders and {} timing fixtures against all three implementations; seed={:#x}",
        validation.len(),
        cases.iter().map(|case| case.fixtures.len()).sum::<usize>(),
        support::SEED,
    );

    for case in cases {
        let mut group = c.benchmark_group(format!("pairing_bytes_{}", case.name));
        for (name, call) in IMPLEMENTATIONS {
            let mut index = 0;
            group.bench_function(BenchmarkId::new(name, case.order.name()), |b| {
                b.iter(|| {
                    let input = &case.fixtures[index].bytes;
                    index = (index + 1) % case.fixtures.len();
                    black_box(call(black_box(input), case.order))
                })
            });
        }
        group.finish();
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
    targets = bench_pairing
}
fn main() {
    if let Ok(value) = std::env::var("BN254_PROFILE_ITERATIONS") {
        let iterations: usize = value.parse().expect("profile iteration count");
        assert!(iterations > 0);
        let cases = support::cases();
        let case = cases
            .iter()
            .find(|case| case.name == "seeded_16" && matches!(case.order, support::Order::Le))
            .unwrap();
        for fixture in &case.fixtures {
            assert_eq!(
                support::full_call(&fixture.bytes, case.order),
                Some(fixture.expected)
            );
        }
        let start = std::time::Instant::now();
        for i in 0..iterations {
            let fixture = &case.fixtures[i % case.fixtures.len()];
            black_box(support::full_call(black_box(&fixture.bytes), case.order));
        }
        eprintln!(
            "PROFILE: {iterations} seeded_16/le calls in {:?}; fixture generation excluded from this elapsed time",
            start.elapsed()
        );
        return;
    }
    benches();
    Criterion::default().configure_from_args().final_summary();
}
