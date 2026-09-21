//! Complete byte-call timings, including decoding and per-call preparation.

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use std::{hint::black_box, time::Duration};

#[path = "common/pairing.rs"]
mod support;

fn bench_pairing(c: &mut Criterion) {
    for case in support::cases() {
        for fixture in &case.fixtures {
            assert_eq!(
                support::full_call(&fixture.bytes, case.order),
                Some(fixture.expected)
            );
        }
        let mut group = c.benchmark_group(format!("pairing_bytes_{}", case.name));
        let mut index = 0;
        group.bench_function(BenchmarkId::new("solana-bn254", case.order.name()), |b| {
            b.iter(|| {
                let input = &case.fixtures[index].bytes;
                index = (index + 1) % case.fixtures.len();
                black_box(support::full_call(black_box(input), case.order))
            })
        });
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
criterion_main!(benches);
