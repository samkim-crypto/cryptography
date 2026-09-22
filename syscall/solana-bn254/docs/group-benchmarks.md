# G1/G2 comparison through benchctl

`group_compare` compares this crate, Arkworks 0.5 through the unchanged
`solana-bn254-syscall` versioned adapters, and Firedancer on equivalent complete
byte-input operations. G1 addition and multiplication use the established
big-endian zero-padding rules. G2 inputs require exact lengths. Both byte
orders are covered. G2 addition checks the curve only; G2 multiplication also
checks subgroup membership, including when the scalar is zero.

Each complete call includes decoding, canonicality and curve validation,
subgroup checking when required, arithmetic, per-call table preparation,
normalization, and encoding. No points or tables are cached across these
calls. G1 results occupy the first 64 bytes of a shared 128-byte output buffer;
all three adapters use the same output convention without introducing a heap
allocation per call.

The unchanged Ark adapters call `Affine::mul_bigint`, which uses binary
multiplication in Arkworks 0.5. These measurements describe those Solana
adapters, not an explicitly selected Ark GLV implementation. The decoded
G1 multiplication kernel also calls `Affine::mul_bigint`; the raw G2 kernel
uses it to preserve ordinary-integer multiplication on the full twist.

There are 63 input families, each with eight rotating fixtures generated from
default seed `0x6731673262656e31` independently using Arkworks. Addition covers random,
equal, opposite, and identity operands, plus full-twist G2 points. Multiplication
covers random 256/192/128/96/64-bit integers, sparse scalars, values around the group
order, the maximum 256-bit scalar, zero, and one. Both byte orders and three
implementations yield 378 complete-call measurements. The 96-bit and 192-bit
families were added before G07 to measure windowing at different input sizes;
the original fixtures retain the same seed and values. Before G13, bounded
16/32/48/80/112/144/160/176/224-bit classes, exact 127/128/129-bit classes,
sparse 128/192/256-bit classes, high-bit sparse inputs, and long runs of ones
were added. Bounded classes are uniform below 2^n; their highest bit is not
forced. Exact classes force it. All preparation is outside timing.

Thirty-two additional decoded-input kernels compare ours with Arkworks: G1/G2
addition, G1 multiplication, raw full-twist G2 multiplication, and valid/invalid
G2 subgroup checking. Raw G2 covers 256/192/128/96/64-bit inputs, sparse and
high-bit sparse integers, order-adjacent values, maximum, zero and one. The ten
extra raw scalar classes were added before G08; preparation and independent
ordinary-integer oracle checks happen outside timing. G13 adds the same
crossover classes (high-bit sparse was already present). These 64 measurements have separate `group_kernel_`
names. They do not reuse subgroup validation or precomputed multiplication
tables inside the measured operation. They are not presented as Firedancer
syscall comparisons.

Every executable checks all byte timing fixtures, malformed encodings and
lengths, flags, subgroup rejection, and all scalar bit positions before timing.
The kernel fixtures also verify raw full-twist multiplication independently.
Criterion filters reduce timed cases, not these correctness checks.

## Source capture and smoke check

Capture the local Firedancer sources using the shared pairing snapshot helper:

```sh
python3 scripts/benchmark-bn254-pairing.py snapshot \
  --firedancer /Users/samkim/Projects/playground/firedancer \
  --archive .benchctl-inputs/firedancer-bn254-groups.tar.gz

benchctl submit --json --label bn254-groups-smoke \
  --artifact group-comparison-metadata.json -- \
  python3 scripts/benchmark-bn254-pairing.py run \
  --bench group_compare \
  --archive .benchctl-inputs/firedancer-bn254-groups.tar.gz --test
```

The archive is created exclusively; do not overwrite an existing snapshot.
Firedancer is compiled with GCC native ADX and its optional s2n-bignum backend
disabled. The metadata records source hashes, C/Rust compilers, flags, CPU,
and exact commands. The benchmark uses locked workspace dependencies.

## One experiment

Before changing implementation files, create a checkpoint with a new ID:

```sh
python3 scripts/benchmark-bn254-groups.py checkpoint --id G01-divsteps \
  syscall/solana-bn254/src/backend/portable/inversion.rs
```

After applying that candidate, submit the frozen comparison:

```sh
benchctl submit --json --label bn254-G01-divsteps --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G01-divsteps \
  --comparison --pairing
```

The runner builds baseline and candidate from the same snapshot, compiles
Firedancer, checks the comparison fixtures, and runs the candidate's crate
tests. Separate target directories prevent flags from mixing between builds:

| Configuration | Rust flags |
| --- | --- |
| `native` | `-C target-cpu=native` |
| `native_scalar` | `-C target-cpu=native -C target-feature=-avx512ifma` |
| `generic` | `-C target-cpu=x86-64` |

The benchctl profile pins Rust 1.98.0. Measurement runs use CPU 16, 100 samples,
one second of warm-up, and two seconds of collection per case by default.
Baseline/candidate/candidate/baseline rounds time our complete little-endian
calls and decoded kernels. The `--comparison` flag additionally measures all
three baseline implementations in both byte orders. For a final retained-source
comparison, use `--comparison-variant candidate`; `--comparison-filter` narrows
that separate comparison without changing the ABBA `--filter`. `--pairing` adds shared
field regression checks for one, four, and sixteen pairs and validates the
full pairing fixture suite. Use explicit filters/configurations for later
targeted trials, and record every override.

Use `--seed 0x6731673262656e32` for a separate point/scalar pool. The runner
sets `BN254_GROUP_BENCH_SEED` and records the override in metadata; it affects
fixture generation only. The default seed and all original inputs remain
unchanged. Pairing uses its own existing fixture seed.

Wait for and fetch the exact UUID returned by submission. Results live under
`outputs/group-experiment-results`, including candidate patch, per-file
baseline/candidate hashes, configuration metadata, emitted implementation
assembly, raw Criterion samples, and ABBA summaries. Configuration names and
their exact flags must accompany any reported timing.

For a discarded candidate, restore only checkpointed files whose current bytes
still match the measured candidate:

```sh
python3 scripts/benchmark-bn254-groups.py restore --id G01-divsteps \
  --results /path/to/fetched/outputs/group-experiment-results
```

The guard aborts rather than overwriting intervening edits. Every build, test,
benchmark, and result transfer goes through benchctl's shared queue, following
[BENCHMARKING.md](../BENCHMARKING.md).
