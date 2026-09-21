# Pairing comparison through benchctl

`pairing_compare` measures the same complete byte-input pairing-product check
using this crate, Arkworks 0.5 through the workspace's unchanged
`solana-bn254-syscall` V1 wrapper, and Firedancer's
`fd_bn254_pairing_is_one_syscall`. Decoding, canonicality and curve checks, G2
subgroup checks, per-call preparation, Miller loops, final exponentiation and
32-byte Boolean output are included. The Rust adapters also include their
per-call allocations. No decoded points or prepared lines are cached.

This is a checked pairing-product comparison, rather than a measurement of
only a Miller loop or a prevalidated/prepared pairing API.

The existing seeded fixtures supply four inputs for each case. Each timed call
rotates to the next input. The counts are 0, 1, 2, 3, 4, 8, 15, 16, 17, 31, 32,
33, 63, 64 and 65 pairs, plus repeated, cancelling and mixed-identity cases.
All cases run in both byte orders. Every implementation must agree on all
timing fixtures and the existing validation fixtures before any timing starts.
Validation includes
invalid lengths, noncanonical coordinates, off-curve points and non-subgroup
G2 points, including after cancelling or identity pairs.

## Capture the local Firedancer checkout

From the cryptography workspace root:

```sh
python3 scripts/benchmark-bn254-pairing.py snapshot \
  --firedancer /path/to/firedancer
```

This reads the local working-tree bytes of the BN254 C translation units,
their quoted header and assembly dependencies, and the license. It writes
`.benchctl-inputs/firedancer-bn254-native.tar.gz`, recording the Firedancer Git
revision and per-file SHA-256 hashes. The generated archive must remain
nonignored so benchctl includes it in the immutable source snapshot. The
Firedancer checkout is not modified. Existing archives are never overwritten;
use a different `--archive PATH` for a subsequent version and pass that same
path to the remote `run` command.

## Test and measure remotely

Configure benchctl for an x86 Linux server before submitting these commands.
The measurements in the experiment record used Rust 1.98.0 with
`RUSTUP_AUTO_INSTALL=0` and `RUSTFLAGS="-C target-cpu=native"` in the local
workspace profile. Server configuration and generated source archives are local
inputs; they are not part of the library commits.

The comparison requires C compilation and explicit static linking, so its
runner replaces the ordinary `cargo bench ... --bench poseidon_bench` command
used by this checkout's pilot workflow. All compilation and execution still
happen in benchctl's shared remote queue.

```sh
benchctl submit --json --label bn254-pairing-smoke \
  --artifact pairing-comparison-metadata.json -- \
  python3 scripts/benchmark-bn254-pairing.py run --test
```

`--test` runs `cargo test --locked -p solana-bn254 --lib --tests`, then the
comparison in Criterion's smoke mode. It produces no performance measurements.
After waiting for and fetching that exact job, submit measurements:

```sh
benchctl submit --json --label bn254-pairing-full \
  --artifact pairing-comparison-metadata.json -- \
  python3 scripts/benchmark-bn254-pairing.py run
```

For each returned UUID:

```sh
benchctl wait JOB_ID --json
benchctl fetch JOB_ID --json
```

Criterion arguments can follow `run --`, for example
`run -- 'pairing_bytes_seeded_1/'`. Default settings are 100 samples,
3 seconds of warm-up, 5 seconds of measurement and 95% confidence intervals.
The complete run contains 108 measurements and takes at least 14 minutes,
plus compilation and statistical analysis.

## Build configuration and artifacts

- Rust uses the workspace's benchctl profile: 1.98.0 with
  `RUSTFLAGS="-C target-cpu=native"`, the locked dependencies and the bench
  profile. The runner invokes `cargo rustc --locked --profile bench -p
  solana-bn254 --features firedancer-bench --bench pairing_compare` with a
  native library search path, then runs the executable Cargo reports.
- Firedancer uses GCC with `-O3 -march=native -mtune=native`, native x86/ADX
  paths and its normal optimization feature macros. The optional external
  s2n-bignum backend is disabled. All C flags and the exact compiler version
  are recorded. Neither side enables LTO in this runner.
- The opt-in `firedancer-bench` feature gates the comparison target because
  it requires an external C archive. Ordinary library builds and the original
  `pairing_bench` need no Firedancer installation.
- `outputs/pairing-comparison-metadata.json` records source hashes, compiler
  versions, flags, CPU information, CPU affinity and the precise commands.
- `outputs/target/criterion/` contains individual Criterion estimates and
  samples. Timing estimates are in nanoseconds; divide by 1,000 for microseconds.
- Benchctl's `metadata/` records the overall source fingerprint, job UUID,
  command, runtime and logs. Always keep these with the reported results.

The shared queue serializes benchctl jobs; it does not reserve a CPU against
unrelated server processes. These measurements describe the recorded compiler,
CPU, build flags and input contract.
