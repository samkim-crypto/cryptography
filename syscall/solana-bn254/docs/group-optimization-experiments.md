# G1/G2 optimization experiments

Branch: `bn254-g1-opt`, created from `bn254-gt` at `c9cf3a7`.
Plan: [G01-G13](g1-g2-poseidon-optimization-review.md).
Workflow and interpretation: [group-benchmarks.md](group-benchmarks.md).
Poseidon optimization cycles are deferred.

Planned G1/G2 sequence completed on 2026-09-23. Retained: G01, G05B, G06A, G06B and
G07B (G1 width 4) and G07E (G2 width 4). G02–G04, G05A and the G07A/C/D
selectors are discarded, as is G07F. G07 retained width 4 for both groups;
G13C now selects width 5 for long dense G1 scalars. G08A raw width 3 is also
retained; G08B/C default widths 4/5 were discarded.
G09A was discarded; G09B's common-denominator subgroup chain is retained.
G10A was discarded; G10B's bounded G2 constant multiples are retained.
G10C/D fused-subtraction trials were discarded. G10 is complete.
G11's four-way subgroup multiplication is retained with G11B's two joint
signed schedules, superseding G11A's subset table.
G12's IFMA scheduling within G2 doubling and G12B's private lazy sums are retained.
G13A's G1 trivial/short-scalar paths are retained. Its job succeeded and was
waited/fetched. G13B's combined raw dispatch/outline trial was discarded;
G13B2's isolated raw trivial-input returns and G13C's conditional long-scalar
G1 windows are retained. G13D's >128-bit dense GS cutoff and G13E's
conditional raw-G2 widths are retained. G13E job
`22c00201a18d4acca670530a598be886` succeeded, was waited/fetched, and its
candidate hashes matched at the decision. G13F was discarded and guarded-restored
after repeatable high-bit sparse regressions. Its job was waited/fetched.
G13G's G1 setup estimate of 40 is retained; its job succeeded/waited/fetched.
G13H and G13I were discarded and guarded-restored; their jobs succeeded,
were waited/fetched, and G2 retains setup weight 100 and doubling weight 17.
All planned optimization trials are settled; no production candidate is provisional.
Poseidon remains deferred.

Final validation is complete. `G-final.json` captures the original `c9cf3a7`
production files, verified against the first per-file checkpoints, without resetting
the local working tree. The two runs use seeds `0x6731673262656e31` and
`0x6731673262656e32`, 41 group and three pairing ABBA cases per configuration,
plus fresh timings of the four primary byte operations across all three libraries.
The compiler, flags, CPU, sampling and retained source are held fixed.

Both runs (`9d90278f4a66484294c32bd909c60a52` and
`bea7e864d82f456089a46e1eea77457a`) succeeded and were waited/fetched.
Each has 123 group and nine pairing rows with separated favorable intervals
versus the original source: 264 favorable rows in total, with no overlaps or
regressions. Production files, harness, lockfile, toolchains and measurement
settings match across the two group input seeds.
See the [consolidated results](group-optimization-results.md) for fresh
Ark/Firedancer comparisons and cumulative gains; full evidence is also below.
No task jobs remain running. No planned G1/G2 trial remains; Poseidon is deferred.

## Baseline validation

Job `779d268633bb41aab03f4c57479fd5e9` passed all 228 native crate tests and
the new G1/G2 comparison smoke check, including 464 byte fixtures plus length
and scalar-bit boundary checks across ours, Arkworks, and Firedancer. The
separately labeled raw-G2 kernels also passed their independent oracle checks.
This was a correctness run, not a performance measurement.

- Source fingerprint: `cffc2a23cd7bc04a54c1d3ae6553b592577c10bcc09d3f4422ba1d542d6eee16`.
- Rust 1.98.0; `RUSTFLAGS=-C target-cpu=native`.
- Firedancer: `20c3fa1ff2dab737ec075c3e3e302ba778fd98fe`, clean captured source;
  archive SHA-256 `b8e1cd1a9fef961a9889bb29e5818ca53fcdd13e36dae9b2a6e85dc8c637fa2a`.
- Command: `benchctl submit --json --label bn254-groups-baseline-smoke --artifact group-comparison-metadata.json -- python3 scripts/benchmark-bn254-pairing.py run --bench group_compare --archive .benchctl-inputs/firedancer-bn254-groups.tar.gz --test`.
- Fetched result: `/Users/samkim/.local/state/benchctl/results/779d268633bb41aab03f4c57479fd5e9`.

Initial SSH authentication failed; the user unlocked the agent and the same
saved UUID was resumed successfully.

## G01: skip consecutive even divsteps

Decision: **keep**. The complete addition calls improve substantially in all
three configurations, and G1 multiplication also improves consistently.

The existing 62-step inversion batch now groups consecutive even-g transitions
using trailing-zero counts. The signed matrix and full-width update invariants
are unchanged. Integer-oracle coverage now includes zero and every 256-bit
power of two, alongside the existing random inputs, to exercise long runs and
all-zero low words. The source links libsecp256k1's explanation of this method.

The first runner job, `e963e75a89fd43a89392127aaa50591f`, failed before building
because an isolated target directory's parent did not yet exist. Its metadata
and candidate patch were fetched to
`/Users/samkim/.local/state/benchctl/results/e963e75a89fd43a89392127aaa50591f`.
The directory creation was fixed and a new snapshot submitted; this failure
provides no arithmetic or timing result.

Measurement job: `657f18de87d44381b9952351bb480bc6`.
Source fingerprint:
`b3f5817cba34455f654ee20c6b1bec7bdaca8c6089d8b48b66cb06c16258bee3`.
Command:

```sh
benchctl submit --json --label bn254-G01-divsteps-r2 --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G01-divsteps \
  --comparison --pairing
```

This job requests native IFMA, native scalar, and generic-x86 builds with the
same Rust 1.98.0 compiler, CPU 16, ABBA measurements, complete comparator
baselines, and pairing regression checks. Exact flags are in the workflow and
job metadata.

The job succeeded, and its results were fetched to
`/Users/samkim/.local/state/benchctl/results/657f18de87d44381b9952351bb480bc6`.
The raw Criterion data, assembly, file hashes and all 102 ABBA result rows are
under `outputs/group-experiment-results`. The default `target/criterion`
artifact is absent because this runner gives each round its own directory.
All candidate crate tests and group/pairing comparator checks passed in all
three configurations.

Complete little-endian calls, geometric mean of each variant's two rounds:

| Configuration | Operation | Before (µs) | After (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | G1 random addition | 1.347 | 1.061 | 21.24% |
| Native IFMA | G2 random addition | 1.871 | 1.574 | 15.83% |
| Native IFMA | G1 random 256-bit multiplication | 36.853 | 36.306 | 1.48% |
| Native IFMA | G2 checked random 256-bit multiplication | 127.586 | 127.175 | 0.32% |
| Native scalar | G1 random addition | 1.347 | 1.065 | 20.96% |
| Native scalar | G2 random addition | 1.872 | 1.588 | 15.18% |
| Native scalar | G1 random 256-bit multiplication | 36.852 | 36.303 | 1.49% |
| Native scalar | G2 checked random 256-bit multiplication | 127.385 | 127.162 | 0.17% |
| Generic x86 | G1 random addition | 1.472 | 1.076 | 26.95% |
| Generic x86 | G2 random addition | 1.975 | 1.573 | 20.34% |
| Generic x86 | G1 random 256-bit multiplication | 40.456 | 39.675 | 1.93% |
| Generic x86 | G2 checked random 256-bit multiplication | 137.128 | 137.229 | -0.07% |

For addition and G1 multiplication above, both candidate confidence intervals
are below both baseline intervals. The small G2 multiplication changes do not
meet that criterion; treat those as approximately unchanged. Other dense G1
scalar classes improved 1.1–1.9%, and near-order G1 calls improved 13–18%.
Standalone G2 subgroup checks improved about 0.5–0.7%.

Tradeoffs: some native identity/zero/one controls moved by about 7–11 ns
(up to 2.9%); a few of these shifts have disjoint intervals. Pairing shifts
ranged from -0.20% to +0.02%, also with disjoint intervals in a few cases.
These are small compared with the 280–400 ns saved per ordinary affine
addition; retain the change while recording those costs, without claiming
that every case improved. The planned G13 small-scalar paths remain separate.

## G02A: wide-product Fq2 squaring

Decision: **discard**. Native builds regress throughout the G2 cases; generic
x86 gains on long multiplications do not offset slower addition, subgroup
checks, and short/sparse multiplications. G01 remains the retained baseline.

Two wide products form `(a0+a1)*(a0-a1 mod q)` and `(2*a0)*a1`, followed by
two REDCs. Both numerators are below `2q² < qR`; public coefficients remain
canonical. Existing raw-Montgomery boundary and seeded extension-field tests
exercise the new path, alongside the private product/reduction integer oracles.
The candidate made the former FqSum helper test-only.

- Job: `e684b1c9cbfc4e2aa65a1df1862f2d6a`.
- Source fingerprint: `8d013e968d83a6b0773333865166bb7de8b6cf5fb71fe027cb2a3a436e1473a6`.
- Rust 1.98.0; all three standard configurations, CPU 16, 100 samples,
  one-second warm-up and two-second collection, ABBA.
- Flags: native IFMA `-C target-cpu=native`; native scalar
  `-C target-cpu=native -C target-feature=-avx512ifma`; generic x86
  `-C target-cpu=x86-64`.
- Filter override: only G2 complete calls and decoded G2 kernels are timed,
  plus the three pairing regressions. All comparison correctness fixtures
  still execute; the full three-library reference comparison is not repeated.

```sh
benchctl submit --json --label bn254-G02-wide-square --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G02-wide-square \
  --pairing \
  --filter 'group_bytes_g2_.*/solana-bn254/le$|group_kernel_g2_.*/solana-bn254$'
```

The job succeeded and was waited for and fetched to
`/Users/samkim/.local/state/benchctl/results/e684b1c9cbfc4e2aa65a1df1862f2d6a`.
All candidate crate tests and the group/pairing comparator checks passed in
all three configurations. The 60 measured result rows, raw Criterion data,
assembly, metadata and discarded candidate patch are under
`outputs/group-experiment-results`.

Geometric mean of each variant's two rounds; positive percentages mean less
time. Byte-call rows use little-endian inputs.

| Configuration | Operation | Before (µs) | Candidate (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | G2 random addition | 1.572 | 1.604 | -2.01% |
| Native IFMA | G2 checked random 256-bit multiplication | 126.921 | 133.915 | -5.51% |
| Native IFMA | G2 valid subgroup check | 37.292 | 40.345 | -8.19% |
| Native IFMA | Pairing, 16 pairs | 3396.287 | 3458.889 | -1.84% |
| Native scalar | G2 random addition | 1.573 | 1.605 | -2.01% |
| Native scalar | G2 checked random 256-bit multiplication | 127.167 | 134.203 | -5.53% |
| Native scalar | G2 valid subgroup check | 37.289 | 40.325 | -8.14% |
| Native scalar | Pairing, 16 pairs | 3633.491 | 3695.479 | -1.71% |
| Generic x86 | G2 random addition | 1.573 | 1.588 | -0.90% |
| Generic x86 | G2 checked random 256-bit multiplication | 137.288 | 135.895 | +1.01% |
| Generic x86 | G2 valid subgroup check | 39.936 | 40.846 | -2.28% |
| Generic x86 | G2 raw multiplication kernel | 200.170 | 189.561 | +5.30% |
| Generic x86 | Pairing, 16 pairs | 3796.623 | 3777.824 | +0.50% |

Both candidate confidence intervals are entirely on the reported side of
both baseline intervals for every row above. Generic x86 checked short and
sparse scalar cases regress about 2.1–2.3%; the native configurations regress
about 7.8–9.3% on those cases. The generic raw-kernel gain is therefore not a
sufficient reason to retain this square implementation globally.

Restored all three candidate files from the G02 checkpoint after verifying
their hashes against the measured source. G01's inversion change is preserved.
No follow-on candidate was applied or submitted before pausing.

## G02B: ADX multiplication for the bounded Fq2 square product

Decision: **discard as redundant**. G01 remains the retained baseline.

The candidate made `FqSum::product_reduced` use the Linux x86-64 ADX/BMI2 multiplier
when those target features are enabled, preserving CIOS on other builds.
The multiplier already accepts inputs below `2q`; its documented bounds apply
without changes to assembly or the public canonical-residue contract. Existing
boundary and seeded integer-oracle tests cover the private unreduced operand.

Correction to the original proposal: `PortableBackend::mul_cios` already
dispatches Fq to ADX under exactly those features. The candidate merely
duplicates that dispatch; it does not introduce a new arithmetic kernel.
The fetched native disassembly has an identical `Fq2::square` function block
in baseline and candidate, confirming that this trial did not improve that path.

- Job: `26c3b8c702174ff7a37b5d165ae48c4a`.
- Source fingerprint: `b0c6f95bf3f7c1218586ff45c01aa03728eb52ee2cf20d630466bc7947b97a36`.
- Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
  `-C target-cpu=native -C target-feature=-avx512ifma`, and generic x86
  `-C target-cpu=x86-64`. CPU 16; 100 samples; one-second warm-up and
  two-second collection; ABBA.
- Timing filter: G2 complete calls and decoded G2 kernels plus the three
  pairing regressions. All comparator correctness fixtures still run.

```sh
benchctl submit --json --label bn254-G02-adx-square --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G02-adx-square \
  --pairing \
  --filter 'group_bytes_g2_.*/solana-bn254/le$|group_kernel_g2_.*/solana-bn254$'
```

Native IFMA completed all four ABBA rounds. Native and native-scalar crate
tests and comparator smoke checks passed. After discovering the redundant
dispatch, the remaining measurements were cancelled during the native-scalar
baseline round; generic was not run. `wait` returned 130 (cancelled), not a
successful full three-configuration run. Results were fetched to
`/Users/samkim/.local/state/benchctl/results/26c3b8c702174ff7a37b5d165ae48c4a`.

Completed native results, geometric means of the two rounds per variant:

| Operation | Before (µs) | Candidate (µs) | Improvement |
| --- | ---: | ---: | ---: |
| G2 random addition | 1.574 | 1.571 | +0.19% |
| G2 checked random 256-bit multiplication | 127.101 | 128.254 | -0.91% |
| G2 valid subgroup check | 37.300 | 37.309 | -0.02% |
| Pairing, one pair | 467.608 | 468.378 | -0.16% |
| Pairing, 16 pairs | 3399.965 | 3398.650 | +0.04% |

None of these rows separates both candidate intervals from both baseline
intervals. The sparse-scalar row's +0.14% shift does separate them, but does
not establish a useful arithmetic optimization when the kernel is already
selected. Do not interpret binary/layout differences as new ADX coverage.
Restored the sole checkpointed source file with hash guards; the partial
measurements, metadata, assembly and candidate patch remain in the artifact.

## G03A: G1 doubling with 2M+5S

Decision: **discard**. G1 multiplication regresses in all three configurations;
retain the existing 3M+4S formula and G01's inversion improvement.

Replace `D=4XB` in the Jacobian doubling formula with
`D=2*((X+B)^2-X^2-B^2)`, exchanging one multiplication for one square and
the associated additions. Identity/Y=0 guards and canonical intermediates
remain intact. The source links EFD's `dbl-2009-l`. Existing scaled-Jacobian
oracle tests and scalar boundary/seeded tests cover this formula.

- Job: `ce34e622f65745fdab3878e38c100559`.
- Source fingerprint: `bc2be51a359393df32d54028a5e06e60dd779b586299e16d1af3cf97d92fbcb4`.
- Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
  `-C target-cpu=native -C target-feature=-avx512ifma`, and generic x86
  `-C target-cpu=x86-64`. CPU 16; 100 samples; one-second warm-up and
  two-second collection; ABBA.
- Timing filter: G1 complete calls and decoded G1 kernels. All group
  comparator correctness fixtures still run. No pairing timing: this private
  G1 projective method is not used by the pairing operation.

```sh
benchctl submit --json --label bn254-G03-g1-double --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G03-g1-double \
  --filter 'group_bytes_g1_.*/solana-bn254/le$|group_kernel_g1_.*/solana-bn254$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/ce34e622f65745fdab3878e38c100559`.
All crate tests and group comparator correctness checks passed in all three
configurations. The artifact contains 42 ABBA result rows plus the discarded
patch, metadata, raw Criterion samples and assembly.

Complete little-endian calls, geometric means of each variant's two rounds:

| Configuration | Scalar class | Before (µs) | Candidate (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | Random 256-bit | 36.336 | 37.884 | -4.26% |
| Native IFMA | Random 64-bit | 17.484 | 18.258 | -4.42% |
| Native IFMA | Sparse | 20.452 | 21.938 | -7.26% |
| Native scalar | Random 256-bit | 36.327 | 37.941 | -4.44% |
| Native scalar | Random 64-bit | 17.481 | 18.297 | -4.67% |
| Native scalar | Sparse | 20.445 | 22.008 | -7.64% |
| Generic x86 | Random 256-bit | 39.686 | 40.869 | -2.98% |
| Generic x86 | Random 64-bit | 19.041 | 19.652 | -3.21% |
| Generic x86 | Sparse | 22.037 | 23.222 | -5.38% |

Both candidate intervals are above both baseline intervals in every row above.
Random-128-bit and maximum scalars also regress consistently. Generic affine
addition shows small favorable shifts despite not calling the changed private
doubling method; these do not offset the direct multiplication regressions.
Restored `g1.rs` from its hash-verified checkpoint. No G1 formula change is kept.

## G03B: G2 doubling with 3M+4S

Decision: **discard**. Both native builds regress across the G2 cases; generic
x86's gains are mixed and come with slower subgroup checking. Retain 2M+5S.

Replace `D=2*((X+B)^2-X^2-B^2)` with `D=4XB`, exchanging one Fq2 square and
associated additions for a multiplication. The source links EFD's
`dbl-2009-l`. Existing scaled full-twist doubling oracles, subgroup tests and
scalar boundary/seeded tests cover the formula; dispatch weights are unchanged.

- Job: `1f005aeceebd4c29a12f3c6cf1242e8b`.
- Source fingerprint: `d0a44cb5e8333ef990edb4c66ee8a2483f22d95864ad9051e0d2b7a46514650b`.
- Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
  `-C target-cpu=native -C target-feature=-avx512ifma`, and generic x86
  `-C target-cpu=x86-64`. CPU 16; 100 samples; one-second warm-up and
  two-second collection; ABBA.
- Timing filter: G2 checked multiplication, raw multiplication and subgroup
  kernels, plus pairing for 1/4/16 pairs. Unaffected affine-addition timings
  are omitted; every group/pairing comparator correctness fixture still runs.

```sh
benchctl submit --json --label bn254-G03-g2-double --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G03-g2-double \
  --pairing \
  --filter 'group_bytes_g2_mul_.*/solana-bn254/le$|group_kernel_g2_(raw_mul|subgroup_valid|subgroup_invalid)/solana-bn254$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/1f005aeceebd4c29a12f3c6cf1242e8b`.
All crate tests and group/pairing comparator checks passed in all three
configurations. The artifact contains all 42 ABBA result rows, the discarded
patch, metadata, raw Criterion samples and assembly.

Geometric means of each variant's two rounds; byte calls are little-endian:

| Configuration | Operation | Before (µs) | Candidate (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | G2 checked random 256-bit multiplication | 127.839 | 129.288 | -1.13% |
| Native IFMA | G2 valid subgroup check | 37.303 | 38.009 | -1.89% |
| Native IFMA | Pairing, 16 pairs | 3397.772 | 3416.553 | -0.55% |
| Native scalar | G2 checked random 256-bit multiplication | 128.023 | 129.349 | -1.04% |
| Native scalar | G2 valid subgroup check | 37.296 | 38.026 | -1.96% |
| Native scalar | Pairing, 16 pairs | 3633.027 | 3649.623 | -0.46% |
| Generic x86 | G2 checked random 256-bit multiplication | 137.629 | 137.149 | +0.35% |
| Generic x86 | G2 valid subgroup check | 39.777 | 40.245 | -1.18% |
| Generic x86 | G2 raw multiplication kernel | 199.543 | 196.206 | +1.67% |
| Generic x86 | Pairing, 16 pairs | 3791.742 | 3784.184 | +0.20% |

Both candidate intervals are on the reported side of both baseline intervals
for these rows except generic checked random-256 multiplication, which
overlaps. Native G2 scalar classes regress about 1.0–2.8%. Generic maximum
scalars improve 1.89%, but random-128, short/sparse scalars and subgroup checks
regress; a generic-only switch therefore is not retained. Native-scalar
single-pair verification improves 0.56%, while its 16-pair case regresses.
Restored `g2.rs` with the checkpoint hash guard. G1 retains 3M+4S and G2
retains 2M+5S; operation counts alone did not predict the faster implementation.

## G04A: G1 mixed addition with 7M+4S

Decision: **discard**. Dense G1 multiplication regresses in every configuration;
retain the original 8M+3S mixed-addition formula.

Replace the unscaled 8M+3S mixed Jacobian addition with EFD `madd-2007-bl`,
which uses 7M+4S and additional linear combinations. Identity, doubling and
opposite-point guards are unchanged. Existing scaled-coordinate oracles and
the complete scalar boundary/seeded comparisons exercise the changed path.

- Job: `19bac21f798f4f138c96a228af0ec48f`.
- Source fingerprint: `3588bec76d01e4d8b0d3ddd50f789c65bc468091663b2c2f848cb8a3f5928925`.
- Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
  `-C target-cpu=native -C target-feature=-avx512ifma`, and generic x86
  `-C target-cpu=x86-64`. CPU 16; 100 samples; one-second warm-up and
  two-second collection; ABBA.
- Timing filter: G1 complete scalar multiplication and its decoded kernel.
  Affine addition and pairing do not call this private mixed-addition method,
  so they are not timed. All group comparator correctness fixtures still run.

```sh
benchctl submit --json --label bn254-G04-g1-mixed --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G04-g1-mixed \
  --filter 'group_bytes_g1_mul_.*/solana-bn254/le$|group_kernel_g1_mul/solana-bn254$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/19bac21f798f4f138c96a228af0ec48f`.
All crate tests and group comparator checks passed across the three builds.
The artifact contains 27 ABBA rows, metadata, raw samples, assembly and the
discarded patch.

Complete little-endian calls, geometric means of each variant's two rounds:

| Configuration | Scalar class | Before (µs) | Candidate (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | Random 256-bit | 36.334 | 38.061 | -4.75% |
| Native IFMA | Random 128-bit | 33.790 | 35.237 | -4.28% |
| Native IFMA | Random 64-bit | 17.488 | 18.287 | -4.57% |
| Native scalar | Random 256-bit | 36.318 | 37.963 | -4.53% |
| Native scalar | Random 128-bit | 33.775 | 35.139 | -4.04% |
| Native scalar | Random 64-bit | 17.472 | 18.237 | -4.38% |
| Generic x86 | Random 256-bit | 39.666 | 40.672 | -2.54% |
| Generic x86 | Random 128-bit | 36.837 | 37.670 | -2.26% |
| Generic x86 | Random 64-bit | 19.040 | 19.504 | -2.44% |

Both candidate intervals are above both baseline intervals for every row above;
maximum scalars and the decoded multiplication kernel also regress. Small
favorable shifts on native zero/one controls and generic sparse inputs do not
offset this, and are not evidence of faster mixed addition. Restored `g1.rs`
with the checkpoint hash guard, preserving G01.

## G04B: G2 mixed addition with 7M+4S

Decision: **discard**. G2 multiplication and subgroup checks regress in every
configuration. Restored the original 8M+3S formula with the checkpoint hash guard;
G01 remains the retained baseline.

Test EFD `madd-2007-bl` in the G2 mixed Jacobian addition, preserving the
existing identity, equal-point and opposite-point guards. Full projective
addition, the doubling formula and scalar strategy selection are unchanged.
The existing scaled-coordinate and full-twist scalar/subgroup oracles cover it.

- Job: `04033570b9b84359a3e82449bfcccc8a`.
- Source fingerprint: `825762f83d4f5af0fbd058c389fdb0c9bee3cdc175181192b41fbea1f046ead7`.
- Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
  `-C target-cpu=native -C target-feature=-avx512ifma`, and generic x86
  `-C target-cpu=x86-64`. CPU 16; 100 samples; one-second warm-up and
  two-second collection; ABBA.
- Timing filter: G2 checked multiplication, raw multiplication and subgroup
  kernels, plus pairing for 1/4/16 pairs. All group/pairing comparator
  correctness fixtures still run.

```sh
benchctl submit --json --label bn254-G04-g2-mixed --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G04-g2-mixed \
  --pairing \
  --filter 'group_bytes_g2_mul_.*/solana-bn254/le$|group_kernel_g2_(raw_mul|subgroup_valid|subgroup_invalid)/solana-bn254$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/04033570b9b84359a3e82449bfcccc8a`.
All crate tests and group/pairing comparator checks passed in all three builds.
The artifact contains all 42 ABBA result rows, the discarded patch, metadata,
raw Criterion samples and assembly.

Complete little-endian calls, geometric means of each variant's two rounds:

| Configuration | Operation | Before (µs) | Candidate (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | G2 checked random 256-bit multiplication | 128.107 | 137.192 | -7.09% |
| Native IFMA | G2 valid subgroup check | 37.307 | 37.614 | -0.82% |
| Native IFMA | Pairing, 16 pairs | 3397.405 | 3419.572 | -0.65% |
| Native scalar | G2 checked random 256-bit multiplication | 127.813 | 138.933 | -8.70% |
| Native scalar | G2 valid subgroup check | 37.296 | 37.623 | -0.88% |
| Native scalar | Pairing, 16 pairs | 3634.743 | 3654.632 | -0.55% |
| Generic x86 | G2 checked random 256-bit multiplication | 138.305 | 148.305 | -7.23% |
| Generic x86 | G2 valid subgroup check | 39.935 | 40.407 | -1.18% |
| Generic x86 | Pairing, 16 pairs | 3797.555 | 3819.314 | -0.57% |

Both candidate intervals are above both baseline intervals for every row above.
Raw G2 multiplication regresses 6.53–8.09%; random-128 and random-64 inputs also
regress in all three builds. Native single-pair checks improve 0.21–0.41%, but
the larger pairing batches regress, so those gains do not justify keeping it.

## G05A: fixed-constant products in GLV decomposition

Decision: **discard the unconditional substitution**. Native G1 gains are
indistinguishable from noise, and native-scalar G2 regresses. Generic x86 gains
are consistent enough to warrant a separate generic-only follow-up.

Replace the six unrestricted integer products in GLV decomposition with exact
Comba products specialized to the constant widths and proven quotient widths.
Each constant has limb sum below 2^64, so every column fits a `u128` including
its incoming carry. Compile-time assertions enforce that bound. All low-column
carries are retained, including for the two high-half reciprocal products.
The implementation cites Firedancer's fixed-width GLV helpers. A BigUint oracle
checks each specialization at its full input width, alongside the existing
decomposition and reciprocal-boundary tests.

- Job: `f248aa31e305420ea1c1ab851e786d13`.
- Source fingerprint: `e55041453a3081b6c39dc08f8817b3b6cd6ff07299c9b9a3e9d7654ef85166de`.
- Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
  `-C target-cpu=native -C target-feature=-avx512ifma`, and generic x86
  `-C target-cpu=x86-64`. CPU 16; 100 samples; one-second warm-up and
  two-second collection; ABBA.
- Timing filter: complete G1/G2 scalar multiplication and the decoded G1
  multiplication kernel. Pairing and raw G2 multiplication do not call this
  decomposition; all group comparator correctness fixtures still run.

```sh
benchctl submit --json --label bn254-G05-fixed-products --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G05-fixed-products \
  --filter 'group_bytes_g[12]_mul_.*/solana-bn254/le$|group_kernel_g1_mul/solana-bn254$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/f248aa31e305420ea1c1ab851e786d13`.
All crate tests and complete group comparator checks passed in all three builds;
51 ABBA rows, the candidate patch, metadata, assembly and raw samples are saved.

Complete little-endian calls, geometric means of each variant's two rounds:

| Configuration | Operation | Before (µs) | Candidate (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | G1 random 256-bit multiplication | 36.300 | 36.293 | +0.02% |
| Native IFMA | G2 checked random 256-bit multiplication | 127.485 | 127.237 | +0.19% |
| Native scalar | G1 random 256-bit multiplication | 36.306 | 36.304 | +0.00% |
| Native scalar | G2 checked random 256-bit multiplication | 126.841 | 127.084 | -0.19% |
| Native scalar | G2 checked random 128-bit multiplication | 118.711 | 119.157 | -0.38% |
| Generic x86 | G1 random 256-bit multiplication | 39.666 | 39.596 | +0.18% |
| Generic x86 | G2 checked random 256-bit multiplication | 137.830 | 136.443 | +1.01% |
| Generic x86 | G2 checked random 128-bit multiplication | 128.739 | 127.548 | +0.92% |

Native G1 rows and native-IFMA G2 random-256 overlap between runs. Both
candidate intervals are above both baseline intervals for the two reported
native-scalar G2 regressions. Both generic candidate intervals are below both
baseline intervals for each reported gain. Generic G2 classes improve
0.81–1.01%, including controls that bypass GLV, so this is a complete-binary
result rather than evidence that all gains come from faster decomposition.
Restored `glv.rs` with the checkpoint hash guard, preserving G01. G05B will
test retaining the original products in native builds and using the specialized
products only on generic x86.

## G05B: fixed-constant products only without x86 BMI2

Decision: **keep** the generic-x86 specialization. The two native benchmark
binaries are each byte-for-byte identical to their corresponding baseline;
generic x86 repeats modest gains without a demonstrated regression.

Use G05A's bounded Comba products only for `x86_64` builds without the `bmi2`
target feature, matching the generic-x86 configuration. Native BMI2 and other
architectures retain the original unrestricted products. Tests still exercise
both exact-product helpers. This isolates the generic gains observed in G05A
without deliberately accepting its native-scalar regressions.

- Job: `5ba268a97f84462198bd9493fbacee73`.
- Source fingerprint: `a3fcea32d91b0672fc18fcd07ad48c2bd030cccdad7c360e51005e2d584b5c0a`.
- Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
  `-C target-cpu=native -C target-feature=-avx512ifma`, and generic x86
  `-C target-cpu=x86-64`. CPU 16; 100 samples; one-second warm-up and
  two-second collection; ABBA.

```sh
benchctl submit --json --label bn254-G05-generic-products --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G05-generic-products \
  --filter 'group_bytes_g[12]_mul_.*/solana-bn254/le$|group_kernel_g1_mul/solana-bn254$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/5ba268a97f84462198bd9493fbacee73`.
All crate tests and group comparator checks passed in all three builds. The
artifact contains 51 ABBA rows, metadata, raw samples, assembly and the patch.

The native IFMA baseline/candidate executable SHA-256 is identically
`408c5f206c44843c811be89b97d309341b35ec27c9ebaf704b8c88184cc00bca`;
native scalar is identically
`d3e366c784155b73863173387000d4b5a8e6c7862acc3496331945a57fa47169`.
Their observed timing shifts therefore are run variation, not a code gain or
regression. This also illustrates why Criterion intervals alone do not capture
all between-run variation.

Generic-x86 complete little-endian calls, geometric means of two rounds:

| Operation | Before (µs) | Candidate (µs) | Improvement | Both candidate intervals below both baselines? |
| --- | ---: | ---: | ---: | --- |
| G1 random 256-bit multiplication | 39.669 | 39.642 | +0.07% | Yes |
| G1 random 128-bit multiplication | 36.833 | 36.811 | +0.06% | Yes |
| G1 near-order multiplication | 1.118 | 1.102 | +1.42% | Yes |
| G2 checked random 256-bit multiplication | 137.081 | 136.348 | +0.53% | No |
| G2 checked random 128-bit multiplication | 128.218 | 127.467 | +0.59% | Yes |
| G2 checked random 64-bit multiplication | 83.333 | 82.937 | +0.48% | Yes |
| G2 near-order multiplication | 41.431 | 41.249 | +0.44% | Yes |

G2 full-width results overlap the faster first baseline, so +0.53% is a point
estimate rather than a firm speedup claim. Generic G1 zero/one improve by
about 14–16 ns; those cases do not execute decomposition. Together with G05A,
the evidence supports a small improvement for this complete generic binary,
including layout effects, not a claim that every timing gain comes from the
integer products. Native builds retain the original code exactly. G01 and
G05B now form the retained baseline for G06.

## G06A: G1 GLV table with a common denominator

Decision: **keep**. Complete G1 random-256 multiplication improves 1.58–1.86%
and random-128 improves 1.29–1.41% across all three configurations.

Construct the four joint-signed table entries with the common denominator
`H=phi(P).x-P.x`, removing the setup inversion for `phi(P)-P`. Run the private
point loop on the isomorphic curve with coefficient `b*H^6`, then fold H into
the final Jacobian Z before normalization. Preserve the original exceptional
fallback when H is zero. The existing independent joint-component tests cover
both signs, identity and boundary component magnitudes. The source cites the
related libsecp256k1 global-Z/isomorphic-table technique.

- Job: `37b5493d1cc846f58b0c6f3ee3a394a2`.
- Source fingerprint: `8af9ca77fd1192893f17970088bcf4ebf0c0e04e96ec4cd828dd712fa6e8e623`.
- Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
  `-C target-cpu=native -C target-feature=-avx512ifma`, and generic x86
  `-C target-cpu=x86-64`. CPU 16; 100 samples; one-second warm-up and
  two-second collection; ABBA.
- Timing filter: complete G1 multiplication and its decoded kernel. Pairing
  and affine addition do not use this private table; all group correctness
  fixtures still run.

```sh
benchctl submit --json --label bn254-G06-g1-global-z --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G06-g1-global-z \
  --filter 'group_bytes_g1_mul_.*/solana-bn254/le$|group_kernel_g1_mul/solana-bn254$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/37b5493d1cc846f58b0c6f3ee3a394a2`.
All crate tests and complete group comparator checks passed in all three
builds. The artifact contains 27 ABBA rows, the patch, metadata, raw samples
and assembly.

Complete little-endian calls, geometric means of each variant's two rounds:

| Configuration | Scalar class | Before (µs) | Candidate (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | Random 256-bit | 36.316 | 35.641 | +1.86% |
| Native IFMA | Random 128-bit | 33.766 | 33.289 | +1.41% |
| Native IFMA | Maximum | 36.522 | 35.887 | +1.74% |
| Native scalar | Random 256-bit | 36.323 | 35.648 | +1.86% |
| Native scalar | Random 128-bit | 33.760 | 33.283 | +1.41% |
| Native scalar | Maximum | 36.543 | 35.902 | +1.75% |
| Generic x86 | Random 256-bit | 39.684 | 39.058 | +1.58% |
| Generic x86 | Random 128-bit | 36.847 | 36.371 | +1.29% |
| Generic x86 | Maximum | 39.939 | 39.320 | +1.55% |

Both candidate intervals are below both baseline intervals for every row
above. The decoded kernel improves 1.58–1.79%. Random-64 calls are essentially
unchanged. Native-scalar zero increases from about 382 to 387 ns (+1.36%),
with disjoint intervals; its one-scalar control improves about 11 ns. The
five-nanosecond zero overhead is accepted for the 0.48–0.68 µs dense-input
savings and is recorded rather than described as no regression. Native
near-order/zero and generic zero estimates overlap between runs. G01, G05B
and G06A are retained.

## G06B: G2 GLV table with a common denominator

Decision: **keep**. Complete G2 random-256 multiplication improves 1.28–1.49%
across all builds; random-128 and maximum scalars also improve consistently.

Apply the direct common-denominator four-entry table to G2's checked scalar
multiplication, retaining the H=0 fallback and folding H into final Jacobian
normalization. The private table's full-twist and signed-component oracles
exercise exceptional cases independently of scalar decomposition.

- Job: `aa606711e9d0428c882bb29c5e1a41ff`.
- Source fingerprint: `2604d1e09be21e86daffc15d6be9a5ace73f7b74ea62be366739332684db3c6e`.
- Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
  `-C target-cpu=native -C target-feature=-avx512ifma`, and generic x86
  `-C target-cpu=x86-64`. CPU 16; 100 samples; one-second warm-up and
  two-second collection; ABBA.
- Timing filter: complete G2 checked multiplication. Raw multiplication,
  subgroup checking and pairing do not use this private GLV table; their
  existing crate/group correctness checks still run.

```sh
benchctl submit --json --label bn254-G06-g2-global-z --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G06-g2-global-z \
  --filter 'group_bytes_g2_mul_.*/solana-bn254/le$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/aa606711e9d0428c882bb29c5e1a41ff`.
All crate tests and group comparator checks passed in all three configurations.
The artifact contains 24 ABBA rows, the patch, metadata, assembly and raw samples.

Complete little-endian checked calls, geometric means of two rounds:

| Configuration | Scalar class | Before (µs) | Candidate (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | Random 256-bit | 128.022 | 126.114 | +1.49% |
| Native IFMA | Random 128-bit | 118.944 | 117.789 | +0.97% |
| Native IFMA | Maximum | 127.789 | 125.680 | +1.65% |
| Native scalar | Random 256-bit | 127.925 | 126.292 | +1.28% |
| Native scalar | Random 128-bit | 119.977 | 117.237 | +2.28% |
| Native scalar | Maximum | 127.657 | 125.650 | +1.57% |
| Generic x86 | Random 256-bit | 137.434 | 135.471 | +1.43% |
| Generic x86 | Random 128-bit | 127.458 | 126.465 | +0.78% |
| Generic x86 | Maximum | 136.906 | 135.140 | +1.29% |

Both candidate intervals are below both baseline intervals for every row above.
Other scalar-class results overlap between runs. In particular, native sparse
point estimates regress 0.35–0.37% with overlapping intervals; zero, one and
near-order calls remain essentially unchanged. G01, G05B and both G06 table
changes are now retained.

## G07A: width-3 signed windows for G1 GLV

Decision: **discard this selector**. Width 3 helps 96/128-bit inputs, but
regresses 192/256-bit and maximum scalars. Preserve the per-class findings
for G13's conditional strategy trials. G01, G05B, G06A and G06B remain the
retained baseline.

Use width-3 NAF for both signed GLV components on dense magnitudes of at least
96 bits with more than 32 set bits. Keep the current binary/SJSF selection for
shorter and sparse values. Build the two positive odd multiples on an
isomorphic curve, bring them to one denominator with prefix/suffix products,
derive endomorphism images, and fold the denominator into final normalization.
All table work is inside each timed call. The source references the related
libsecp256k1 table technique and Arkworks NAF use.

Independent BigInt tests reconstruct width-3/4/5 digits at 128/256-bit limits;
independent point tests check odd tables and signed GLV components for all
three widths. Only width 3 is selected in production in this trial. Dense
96-bit and 192-bit byte fixtures were added to both variants before the
checkpoint; existing fixture values are unchanged. Every benchmark executable
now checks 29 byte-input families plus malformed and scalar-boundary inputs.

- Initial compile-only failure: `8ba0745178184a8ea59a173f2dfaed40`.
- Initial source fingerprint: `83e2d4d5e07dc4445c3eb334ad1f75f4f700e9a3f6266b6f75ec5c3f6227c89a`.
- Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
  `-C target-cpu=native -C target-feature=-avx512ifma`, and generic x86
  `-C target-cpu=x86-64`. CPU 16; 100 samples; one-second warm-up and
  two-second collection; ABBA.
- Timing filter: complete G1 multiplication and its decoded kernel. Pairing
  and affine addition do not use the changed scalar path.

```sh
benchctl submit --json --label bn254-G07-g1-w3 --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G07-g1-w3 \
  --filter 'group_bytes_g1_mul_.*/solana-bn254/le$|group_kernel_g1_mul/solana-bn254$'
```

The initial job failed before candidate tests or timings: Rust E0282 required
an explicit shift-index type in the new BigUint recoder oracle. `wait` returned
one, and failure logs/metadata were fetched to
`/Users/samkim/.local/state/benchctl/results/8ba0745178184a8ea59a173f2dfaed40`.
Changed the test's index range to `0usize..256`; production arithmetic is
unchanged. A new frozen submission is required because retrying the old UUID
would reuse the failing test source.

- Corrected measured submission: `5561f7ef82ce431fb8a3aa39c2f880c4`.
- Source fingerprint: `55ce3ee4592f359191deedab66b92c7d2e3035ecb5757031e6d5f9a3935c7801`.
- Command, compiler, flags, inputs and timing settings are as recorded above.

The corrected job succeeded, `wait` returned zero, and all results were fetched
to `/Users/samkim/.local/state/benchctl/results/5561f7ef82ce431fb8a3aa39c2f880c4`.
All crate tests and group comparator checks passed in all three builds; the
artifact contains 33 ABBA rows, patch, metadata, assembly and raw samples.

Complete little-endian calls, geometric means of two rounds:

| Configuration | Scalar class | Before (µs) | Candidate (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | Random 96-bit | 23.796 | 22.442 | +5.69% |
| Native IFMA | Random 128-bit | 33.318 | 32.428 | +2.67% |
| Native IFMA | Random 192-bit | 35.845 | 36.409 | -1.57% |
| Native IFMA | Random 256-bit | 35.682 | 35.970 | -0.81% |
| Native IFMA | Maximum | 35.908 | 36.455 | -1.52% |
| Native scalar | Random 96-bit | 23.804 | 22.438 | +5.74% |
| Native scalar | Random 128-bit | 33.322 | 32.464 | +2.58% |
| Native scalar | Random 192-bit | 35.865 | 36.465 | -1.67% |
| Native scalar | Random 256-bit | 35.682 | 36.024 | -0.96% |
| Native scalar | Maximum | 35.922 | 36.470 | -1.53% |
| Generic x86 | Random 96-bit | 25.933 | 24.370 | +6.03% |
| Generic x86 | Random 128-bit | 36.374 | 35.374 | +2.75% |
| Generic x86 | Random 192-bit | 39.264 | 39.825 | -1.43% |
| Generic x86 | Random 256-bit | 39.068 | 39.373 | -0.78% |
| Generic x86 | Maximum | 39.323 | 39.876 | -1.41% |

All rows above have disjoint intervals in the indicated direction. The decoded
kernel regresses 0.88–0.96%. One-scalar controls add about 18–19 ns; generic
zero adds about 18 ns. Native/generic near-order controls also regress, while
64-bit timing overlaps. The guarded restore returned all three candidate
source files to their checkpoint, retaining the expanded benchmark fixtures.

## G07B: width-4 signed windows for G1 GLV

Decision: **keep**. Complete dense G1 calls improve consistently across all
three builds. G07A was restored, so this compares width 4 against retained
G01/G05B/G06A/G06B, not against width 3.
Use the same dense >=96-bit selector, inversion-free odd tables, scalar
classes and independent width-3/4/5 oracles described for G07A. The positive
odd table now has four entries per component.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, one-second warm-up and
two-second measurement, ABBA. Pairing does not use this private scalar path.

- Job: `62e4433e84404e1e8da4e175e695a138`.
- Source fingerprint: `99f266b6ef79b302d401d766c2b61d365628a6286129d31d7de73ffeeb8f8c33`.

```sh
benchctl submit --json --label bn254-G07-g1-w4 --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G07-g1-w4 \
  --filter 'group_bytes_g1_mul_.*/solana-bn254/le$|group_kernel_g1_mul/solana-bn254$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/62e4433e84404e1e8da4e175e695a138`.
All crate tests and group comparator checks passed in all three builds.
Candidate source hashes match the local retained implementation. The artifact
contains 33 ABBA rows, patch, metadata, assembly and raw samples.

Complete little-endian calls, geometric means of two rounds:

| Configuration | Scalar class | Before (µs) | Candidate (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | random96 | 23.798 | 22.222 | +6.62% |
| Native IFMA | random128 | 33.295 | 30.931 | +7.10% |
| Native IFMA | random192 | 35.837 | 34.130 | +4.76% |
| Native IFMA | random256 | 35.663 | 34.054 | +4.51% |
| Native IFMA | max | 35.931 | 34.166 | +4.91% |
| Native scalar | random96 | 23.798 | 22.221 | +6.63% |
| Native scalar | random128 | 33.303 | 30.908 | +7.19% |
| Native scalar | random192 | 35.837 | 34.094 | +4.86% |
| Native scalar | random256 | 35.672 | 34.015 | +4.65% |
| Native scalar | max | 35.912 | 34.141 | +4.93% |
| Generic x86 | random96 | 25.903 | 24.127 | +6.86% |
| Generic x86 | random128 | 36.351 | 33.693 | +7.31% |
| Generic x86 | random192 | 39.231 | 37.257 | +5.03% |
| Generic x86 | random256 | 39.034 | 37.173 | +4.77% |
| Generic x86 | max | 39.300 | 37.332 | +5.01% |

All rows above have both candidate intervals below both baselines. The decoded
kernel improves 4.52–4.80%. Random-64 calls overlap. Native sparse adds about
24 ns (-0.12%, disjoint intervals), native-scalar one adds about 15 ns
(-3.94%, disjoint), and generic near-order adds about 9 ns (-0.82%, disjoint).
These small absolute costs are accepted for 1.58–2.66 µs dense-input savings;
G13 will revisit cheap-scalar dispatch. G01, G05B, both G06 changes and G07B
are now retained.

## G07C: width-5 signed windows for G1 GLV

Decision: **discard this selector**. Long inputs improve, but 96/128-bit
inputs regress. Preserve width 5 as a conditional G13 candidate. This trial
changes only the production width from 4 to 5 (eight positive odd multiples). The retained width-4 implementation is
the baseline; correctness fixtures and the >=96-bit dense selector are unchanged.

- Job: `64524560068c494e8d070832cefadef0`.
- Source fingerprint: `219981e2e2c7437fd0593b0dc1e570b6ecba90b8eac5440b80e74f74f800f3d5`.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, one-second warm-up and
two-second measurement, ABBA.

```sh
benchctl submit --json --label bn254-G07-g1-w5 --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G07-g1-w5 \
  --filter 'group_bytes_g1_mul_.*/solana-bn254/le$|group_kernel_g1_mul/solana-bn254$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/64524560068c494e8d070832cefadef0`.
All crate tests and group comparator checks passed in all three builds;
the artifact contains 33 ABBA rows, patch, metadata, assembly and raw samples.

| Configuration | Scalar class | Before (µs) | Candidate (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | random96 | 22.246 | 22.606 | -1.62% |
| Native IFMA | random128 | 30.966 | 31.165 | -0.64% |
| Native IFMA | random192 | 34.157 | 33.923 | +0.68% |
| Native IFMA | random256 | 34.086 | 33.792 | +0.86% |
| Native IFMA | max | 34.192 | 33.736 | +1.33% |
| Native scalar | random96 | 22.251 | 22.592 | -1.53% |
| Native scalar | random128 | 30.951 | 31.133 | -0.59% |
| Native scalar | random192 | 34.127 | 33.937 | +0.56% |
| Native scalar | random256 | 34.053 | 33.804 | +0.73% |
| Native scalar | max | 34.180 | 33.726 | +1.33% |
| Generic x86 | random96 | 24.312 | 24.557 | -1.01% |
| Generic x86 | random128 | 33.691 | 33.891 | -0.60% |
| Generic x86 | random192 | 37.242 | 36.967 | +0.74% |
| Generic x86 | random256 | 37.172 | 36.858 | +0.84% |
| Generic x86 | max | 37.335 | 36.779 | +1.49% |

Both candidate intervals are separated from both baselines in the indicated
direction for all rows except generic random96, which overlaps. The decoded
kernel improves 0.74–0.89%. However, short/128-bit regressions are repeatable;
zero adds 17–23 ns, native one adds 16 ns, generic one adds 32 ns, and
native-scalar/generic near-order add about 20/30 ns. Random64 also adds
16–26 ns with disjoint intervals. Restored all checkpointed candidate files,
so the retained G1 production width remains 4. G13 can measure width 5 only
for longer inputs without imposing its larger table on the shorter classes.

## G07D: width-3 signed windows for G2 GLV

Decision: **discard this selector**. It improves 96/128-bit inputs but
regresses longer inputs in every build. This trial adds ordinary width-3 NAF
for both GLV components of checked G2 multiplication, with the same dense
>=96-bit guard used for G1.
The raw full-twist API and subgroup check retain their existing algorithms.
Odd-table tests include arbitrary twist points and identity-aware common
denominators; signed-component oracles compare all three widths independently.
The baseline retains G01/G05B/G06A/G06B and G1 width 4 from G07B.

- Job: `bf263faa04b34a15a4de0ead896c931b`.
- Source fingerprint: `6fe73d7678e5a9f3b6aecb08292a5adafdac33cbbd8551529636b46b28c0f752`.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, one-second warm-up and
two-second measurement, ABBA. Pairing does not use this private GLV path.

```sh
benchctl submit --json --label bn254-G07-g2-w3 --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G07-g2-w3 \
  --filter 'group_bytes_g2_mul_.*/solana-bn254/le$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/bf263faa04b34a15a4de0ead896c931b`.
All crate tests and group comparator checks passed in all three builds.
The artifact contains 30 ABBA rows, patch, metadata, assembly and raw samples.

| Configuration | Scalar class | Before (µs) | Candidate (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | random96 | 92.119 | 89.174 | +3.20% |
| Native IFMA | random128 | 117.408 | 115.728 | +1.43% |
| Native IFMA | random192 | 125.961 | 127.940 | -1.57% |
| Native IFMA | random256 | 125.833 | 127.507 | -1.33% |
| Native IFMA | max | 125.746 | 127.644 | -1.51% |
| Native scalar | random96 | 92.002 | 89.148 | +3.10% |
| Native scalar | random128 | 117.686 | 115.869 | +1.54% |
| Native scalar | random192 | 126.303 | 127.869 | -1.24% |
| Native scalar | random256 | 125.532 | 127.426 | -1.51% |
| Native scalar | max | 125.686 | 127.487 | -1.43% |
| Generic x86 | random96 | 98.472 | 95.471 | +3.05% |
| Generic x86 | random128 | 126.269 | 124.761 | +1.19% |
| Generic x86 | random192 | 135.333 | 137.717 | -1.76% |
| Generic x86 | random256 | 135.201 | 137.304 | -1.56% |
| Generic x86 | max | 134.834 | 136.842 | -1.49% |

All rows above have disjoint intervals in the indicated direction. Generic
sparse also regresses 0.48% (about 422 ns), with disjoint intervals. The other
controls mostly overlap, with small gains for native random64/one and
native-scalar zero. Restored all checkpointed files; G1 width 4 and both G06
tables remain retained. Save the shorter-input gains for conditional G13 trials.

## G07E: width-4 signed windows for G2 GLV

Decision: **keep**. All dense scalar classes improve in every build. G07D
was restored; this compares width 4 directly with the retained joint-signed
G2 implementation. Use four positive odd
multiples, the same dense >=96-bit guard, and the same independent table,
component and byte oracles. G1 remains at retained width 4.

- Job: `9a5ecc42c2e6479eb0b364e02458663b`.
- Source fingerprint: `fbde31b1a22515f6326a24ff65b2703919c0d9e46562fa121441e54c6add7d14`.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, one-second warm-up and
two-second measurement, ABBA. Pairing does not use this private GLV path.

```sh
benchctl submit --json --label bn254-G07-g2-w4 --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G07-g2-w4 \
  --filter 'group_bytes_g2_mul_.*/solana-bn254/le$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/9a5ecc42c2e6479eb0b364e02458663b`.
All crate tests and group comparator checks passed in all three builds.
Local candidate source hashes match the measured snapshot. The artifact contains
30 ABBA rows, patch, metadata, assembly and raw samples.

| Configuration | Scalar class | Before (µs) | Candidate (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | random96 | 91.979 | 88.456 | +3.83% |
| Native IFMA | random128 | 117.823 | 111.307 | +5.53% |
| Native IFMA | random192 | 127.174 | 120.894 | +4.94% |
| Native IFMA | random256 | 126.863 | 121.425 | +4.29% |
| Native IFMA | max | 126.186 | 119.888 | +4.99% |
| Native scalar | random96 | 92.030 | 88.552 | +3.78% |
| Native scalar | random128 | 118.330 | 112.150 | +5.22% |
| Native scalar | random192 | 127.066 | 122.323 | +3.73% |
| Native scalar | random256 | 126.930 | 122.937 | +3.15% |
| Native scalar | max | 126.991 | 120.865 | +4.82% |
| Generic x86 | random96 | 98.441 | 94.846 | +3.65% |
| Generic x86 | random128 | 126.211 | 120.000 | +4.92% |
| Generic x86 | random192 | 135.438 | 130.174 | +3.89% |
| Generic x86 | random256 | 135.335 | 131.096 | +3.13% |
| Generic x86 | max | 135.043 | 129.607 | +4.03% |

Every row above has both candidate intervals below both baseline intervals,
including the faster closing baselines. Some native/scalar rounds were noisier
than prior jobs, so the point estimates should not be interpreted as precise
IFMA-versus-scalar differences. All control intervals overlap; generic sparse
has a -0.27% point estimate but no separated regression. Both G1 and G2 now
retain width 4 for dense magnitudes of at least 96 bits.

## G07F: width-5 signed windows for G2 GLV

Decision: **discard this selector**. Long-input gains do not offset the
96/128-bit regressions. This trial changes only the production G2 width from
4 to 5 (eight positive odd multiples). The retained width-4 implementation
is the baseline; G1, the selector and all correctness fixtures are unchanged.

- Job: `a6e63eeece0d49feafef8c111b53e688`.
- Source fingerprint: `f1d2239ee81bd250439820c8820881d6d1f6322945b4310e988481a0a47c990f`.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, one-second warm-up and
two-second measurement, ABBA. Pairing does not use this private GLV path.

```sh
benchctl submit --json --label bn254-G07-g2-w5 --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G07-g2-w5 \
  --filter 'group_bytes_g2_mul_.*/solana-bn254/le$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/a6e63eeece0d49feafef8c111b53e688`.
All crate tests and group comparator checks passed in all three builds.
The artifact contains 30 ABBA rows, patch, metadata, assembly and raw samples.

| Configuration | Scalar class | Before (µs) | Candidate (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | random96 | 88.370 | 89.822 | -1.64% |
| Native IFMA | random128 | 111.436 | 112.114 | -0.61% |
| Native IFMA | random192 | 120.914 | 120.534 | +0.31% |
| Native IFMA | random256 | 121.477 | 120.851 | +0.52% |
| Native IFMA | max | 120.241 | 119.160 | +0.90% |
| Native scalar | random96 | 88.357 | 89.971 | -1.83% |
| Native scalar | random128 | 111.380 | 112.300 | -0.83% |
| Native scalar | random192 | 121.136 | 120.394 | +0.61% |
| Native scalar | random256 | 121.576 | 120.955 | +0.51% |
| Native scalar | max | 120.320 | 119.737 | +0.48% |
| Generic x86 | random96 | 94.926 | 96.362 | -1.51% |
| Generic x86 | random128 | 119.911 | 120.682 | -0.64% |
| Generic x86 | random192 | 130.308 | 129.455 | +0.65% |
| Generic x86 | random256 | 130.925 | 129.818 | +0.85% |
| Generic x86 | max | 129.375 | 128.324 | +0.81% |

All rows have disjoint intervals in the indicated direction except native-
scalar maximum, which overlaps. Random64 regresses 0.10% (81 ns) in native
scalar and improves 0.20% in generic; other controls overlap, including
generic sparse with a -0.41% point estimate. Restored the checkpoint. Both
groups retain width 4; the modest width-5 long-input gains remain evidence
for a separate G13 conditional selector trial if later algorithms need it.

## G08A: width-3 signed windows for raw G2 multiplication

Decision: **keep**, with the native high-sparse tradeoff recorded below.
Replace dense >=96-bit raw binary multiplication
with ordinary 256-bit width-3 NAF, without reducing modulo r or using subgroup
eigenvalues. Reuse the retained G2 odd-table construction and preserve the
binary fallback for small/sparse values and exceptional table preparation.
The shared recoder now exposes its full-U256 entry point in production.

- Job: `fde0426eef5d4dc1b5f35a569f0c6d41`.
- Source fingerprint: `a4447a1f77e6d6f8200cda447293fa93a5f3b51b3977336efe5e24f7a857fd2a`.

Add raw scalar timing classes before the checkpoint: random192/128/96/64,
sparse, high_sparse, near_order, maximum, zero and one, in addition to the
existing random256 kernel. Every fixture is checked against independent Ark
ordinary-integer multiplication outside timing. New unit oracles cover all
three widths on the full twist, including full-width/order/bit boundaries.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, one-second warm-up and
two-second measurement, ABBA. Checked multiplication/subgroup/pairing paths
do not call this raw entry point; their existing correctness checks still run.

```sh
benchctl submit --json --label bn254-G08-raw-w3 --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G08-raw-w3 \
  --filter 'group_kernel_g2_raw_mul.*/solana-bn254$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/fde0426eef5d4dc1b5f35a569f0c6d41`.
All crate tests and the expanded group comparator checks passed in every
configuration. Local candidate source hashes match the measured snapshot.
The artifact contains 33 ABBA rows, patch, metadata, assembly and raw samples.

Decoded raw full-twist multiplication, with all per-call preparation and final
normalization included, geometric means of two rounds:

| Configuration | Scalar class | Before (µs) | Candidate (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | random256 | 184.248 | 143.304 | +22.22% |
| Native IFMA | random128 | 82.596 | 66.548 | +19.43% |
| Native IFMA | random96 | 60.613 | 52.397 | +13.56% |
| Native IFMA | max | 272.139 | 98.828 | +63.68% |
| Native IFMA | high_sparse | 95.345 | 96.403 | -1.11% |
| Native scalar | random256 | 183.194 | 143.061 | +21.91% |
| Native scalar | random128 | 82.689 | 66.524 | +19.55% |
| Native scalar | random96 | 60.597 | 52.368 | +13.58% |
| Native scalar | max | 272.126 | 98.952 | +63.64% |
| Native scalar | high_sparse | 95.351 | 96.443 | -1.15% |
| Generic x86 | random256 | 198.849 | 157.375 | +20.86% |
| Generic x86 | random128 | 88.086 | 71.411 | +18.93% |
| Generic x86 | random96 | 64.595 | 56.127 | +13.11% |
| Generic x86 | max | 290.691 | 107.957 | +62.86% |
| Generic x86 | high_sparse | 104.549 | 104.590 | -0.04% |

All dense/maximum rows have both candidate intervals below both baselines.
Random192 improves 20.54–21.44%; order-adjacent integers improve 19.16–20.43%.
Zero/one improve by 34–66 ns. Sparse and most random64 controls overlap.

Tradeoff: native high_sparse regresses 1.11–1.15%, about 1.06–1.09 µs, with
disjoint intervals in both native configurations; generic overlaps. This case
still uses binary multiplication. Assembly inspection finds identical normalized
instruction streams for mul_projective::<4> (518 instructions) and Projective
double (1257), ignoring relocated branch/call/RIP targets. The public wrapper
now inlines window preparation and has a 3384-byte frame. A wrapper/layout
effect is plausible, but the exact cause has not been isolated. Accept this
measured cost for the 40–41 µs random256 and 173–183 µs maximum savings;
retain high_sparse in subsequent width trials and G13 selector work.

These raw-API gains do not describe the subgroup-checked byte syscall: that
entry point uses the separately optimized GLV path and remains unchanged.

## G08B: width-4 signed windows for raw G2 multiplication

Decision: **discard this default width**, preserving the dense-input findings
for G13. The confirmed native gain is modest relative to the maximum/high-sparse
costs; a conditional selector should address those costs in a separate trial.
Change only raw G2 width 3 to width 4, retaining
the dense >=96-bit selector and full-integer semantics. Both checked GLV
paths remain at width 4. All raw classes, including high_sparse, remain timed.

- Job: `bb23fdc1709640809022bb94795c3279`.
- Source fingerprint: `4610d534fb8d859e6042c01da12f193b2f77dadcf2f7b7dff5ab5239a5baf684`.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, one-second warm-up and
two-second measurement, ABBA.

```sh
benchctl submit --json --label bn254-G08-raw-w4 --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G08-raw-w4 \
  --filter 'group_kernel_g2_raw_mul.*/solana-bn254$'
```

The first job succeeded, `wait` returned zero, and all results were fetched to
`/Users/samkim/.local/state/benchctl/results/bb23fdc1709640809022bb94795c3279`.
All correctness checks passed in all configurations; the artifact contains
33 ABBA rows. Local candidate hashes match its metadata.

Native scalar and generic random256 improve 4.77% and 5.18%, with both
candidate intervals below both baselines. Native IFMA is inconclusive: the
two baselines are 143.184/143.257 µs, while candidates are 144.772/139.968 µs,
giving an aggregate +0.61% that hides opposite outcomes. This unresolved
primary-case variation warrants a focused native rerun with two-second warm-up
and four-second collection. Other configurations need no repeat.

- Confirmation job: `c1e654d32f6c47468d2c2ce6f0d6c4b2`.
- Confirmation source fingerprint: `ceac3c6c43d913a3b991e33f0a7c8b6352735bfcb70c008ffc70ca775981ba2f`.
- Rust 1.98.0, `-C target-cpu=native`, CPU 16, 100 samples, ABBA; only warm-up,
  collection duration and the timing filter differ as shown in the command.

The first job also shows repeatable maximum-scalar regressions of 1.66–1.73%
(1.64–1.87 µs), gains of 2.45–2.92% for random128, 3.84–4.38% for random192,
and 4.06–4.63% for near-order values. Native high_sparse intervals overlap;
the original G08A sparse cost is not established as resolved.

```sh
benchctl submit --json --label bn254-G08-raw-w4-confirm --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G08-raw-w4 \
  --configs native --warmup 2 --measurement 4 \
  --filter 'group_kernel_g2_raw_mul(_random128|_max|_high_sparse)?/solana-bn254$'
```

The confirmation succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/c1e654d32f6c47468d2c2ce6f0d6c4b2`.
All native correctness checks passed; local candidate hashes matched the result.

| Native confirmation case | Before (µs) | Candidate (µs) | Improvement |
| --- | ---: | ---: | ---: |
| random256 | 140.888 | 138.066 | +2.00% |
| random128 | 66.507 | 64.810 | +2.55% |
| high_sparse | 95.106 | 96.230 | -1.18% |
| maximum | 98.565 | 100.290 | -1.75% |

All four rows have separated intervals in the indicated direction. Native
random256 candidates still vary (136.781/139.363 µs), but both beat both
baselines (140.999/140.778 µs). This establishes a native gain in the repeat,
not the 4.8–5.2% measured in the other builds. The maximum cost is repeatable
in every build, and the confirmation also finds a high_sparse regression.
Restore width 3 for now; G13 can measure a conditional dense-input choice with
a smaller table for low-NAF-weight values and a cheaper sparse dispatch.

## G08C: width-5 signed windows for raw G2 multiplication

Decision: **discard this default width**. G08B was restored, so this compares raw width 5
against retained width 3. Only the raw width constant changes; the dense
>=96-bit selector, checked GLV paths and all correctness fixtures are unchanged.

- Job: `62db771bb9b94a94bd6b3f7414af98a4`.
- Source fingerprint: `74bc949bfae8a9abe499a9e4a999d7df6b43ca5f0faf2cfe4a8b116a7a19e5b2`.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, one-second warm-up and
two-second measurement, ABBA.

```sh
benchctl submit --json --label bn254-G08-raw-w5 --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G08-raw-w5 \
  --filter 'group_kernel_g2_raw_mul.*/solana-bn254$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/62db771bb9b94a94bd6b3f7414af98a4`.
All correctness checks passed in all three configurations; the artifact contains
33 ABBA rows. The guarded restore verified local candidate hashes and restored
raw width 3.

| Configuration | Case | Before (µs) | Candidate (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | random256 | 142.896 | 134.093 | +6.16% |
| Native scalar | random256 | 142.098 | 133.623 | +5.96% |
| Generic x86 | random256 | 157.355 | 147.707 | +6.13% |
| Native IFMA | maximum | 98.923 | 105.631 | -6.78% |
| Native scalar | maximum | 98.884 | 104.880 | -6.06% |
| Generic x86 | maximum | 107.807 | 114.925 | -6.60% |

All these intervals are separated in the indicated direction. Random192 gains
3.73–4.51%, near-order gains 4.19–4.38%, and random128 gains 0.38–0.78%, also
with separated intervals. However, random96 regresses 1.23–1.44% in all builds.
Native zero/one calls regress 65–76 ns (29–34%); the corresponding generic calls
improve 52–60 ns. Native random64 regresses 62 ns; other native sparse controls
overlap. Generic high_sparse/random64 improve 0.29/0.32%.

The maximum and random96 costs rule out this default despite the full-width
gain. Preserve the width-5 dense findings for a separately measured G13
selector; do not infer that raw width 5 helps every scalar class.

## G09A: projective 3P in standalone subgroup checks

Decision: **discard**. Keep the standalone fixed-chain triple projective,
saving its normalization but replacing nine mixed additions with full additions.
The batch checker retains its normalized triple path. Time standalone valid and
invalid checks, complete checked multiplication with random256 and zero scalars,
and pairing at 1/4/16 pairs. Existing full-twist fixed-chain oracles remain enabled.

- Job: `30b2af9e8bfa44d5ae5959030d241327`.
- Source fingerprint: `5c881a4e042d55816449af9b9eff2c1ff0292be90fcdbbb62c60a359a0246ffe`.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, warm-up 1 s, measurement 2 s, ABBA.

```sh
benchctl submit --json --label bn254-G09-projective-triple --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G09-projective-triple \
  --filter 'group_bytes_g2_mul_(random256|zero)/solana-bn254/le$|group_kernel_g2_subgroup_.*/solana-bn254$' \
  --pairing
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/30b2af9e8bfa44d5ae5959030d241327`.
All correctness checks passed in all three configurations; the artifact contains
12 group and nine pairing ABBA rows. Candidate hashes were verified before the
guarded restore.

| Configuration | Valid subgroup check, before → candidate (µs) | Improvement |
| --- | ---: | ---: |
| Native IFMA | 37.293 → 38.512 | -3.27% |
| Native scalar | 37.283 → 38.509 | -3.29% |
| Generic x86 | 39.791 → 41.160 | -3.44% |

All valid/invalid subgroup checks and checked zero-scalar calls regress with
separated intervals: invalid checks lose 3.37–3.51%, zero calls 3.34–3.45%.
Native-scalar random256 loses 0.35% with separated intervals; the native IFMA
(-0.38%) and generic (+0.07%) random256 intervals overlap. Generic one-pair
pairing loses 0.93% with separated intervals. Other pairing rows overlap except
native four-pair's +0.16%. The extra full additions outweigh the saved inverse.

## G09B: common-denominator standalone subgroup chain

Decision: **keep**, against the restored pre-G09A implementation.
Scale P by the projective triple's existing Z and use P/3P numerators on the
same isomorphic curve. The chain retains all 17 mixed additions and folds Z
back before the subgroup relation's Frobenius maps. An infinite triple is
handled explicitly; no subgroup assumption enters this ordinary-integer chain.
Batch normalization remains unchanged. Existing full-twist fixed-chain and
subgroup oracles exercise the new path.

- Job: `26a333d16bfb4f1ba0ebd36326a7c096`.
- Source fingerprint: `f8bc163d9e89a00437265811e773c8a69b142731f5f281cbc7f3a7b21aeaa791`.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, warm-up 1 s, measurement 2 s, ABBA.

```sh
benchctl submit --json --label bn254-G09-common-z --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G09-common-z \
  --filter 'group_bytes_g2_mul_(random256|zero)/solana-bn254/le$|group_kernel_g2_subgroup_.*/solana-bn254$' \
  --pairing
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/26a333d16bfb4f1ba0ebd36326a7c096`.
All correctness checks passed in all configurations; the artifact contains
12 group and nine pairing ABBA rows. Local candidate hashes match metadata.

| Configuration | Case | Before (µs) | After (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | valid subgroup check | 37.283 | 36.540 | +1.99% |
| Native scalar | valid subgroup check | 37.271 | 36.564 | +1.90% |
| Generic x86 | valid subgroup check | 39.787 | 39.055 | +1.84% |
| Native IFMA | checked random256 | 121.412 | 120.138 | +1.05% |
| Native scalar | checked random256 | 121.345 | 119.813 | +1.26% |
| Generic x86 | checked random256 | 130.881 | 128.608 | +1.74% |

Every group row has both candidate intervals below both baselines. Invalid
subgroup checks improve 1.84–2.03%; checked zero-scalar calls improve 1.77–1.90%.
One-pair pairing improves 1.43/0.42/0.64% (native/scalar/generic), with separated
intervals. Native 4/16-pair gains are 0.22/0.13%, and generic four-pair gains
0.17%, also separated. Tradeoff: native-scalar 16-pair loses 0.06% (2.28 µs
over 3.63 ms), with separated intervals; scalar four-pair and generic 16-pair
overlap. Retain the consistent group gains while recording that small cost.

## G10A: bounded constant multiples in G1 doubling

Decision: **discard**. Replace repeated canonical additions for 3A,
4XB and 8C with private five-limb accumulation plus the existing <10q reducer.
Move that reducer unchanged into a shared portable module; its nonresidue
quotient/carry-boundary tests still call the same implementation. Add independent
integer oracles for the new multiples. G2 formulas remain unchanged in this trial.

- Job: `9a08de278fa5439aac546b2c77fcecea`.
- Source fingerprint: `9284089b6d7dddc3fb19e7405432533e878fc31254f1701900405c34ba5b0e10`.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, warm-up 1 s, measurement 2 s, ABBA.

```sh
benchctl submit --json --label bn254-G10-g1-scale --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G10-g1-scale \
  --filter 'group_bytes_g1_(add_(random|double)|mul_(random256|random128|random64|sparse|max|zero))/solana-bn254/le$' \
  --pairing
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/9a08de278fa5439aac546b2c77fcecea`.
All correctness checks passed in all configurations; the artifact contains
24 group and nine pairing ABBA rows. Candidate hashes were checked before
restoring all four trial files, including removal of the new helper module.

| Configuration | Random256 before → candidate (µs) | Improvement |
| --- | ---: | ---: |
| Native IFMA | 34.102 → 34.393 | -0.86% |
| Native scalar | 34.048 → 34.404 | -1.05% |
| Generic x86 | 37.193 → 37.275 | -0.22% |

All timed nonzero multiplication classes regress with separated intervals:
random128 by 0.19–1.09%, random64 by 0.19–0.68%, sparse by 0.34–1.16%, and
maximum by 0.23–0.93%. Doubling, zero and most random-addition controls overlap;
generic random addition loses about 1 ns. Pairing mostly overlaps; scalar
one/four-pair improve 0.13/0.06%. There is no useful G1 gain to retain.

## G10B: bounded constant multiples in G2 doubling

Decision: **keep**. Independently apply the shared <10q reducer to
G2's 3A and 8C, retaining its 2M+5S doubling formula. The G1 scale trial was
restored. Time checked multiplication, raw full-twist multiplication, subgroup
checks and pairing; all integer/point/comparator correctness checks remain on.

- Job: `8ede02f4c1e248628b2bd6b49dea529e`.
- Source fingerprint: `01d240ad6d4f6d31b1ca50e775b96f9101cb6cf546e45f4501d8575faa4b65b1`.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, warm-up 1 s, measurement 2 s, ABBA.

```sh
benchctl submit --json --label bn254-G10-g2-scale --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G10-g2-scale \
  --filter 'group_bytes_g2_(add_double|mul_(random256|random64|sparse|zero))/solana-bn254/le$|group_kernel_g2_(raw_mul(_max)?|subgroup_(valid|invalid))/solana-bn254$' \
  --pairing
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/8ede02f4c1e248628b2bd6b49dea529e`.
All correctness checks passed in all configurations; the artifact contains
27 group and nine pairing ABBA rows. Local candidate hashes match metadata.

| Configuration | Case | Before (µs) | After (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | checked random256 | 119.430 | 117.606 | +1.53% |
| Native scalar | checked random256 | 119.825 | 117.318 | +2.09% |
| Generic x86 | checked random256 | 127.994 | 124.502 | +2.73% |
| Native IFMA | raw random256 | 145.070 | 134.119 | +7.55% |
| Native scalar | raw random256 | 143.773 | 133.938 | +6.84% |
| Generic x86 | raw random256 | 157.261 | 142.899 | +9.13% |
| Native IFMA | raw maximum | 98.579 | 96.106 | +2.51% |
| Native scalar | raw maximum | 98.677 | 96.211 | +2.50% |
| Generic x86 | raw maximum | 107.959 | 103.188 | +4.42% |

All these rows have both candidate intervals below both baselines. Generic
random64/sparse/zero/subgroup calls improve 1.00–2.12%, with separated intervals;
corresponding native controls mostly overlap. Four/16-pair pairing improves
0.50/0.86% native, 0.70/0.78% scalar, and 0.58/0.90% generic, all separated.
Scalar one-pair improves 0.38%; other one-pair intervals overlap.

Tradeoffs: native affine doubling loses 13 ns (0.79%), generic doubling loses
2 ns (0.14%), and scalar valid-subgroup checking loses 43 ns (0.12%), each with
separated intervals. Retain the larger multiplication and pairing gains while
recording these small costs. The differing gains across scalar shapes include
compiler/code-layout effects; an operation-count model alone does not explain
the measured raw-random improvement.

## G10C: fused scaled subtraction in G1 doubling

Decision: **discard**. Replace X=E²-2D and Y=E(D-X)-8C with private
five-limb accumulation of a+N(q-b), below 9q, and the retained shared reducer.
G2 keeps G10B's constant multiples. Independent integer oracles cover the new
subtraction helper; all existing group/pairing correctness tests remain enabled.
Timing targets G1: no existing field kernel or G2/pairing caller changes here.

- Job: `a52593d4a4d141c58654935380a98c98`.
- Source fingerprint: `f1c28ddec63b7119656252c02937f3e376e3bb27bfc5a398bdcb6358fc487bad`.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, warm-up 1 s, measurement 2 s, ABBA.

```sh
benchctl submit --json --label bn254-G10-g1-sub --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G10-g1-sub \
  --filter 'group_bytes_g1_(add_(random|double)|mul_(random256|random128|random64|sparse|max|zero))/solana-bn254/le$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/a52593d4a4d141c58654935380a98c98`.
All correctness checks passed in all configurations; the artifact contains
24 group ABBA rows. Candidate hashes were verified before the guarded restore,
which preserved G10B's shared reducer and G2 constant multiples.

| Configuration | Random256 before → candidate (µs) | Improvement |
| --- | ---: | ---: |
| Native IFMA | 34.045 → 34.869 | -2.42% |
| Native scalar | 34.084 → 34.940 | -2.51% |
| Generic x86 | 37.187 → 37.896 | -1.91% |

All measured nonzero multiplication classes regress with separated intervals:
random128 by 2.13–2.87%, random64 by 1.99–2.27%, sparse by 3.27–3.70%, and
maximum by 1.85–2.53%. Native addition controls improve about 1.1% and zero
improves 11 ns; scalar zero loses 7 ns, and generic zero loses under 1 ns.
These small controls do not offset the consistent multiplication regressions.
No pairing performance claim is made for this G1-only trial.

## G10D: fused scaled subtraction in G2 doubling

Decision: **discard**. Independently replace G2's X=E²-2D and
Y=E(D-X)-8C with the bounded subtraction helper. Retain G10B's 3A computation
and shared reducer. The G1 subtraction trial is restored. Check all integer,
point and comparator oracles, then measure G2 calls and pairing regressions.

- Job: `3601df39b46c4b7d90164179cd4f1291`.
- Source fingerprint: `2f33d9e32b277097ffbe366a700e10db0056dff0911550a98dc61f748509a5d4`.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, warm-up 1 s, measurement 2 s, ABBA.

```sh
benchctl submit --json --label bn254-G10-g2-sub --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G10-g2-sub \
  --filter 'group_bytes_g2_(add_double|mul_(random256|random64|sparse|zero))/solana-bn254/le$|group_kernel_g2_(raw_mul(_max)?|subgroup_(valid|invalid))/solana-bn254$' \
  --pairing
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/3601df39b46c4b7d90164179cd4f1291`.
All correctness checks passed in all configurations; the artifact contains
27 group and nine pairing ABBA rows. Candidate hashes were verified before
the guarded restore, preserving G10B's constant multiples and shared reducer.

| Configuration | Checked random256 before → candidate (µs) | Improvement |
| --- | ---: | ---: |
| Native IFMA | 117.317 → 118.330 | -0.86% |
| Native scalar | 117.234 → 118.209 | -0.83% |
| Generic x86 | 124.302 → 125.579 | -1.03% |

All checked scalar classes and standalone subgroup checks regress with separated
intervals: random64 by 1.14–1.47%, sparse by 1.50–2.00%, zero by 1.21–1.55%,
and valid/invalid subgroup checks by 1.16–1.57%. Raw maximum loses 1.36–1.92%.
Native raw random256 gains 0.30%; other raw random256 intervals overlap.
Native affine doubling loses 5 ns; scalar/generic doubling intervals overlap.

Native pairing improves 0.69/0.37/0.26% at 1/4/16 pairs, with separated
intervals. Scalar one/16-pair gains 0.09/0.08%; scalar four-pair and all generic
pairing intervals overlap. Those pairing gains do not justify the consistent
regressions in the G2 operations targeted by this series.

## G11A: four-way Frobenius decomposition with a joint subset table

Decision: **keep**. Use the Galbraith–Scott Example 5 lattice and
independently bounded downward-rounded reciprocals for four signed components
below 2^67. Construct the four Frobenius images on the original curve, then
15 nonempty subset entries with a shared denominator. The short joint loop
folds that denominator into the result before normalization.

The caller must already have validated subgroup membership. Initially select
only dense scalars with a nonzero top limb; shorter/sparse inputs retain GLV
or binary selection. Raw full-twist multiplication and subgroup checks do not
use the decomposition. Integer quotient-boundary tests and independent point
oracles check the lattice, signs, actual maps and full-width scalar semantics.
Reference: <https://eprint.iacr.org/2008/117.pdf>, Example 5. The separate queued
parameter derivation is recorded below; it was not a performance trial.

- Job: `8251cf3fa6694ae79a025e6cb6f79df3`.
- Source fingerprint: `15dcb25e28be34d51ce691dff199cf41e770409d9dec22f3b9deaf8e6d2fdd42`.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, warm-up 1 s, measurement 2 s, ABBA.
All checked scalar classes are timed. Pairing correctness remains covered by
crate tests; no pairing timing is requested because its callers are unchanged.

```sh
benchctl submit --json --label bn254-G11-shamir --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G11-shamir \
  --filter 'group_bytes_g2_mul_.*/solana-bn254/le$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/8251cf3fa6694ae79a025e6cb6f79df3`.
All correctness checks passed in all configurations; the artifact contains
30 group ABBA rows. Local candidate hashes match metadata.

| Configuration | Case | Before (µs) | After (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | random256 | 117.397 | 106.630 | +9.17% |
| Native scalar | random256 | 117.371 | 106.551 | +9.22% |
| Generic x86 | random256 | 124.556 | 111.640 | +10.37% |
| Native IFMA | maximum | 117.350 | 109.136 | +7.00% |
| Native scalar | maximum | 117.145 | 109.100 | +6.87% |
| Generic x86 | maximum | 124.231 | 114.293 | +8.00% |

All selected-path rows have both candidate intervals below both baselines.
Tradeoffs: native random192 loses 447 ns (0.38%), scalar random192 loses
270 ns (0.23%), and scalar random128 loses 176 ns (0.16%), with separated
intervals. Generic random192 gains 0.28%; other shorter/sparse/near-order/zero/
one controls overlap. These cases still use the old algorithm; track their
dispatch/layout costs in G13 while retaining the much larger full-width gains.

## G11B: four-way decomposition with two joint signed schedules

Decision: **keep**, against retained G11A. Use
lambda_p²=1+lambda_glv to transform the four components to
(k0+k2,k1+k3,k2,k3), each below 2^68, on two GLV pairs. Reuse the G06
four-entry table per pair, cross-scale the two denominators, and run two
joint sparse schedules. This trades a smaller eight-entry table for additional
loop additions. Preserve the same subgroup-only guard, decomposition, and
independent map/integer/point oracles.

- Job: `7d1a8ef61fda43ae89b45b3967182de7`.
- Source fingerprint: `53dc12d5772420953401d7a5f16db59ab44d2849f1c8aca93f22a85c42871cdf`.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, warm-up 1 s, measurement 2 s, ABBA.

```sh
benchctl submit --json --label bn254-G11-pairs --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G11-pairs \
  --filter 'group_bytes_g2_mul_.*/solana-bn254/le$'
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/7d1a8ef61fda43ae89b45b3967182de7`.
All correctness checks passed in all configurations; the artifact contains
30 group ABBA rows. Local candidate hashes match metadata.

| Configuration | Case | Before (µs) | After (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| Native IFMA | random256 | 106.581 | 100.444 | +5.76% |
| Native scalar | random256 | 106.578 | 100.448 | +5.75% |
| Generic x86 | random256 | 111.651 | 105.663 | +5.36% |
| Native IFMA | maximum | 109.179 | 101.153 | +7.35% |
| Native scalar | maximum | 109.149 | 101.174 | +7.31% |
| Generic x86 | maximum | 114.290 | 106.405 | +6.90% |

All selected-path rows have both candidate intervals below both baselines.
Other controls overlap except gains for scalar random192 (+0.31%) and generic
near-order/zero/one (+0.04/+0.10/+0.14%). No row has both candidate intervals
above both baselines. Replace the Shamir table with this smaller-table variant;
the exact four-way decomposition and its proof/oracle tests remain unchanged.

## G12: IFMA scheduling within G2 doubling

Decision: **keep**. Pack two Fq2 squares plus YZ into seven lanes,
then three independent Fq2 squares into six lanes. Use the existing canonical
R=2^256 IFMA multiplier, keeping conversion and packing inside each doubling.
Preserve G10B's 3A/8C combinations. Direct Arkworks oracles cover distinct lanes,
canonical boundaries and 52-bit carries; existing full-twist point and subgroup
tests cover the integrated formula. Compile-time AVX-512 F/DQ/IFMA gates select
the candidate, with the retained scalar formula in the complementary branch.

- Job: `4e55e3007f604f83b979c141e827a8ef`.
- Source fingerprint: `23e027505ec2213fd82eca8f08f693ba9c1c77be3994f511c3241245da3d4fa5`.

Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
`-C target-cpu=native -C target-feature=-avx512ifma`, generic
`-C target-cpu=x86-64`; CPU 16, 100 samples, warm-up 1 s, measurement 2 s, ABBA.
The scalar configurations check the gated fallback as controls. This is the
initial packing experiment, not a persistent packed-coordinate implementation.

```sh
benchctl submit --json --label bn254-G12-ifma-double --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G12-ifma-double \
  --filter 'group_bytes_g2_(add_double|mul_(random256|random64|sparse|zero))/solana-bn254/le$|group_kernel_g2_(raw_mul(_max)?|subgroup_(valid|invalid))/solana-bn254$' \
  --pairing
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/4e55e3007f604f83b979c141e827a8ef`.
All correctness checks passed in all configurations; 27 group and nine pairing
ABBA rows were collected. Local candidate hashes match metadata.

| Native IFMA case | Before (µs) | After (µs) | Improvement |
| --- | ---: | ---: | ---: |
| Checked random256 | 100.460 | 91.955 | +8.47% |
| Checked random64 | 77.095 | 68.453 | +11.21% |
| Checked sparse | 80.863 | 68.862 | +14.84% |
| Subgroup valid | 36.545 | 32.138 | +12.06% |
| Raw random256 | 134.446 | 122.973 | +8.53% |
| Raw maximum | 96.140 | 79.783 | +17.01% |

All native group rows have separated favorable intervals; native checked zero
and invalid subgroup gain 12.11% and 12.10%. Native pairing improves
0.11/0.35/0.31% for 1/4/16 pairs, also with separated intervals.
Scalar and generic group intervals overlap except scalar raw maximum (+0.18%).
Scalar pairing intervals overlap. Generic one-pair shows a separated -0.15%,
but the baseline and candidate generic pairing executables are byte-identical:
this is between-run variation, not a changed generic implementation.
Other generic pairing intervals overlap. The group binaries differ even for
the gated fallbacks; no performance gain is attributed to those configurations.

## G12B: bounded private IFMA input sums

Decision: **keep**. Replace canonical coefficient additions used only
as packed-multiplier inputs with unreduced four-limb sums. Canonical inputs
give sums below 2q < 2^255, so no carry is lost. The existing multiplier accepts
both operands below 2q with normalized radix-52 limbs; its single final
subtraction still suffices because 4q < 2^256. Output coefficients remain
canonical. Existing packed-boundary oracles include sums approaching 2q.
This removes seven reductions per packed G2 doubling, with scalar code gated
out as before. Only `backend/avx512/fq.rs` differs from retained G12.

- Job: `250823593e1d436c968b21e97f8183df`.
- Source fingerprint: `cb8714ed63c8f81936e621928c7d7c465aae1e8c7420321a362a8b82d8191b14`.
- Rust 1.98.0; native IFMA `-C target-cpu=native`, native scalar
  `-C target-cpu=native -C target-feature=-avx512ifma`, generic
  `-C target-cpu=x86-64`; CPU 16, 100 samples, 1 s warm-up, 2 s measurement, ABBA.

```sh
benchctl submit --json --label bn254-G12B-lazy-sums --timeout 2h \
  --artifact group-experiment-results -- \
  python3 scripts/benchmark-bn254-groups.py run --id G12B-lazy-sums \
  --filter 'group_bytes_g2_(add_double|mul_(random256|random64|sparse|zero))/solana-bn254/le$|group_kernel_g2_(raw_mul(_max)?|subgroup_(valid|invalid))/solana-bn254$' \
  --pairing
```

The job succeeded, `wait` returned zero, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/250823593e1d436c968b21e97f8183df`.
All correctness checks passed in all configurations; 27 group and nine pairing
ABBA rows were collected. Local candidate hashes match metadata.

| Native IFMA case | Before (µs) | After (µs) | Improvement |
| --- | ---: | ---: | ---: |
| Checked random256 | 91.967 | 91.438 | +0.58% (overlap) |
| Checked random64 | 68.445 | 67.479 | +1.41% |
| Checked sparse | 68.586 | 66.833 | +2.56% |
| Subgroup valid | 32.129 | 31.672 | +1.42% |
| Raw random256 | 122.639 | 115.451 | +5.86% |
| Raw maximum | 79.656 | 76.264 | +4.26% |

Other native group rows improve with separated intervals except affine
doubling, which overlaps. Native checked zero and invalid subgroup gain
1.30% and 1.47%. Native pairing gains 0.90/0.82/0.90% at 1/4/16 pairs,
with separated intervals. No native row has separated unfavorable intervals.
All scalar and generic executables (groups and pairing) are byte-identical
between baseline and candidate. Their timing differences are run variation,
including scalar random64's separated -0.09%; none represents changed code.

## Independent preparation for G11

Job `25d1641a8b6c4a9aa334b52327e556b9` verified the Galbraith–Scott Example 5
lattice identities and derived prospective four-way decomposition parameters.
This was a queued mathematical preparation job, not a G11 implementation or
performance trial; four-way multiplication had not yet been applied at that point.

- Source fingerprint: `8e1accb055206ec53060be0f0ddf608d3cee2af0c3abed90531416fde4b38725`.
- Command: `benchctl submit --json --label bn254-G11-parameter-derivation --artifact g2-gs-parameters.json -- python3 .benchctl-inputs/group-proposals/g2_gs_parameters.py --output g2-gs-parameters.json`.
- Succeeded and fetched to `/Users/samkim/.local/state/benchctl/results/25d1641a8b6c4a9aa334b52327e556b9`.
- The Python calculation does not compile Rust; the recorded profile remains
  Rust 1.98.0 with `RUSTFLAGS=-C target-cpu=native`.

## G13A: G1 trivial and short scalars

Decision: **keep**. Return centered zero and one directly, including the signed order-adjacent cases, and skip whole leading zero limbs in the remaining binary loop. Every measured short, sparse, and near-order class improves with separated favorable intervals in all builds. Random256, random128 and high_sparse control intervals overlap; no row has separated unfavorable intervals. The expanded harness validates 1072 byte fixtures plus length and scalar boundaries against all three implementations. Pairing timing was not repeated because only G1 scalar dispatch and its binary loop changed; shared field and pairing kernels are unchanged. The user requested a pause after this trial.

- Job: `3370f3c32e6849f6aceb178b1fd3afe3`.
- Source fingerprint: `45a9f42c8768aeb84652e3a73848eea0f74874d04d45fd0293701c1179612ac9`.
- Fetched result: `/Users/samkim/.local/state/benchctl/results/3370f3c32e6849f6aceb178b1fd3afe3`.
- CPU 16; 100 samples, 1 s warm-up, 2 s measurement, ABBA.
- `native`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native`.
- `native_scalar`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native -C target-feature=-avx512ifma`.
- `generic`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=x86-64`.

```sh
benchctl submit --json --label bn254-G13A-g1-short --timeout 2h --artifact group-experiment-results -- python3 scripts/benchmark-bn254-groups.py run --id G13A-g1-short --filter 'group_bytes_g1_mul_(random(16|32|48|64|80|128|256)|sparse|high_sparse|near_order|zero|one)/solana-bn254/le$'
```

The job succeeded and `wait` returned zero. All queued correctness checks
completed successfully. Local candidate hashes match fetched metadata.

| Build | Case | Before (µs) | Candidate (µs) | Improvement | Intervals |
| --- | --- | ---: | ---: | ---: | --- |
| native | group_bytes_g1_mul_high_sparse | 34.483 | 34.490 | -0.02% | overlap |
| native | group_bytes_g1_mul_near_order | 1.076 | 0.899 | +16.45% | gain |
| native | group_bytes_g1_mul_one | 0.400 | 0.185 | +53.63% | gain |
| native | group_bytes_g1_mul_random128 | 30.917 | 30.911 | +0.02% | overlap |
| native | group_bytes_g1_mul_random16 | 4.910 | 4.751 | +3.23% | gain |
| native | group_bytes_g1_mul_random256 | 34.031 | 34.021 | +0.03% | overlap |
| native | group_bytes_g1_mul_random32 | 9.064 | 8.895 | +1.86% | gain |
| native | group_bytes_g1_mul_random48 | 12.988 | 12.827 | +1.24% | gain |
| native | group_bytes_g1_mul_random64 | 17.472 | 17.305 | +0.96% | gain |
| native | group_bytes_g1_mul_random80 | 20.157 | 20.135 | +0.11% | gain |
| native | group_bytes_g1_mul_sparse | 20.435 | 20.374 | +0.30% | gain |
| native | group_bytes_g1_mul_zero | 0.384 | 0.175 | +54.42% | gain |
| native_scalar | group_bytes_g1_mul_high_sparse | 34.509 | 34.520 | -0.03% | overlap |
| native_scalar | group_bytes_g1_mul_near_order | 1.059 | 0.891 | +15.86% | gain |
| native_scalar | group_bytes_g1_mul_one | 0.383 | 0.184 | +51.88% | gain |
| native_scalar | group_bytes_g1_mul_random128 | 30.928 | 30.922 | +0.02% | overlap |
| native_scalar | group_bytes_g1_mul_random16 | 4.906 | 4.737 | +3.44% | gain |
| native_scalar | group_bytes_g1_mul_random256 | 34.060 | 34.046 | +0.04% | overlap |
| native_scalar | group_bytes_g1_mul_random32 | 9.069 | 8.894 | +1.93% | gain |
| native_scalar | group_bytes_g1_mul_random48 | 12.997 | 12.826 | +1.31% | gain |
| native_scalar | group_bytes_g1_mul_random64 | 17.490 | 17.315 | +1.00% | gain |
| native_scalar | group_bytes_g1_mul_random80 | 20.163 | 20.128 | +0.17% | gain |
| native_scalar | group_bytes_g1_mul_sparse | 20.443 | 20.387 | +0.27% | gain |
| native_scalar | group_bytes_g1_mul_zero | 0.383 | 0.171 | +55.33% | gain |
| generic | group_bytes_g1_mul_high_sparse | 37.747 | 37.745 | +0.00% | overlap |
| generic | group_bytes_g1_mul_near_order | 1.103 | 0.908 | +17.68% | gain |
| generic | group_bytes_g1_mul_one | 0.377 | 0.171 | +54.50% | gain |
| generic | group_bytes_g1_mul_random128 | 33.712 | 33.698 | +0.04% | overlap |
| generic | group_bytes_g1_mul_random16 | 5.289 | 5.098 | +3.63% | gain |
| generic | group_bytes_g1_mul_random256 | 37.195 | 37.180 | +0.04% | overlap |
| generic | group_bytes_g1_mul_random32 | 9.831 | 9.639 | +1.96% | gain |
| generic | group_bytes_g1_mul_random48 | 14.129 | 13.943 | +1.32% | gain |
| generic | group_bytes_g1_mul_random64 | 19.052 | 18.858 | +1.02% | gain |
| generic | group_bytes_g1_mul_random80 | 21.975 | 21.938 | +0.17% | gain |
| generic | group_bytes_g1_mul_sparse | 21.974 | 21.867 | +0.48% | gain |
| generic | group_bytes_g1_mul_zero | 0.375 | 0.170 | +54.69% | gain |

“Gain”/“loss” means both candidate 95% intervals lie wholly below/above
both baselines. Overlap does not establish equivalence; between-run
variation can also separate intervals for identical code.

## G13B: raw G2 early returns and outlined windows

Decision: **discard**. The combined candidate adds identity/zero/one early returns and prevents mul_raw_window from being inlined. Raw zero and one improve by 94.3–96.6%, saving roughly 0.22–0.28 microseconds. However, native high_sparse regresses 1.13% (0.832 microseconds), scalar random128 loses 0.24% (0.157 microseconds), and generic random128/random16 lose 0.07%/0.09%, all with separated unfavorable intervals. Other timings overlap. Restore the combined change and test only the early returns as a distinct follow-up; forced outlining is not retained.

- Job: `de66bd6d598b4453a6ce2b3258a83afb`.
- Source fingerprint: `22546e8ba837d30a2e8676df5c488e3a16798dad44705f0c13bd8219b47a51ad`.
- Fetched result: `/Users/samkim/.local/state/benchctl/results/de66bd6d598b4453a6ce2b3258a83afb`.
- CPU 16; 100 samples, 1 s warm-up, 2 s measurement, ABBA.
- `native`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native`.
- `native_scalar`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native -C target-feature=-avx512ifma`.
- `generic`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=x86-64`.

```sh
benchctl submit --json --label bn254-G13B-raw-dispatch --timeout 2h --artifact group-experiment-results -- python3 scripts/benchmark-bn254-groups.py run --id G13B-raw-dispatch --filter 'group_kernel_g2_raw_mul(_(random(16|64|128)|sparse|high_sparse|near_order|max|zero|one))?/solana-bn254$|group_bytes_g2_mul_(random256|zero)/solana-bn254/le$'
```

The job succeeded and `wait` returned zero. All queued correctness checks
completed successfully. Local candidate hashes match fetched metadata.

| Build | Case | Before (µs) | Candidate (µs) | Improvement | Intervals |
| --- | --- | ---: | ---: | ---: | --- |
| native | group_bytes_g2_mul_random256 | 90.941 | 91.111 | -0.19% | overlap |
| native | group_bytes_g2_mul_zero | 32.069 | 32.213 | -0.45% | overlap |
| native | group_kernel_g2_raw_mul | 115.517 | 115.448 | +0.06% | overlap |
| native | group_kernel_g2_raw_mul_high_sparse | 73.955 | 74.787 | -1.13% | loss |
| native | group_kernel_g2_raw_mul_max | 76.431 | 76.768 | -0.44% | overlap |
| native | group_kernel_g2_raw_mul_near_order | 108.624 | 108.658 | -0.03% | overlap |
| native | group_kernel_g2_raw_mul_one | 0.240 | 0.014 | +94.31% | gain |
| native | group_kernel_g2_raw_mul_random128 | 56.864 | 56.860 | +0.01% | overlap |
| native | group_kernel_g2_raw_mul_random16 | 9.092 | 9.111 | -0.21% | overlap |
| native | group_kernel_g2_raw_mul_random64 | 35.583 | 35.626 | -0.12% | overlap |
| native | group_kernel_g2_raw_mul_sparse | 34.608 | 34.597 | +0.03% | overlap |
| native | group_kernel_g2_raw_mul_zero | 0.229 | 0.012 | +94.95% | gain |
| native_scalar | group_bytes_g2_mul_random256 | 101.277 | 101.032 | +0.24% | overlap |
| native_scalar | group_bytes_g2_mul_zero | 36.949 | 36.950 | -0.00% | overlap |
| native_scalar | group_kernel_g2_raw_mul | 133.909 | 134.180 | -0.20% | overlap |
| native_scalar | group_kernel_g2_raw_mul_high_sparse | 93.124 | 93.100 | +0.03% | overlap |
| native_scalar | group_kernel_g2_raw_mul_max | 96.185 | 96.257 | -0.07% | overlap |
| native_scalar | group_kernel_g2_raw_mul_near_order | 128.007 | 127.387 | +0.48% | overlap |
| native_scalar | group_kernel_g2_raw_mul_one | 0.290 | 0.013 | +95.44% | gain |
| native_scalar | group_kernel_g2_raw_mul_random128 | 66.524 | 66.681 | -0.24% | loss |
| native_scalar | group_kernel_g2_raw_mul_random16 | 10.198 | 10.194 | +0.04% | overlap |
| native_scalar | group_kernel_g2_raw_mul_random64 | 40.285 | 40.301 | -0.04% | overlap |
| native_scalar | group_kernel_g2_raw_mul_sparse | 43.749 | 43.753 | -0.01% | overlap |
| native_scalar | group_kernel_g2_raw_mul_zero | 0.279 | 0.012 | +95.75% | gain |
| generic | group_bytes_g2_mul_random256 | 105.841 | 105.742 | +0.09% | overlap |
| generic | group_bytes_g2_mul_zero | 39.006 | 39.004 | +0.00% | overlap |
| generic | group_kernel_g2_raw_mul | 143.277 | 143.279 | -0.00% | overlap |
| generic | group_kernel_g2_raw_mul_high_sparse | 100.032 | 99.934 | +0.10% | overlap |
| generic | group_kernel_g2_raw_mul_max | 103.114 | 103.218 | -0.10% | overlap |
| generic | group_kernel_g2_raw_mul_near_order | 136.016 | 136.017 | -0.00% | overlap |
| generic | group_kernel_g2_raw_mul_one | 0.258 | 0.009 | +96.55% | gain |
| generic | group_kernel_g2_raw_mul_random128 | 70.557 | 70.606 | -0.07% | loss |
| generic | group_kernel_g2_raw_mul_random16 | 10.687 | 10.697 | -0.09% | loss |
| generic | group_kernel_g2_raw_mul_random64 | 42.435 | 42.433 | +0.01% | overlap |
| generic | group_kernel_g2_raw_mul_sparse | 46.799 | 46.794 | +0.01% | overlap |
| generic | group_kernel_g2_raw_mul_zero | 0.250 | 0.009 | +96.51% | gain |

“Gain”/“loss” means both candidate 95% intervals lie wholly below/above
both baselines. Overlap does not establish equivalence; between-run
variation can also separate intervals for identical code.

## G13B2: isolated raw G2 trivial-input returns

Decision: **keep**. Keep only the identity/zero/one early returns; retain the original inlining behavior. Raw zero and one improve 94.2–96.3%, saving about 0.22–0.28 microseconds. All native and native-scalar nontrivial/control intervals overlap, including the previously regressing high_sparse path. Generic random128 has a small separated cost of 0.075% (53 ns), accepted alongside the substantially larger trivial-input savings; generic checked random256 gains 0.15% with separated intervals and other generic controls overlap. No shared field or pairing kernel changes. Recheck varied inputs in final confirmation.

- Job: `4c053ae1ac71471fbcbf635f08d077b1`.
- Source fingerprint: `915b159a66ffbf0659d263b7c9deb09e3c6185d84d619726d9ee7cdf4534fcef`.
- Fetched result: `/Users/samkim/.local/state/benchctl/results/4c053ae1ac71471fbcbf635f08d077b1`.
- CPU 16; 100 samples, 1 s warm-up, 2 s measurement, ABBA.
- `native`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native`.
- `native_scalar`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native -C target-feature=-avx512ifma`.
- `generic`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=x86-64`.

```sh
benchctl submit --json --label bn254-G13B2-raw-trivial --timeout 2h --artifact group-experiment-results -- python3 scripts/benchmark-bn254-groups.py run --id G13B2-raw-trivial --filter 'group_kernel_g2_raw_mul(_(random(16|64|128)|sparse|high_sparse|near_order|max|zero|one))?/solana-bn254$|group_bytes_g2_mul_(random256|zero)/solana-bn254/le$'
```

The job succeeded and `wait` returned zero. All queued correctness checks
completed successfully. Local candidate hashes match fetched metadata.

| Build | Case | Before (µs) | Candidate (µs) | Improvement | Intervals |
| --- | --- | ---: | ---: | ---: | --- |
| native | group_bytes_g2_mul_random256 | 90.954 | 90.944 | +0.01% | overlap |
| native | group_bytes_g2_mul_zero | 32.101 | 32.084 | +0.05% | overlap |
| native | group_kernel_g2_raw_mul | 115.226 | 115.413 | -0.16% | overlap |
| native | group_kernel_g2_raw_mul_high_sparse | 73.904 | 74.140 | -0.32% | overlap |
| native | group_kernel_g2_raw_mul_max | 76.434 | 76.420 | +0.02% | overlap |
| native | group_kernel_g2_raw_mul_near_order | 108.574 | 108.724 | -0.14% | overlap |
| native | group_kernel_g2_raw_mul_one | 0.240 | 0.014 | +94.21% | gain |
| native | group_kernel_g2_raw_mul_random128 | 56.913 | 56.845 | +0.12% | overlap |
| native | group_kernel_g2_raw_mul_random16 | 9.088 | 9.096 | -0.09% | overlap |
| native | group_kernel_g2_raw_mul_random64 | 35.590 | 35.589 | +0.00% | overlap |
| native | group_kernel_g2_raw_mul_sparse | 34.599 | 34.584 | +0.04% | overlap |
| native | group_kernel_g2_raw_mul_zero | 0.229 | 0.013 | +94.38% | gain |
| native_scalar | group_bytes_g2_mul_random256 | 100.396 | 100.416 | -0.02% | overlap |
| native_scalar | group_bytes_g2_mul_zero | 36.937 | 36.951 | -0.04% | overlap |
| native_scalar | group_kernel_g2_raw_mul | 133.940 | 133.724 | +0.16% | overlap |
| native_scalar | group_kernel_g2_raw_mul_high_sparse | 93.337 | 93.090 | +0.26% | overlap |
| native_scalar | group_kernel_g2_raw_mul_max | 96.119 | 96.069 | +0.05% | overlap |
| native_scalar | group_kernel_g2_raw_mul_near_order | 127.080 | 127.165 | -0.07% | overlap |
| native_scalar | group_kernel_g2_raw_mul_one | 0.289 | 0.014 | +95.14% | gain |
| native_scalar | group_kernel_g2_raw_mul_random128 | 66.508 | 66.510 | -0.00% | overlap |
| native_scalar | group_kernel_g2_raw_mul_random16 | 10.188 | 10.194 | -0.06% | overlap |
| native_scalar | group_kernel_g2_raw_mul_random64 | 40.274 | 40.274 | +0.00% | overlap |
| native_scalar | group_kernel_g2_raw_mul_sparse | 43.768 | 43.742 | +0.06% | overlap |
| native_scalar | group_kernel_g2_raw_mul_zero | 0.278 | 0.012 | +95.62% | gain |
| generic | group_bytes_g2_mul_random256 | 105.950 | 105.792 | +0.15% | gain |
| generic | group_bytes_g2_mul_zero | 38.988 | 39.000 | -0.03% | overlap |
| generic | group_kernel_g2_raw_mul | 143.181 | 143.141 | +0.03% | overlap |
| generic | group_kernel_g2_raw_mul_high_sparse | 99.960 | 99.955 | +0.01% | overlap |
| generic | group_kernel_g2_raw_mul_max | 102.975 | 103.126 | -0.15% | overlap |
| generic | group_kernel_g2_raw_mul_near_order | 136.010 | 136.015 | -0.00% | overlap |
| generic | group_kernel_g2_raw_mul_one | 0.258 | 0.010 | +96.32% | gain |
| generic | group_kernel_g2_raw_mul_random128 | 70.499 | 70.552 | -0.07% | loss |
| generic | group_kernel_g2_raw_mul_random16 | 10.689 | 10.682 | +0.06% | overlap |
| generic | group_kernel_g2_raw_mul_random64 | 42.420 | 42.415 | +0.01% | overlap |
| generic | group_kernel_g2_raw_mul_sparse | 46.767 | 46.790 | -0.05% | overlap |
| generic | group_kernel_g2_raw_mul_zero | 0.249 | 0.010 | +96.18% | gain |

“Gain”/“loss” means both candidate 95% intervals lie wholly below/above
both baselines. Overlap does not establish equivalence; between-run
variation can also separate intervals for identical code.

## G13C: conditional width-5 G1 windows

Decision: **keep**. Select width 5 only for dense centered scalars wider than 192 bits, keeping width 4 below that cutoff. Random256 improves 0.62/1.24/0.95% for native/scalar/generic, random224 improves 0.70–1.32%, maximum improves 1.25–1.70%, and high_sparse improves 2.86–3.37%; all have separated favorable intervals. Accept small separated control costs: native random192/random64/sparse lose 28/23/19 ns; generic sparse loses 30 ns, near-order 8 ns, one 1.4 ns and zero 2.7 ns. Other controls overlap or improve. All table construction remains inside timing. Shared field and pairing kernels are unchanged.

- Job: `e8a82f2e28b64d9f87ce7aab1b6cce2e`.
- Source fingerprint: `0fd5283f97c733e4a032a57b507504e7bc0567dc2038b4c021e1e20248c8ded3`.
- Fetched result: `/Users/samkim/.local/state/benchctl/results/e8a82f2e28b64d9f87ce7aab1b6cce2e`.
- CPU 16; 100 samples, 1 s warm-up, 2 s measurement, ABBA.
- `native`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native`.
- `native_scalar`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native -C target-feature=-avx512ifma`.
- `generic`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=x86-64`.

```sh
benchctl submit --json --label bn254-G13C-g1-long-window --timeout 2h --artifact group-experiment-results -- python3 scripts/benchmark-bn254-groups.py run --id G13C-g1-long-window --filter 'group_bytes_g1_mul_(random(64|96|128|192|224|256)|max|high_sparse|sparse|near_order|zero|one)/solana-bn254/le$'
```

The job succeeded and `wait` returned zero. All queued correctness checks
completed successfully. Local candidate hashes match fetched metadata.

| Build | Case | Before (µs) | Candidate (µs) | Improvement | Intervals |
| --- | --- | ---: | ---: | ---: | --- |
| native | group_bytes_g1_mul_high_sparse | 34.482 | 33.495 | +2.86% | gain |
| native | group_bytes_g1_mul_max | 34.130 | 33.704 | +1.25% | gain |
| native | group_bytes_g1_mul_near_order | 0.901 | 0.904 | -0.34% | overlap |
| native | group_bytes_g1_mul_one | 0.188 | 0.185 | +1.43% | overlap |
| native | group_bytes_g1_mul_random128 | 30.910 | 30.920 | -0.03% | overlap |
| native | group_bytes_g1_mul_random192 | 34.095 | 34.124 | -0.08% | loss |
| native | group_bytes_g1_mul_random224 | 34.243 | 34.002 | +0.70% | gain |
| native | group_bytes_g1_mul_random256 | 34.023 | 33.812 | +0.62% | gain |
| native | group_bytes_g1_mul_random64 | 17.306 | 17.329 | -0.13% | loss |
| native | group_bytes_g1_mul_random96 | 22.195 | 22.192 | +0.02% | overlap |
| native | group_bytes_g1_mul_sparse | 20.371 | 20.390 | -0.09% | loss |
| native | group_bytes_g1_mul_zero | 0.175 | 0.172 | +1.96% | overlap |
| native_scalar | group_bytes_g1_mul_high_sparse | 34.604 | 33.438 | +3.37% | gain |
| native_scalar | group_bytes_g1_mul_max | 34.240 | 33.659 | +1.70% | gain |
| native_scalar | group_bytes_g1_mul_near_order | 0.891 | 0.888 | +0.39% | gain |
| native_scalar | group_bytes_g1_mul_one | 0.184 | 0.184 | +0.04% | overlap |
| native_scalar | group_bytes_g1_mul_random128 | 31.006 | 30.890 | +0.37% | gain |
| native_scalar | group_bytes_g1_mul_random192 | 34.200 | 34.069 | +0.38% | gain |
| native_scalar | group_bytes_g1_mul_random224 | 34.349 | 33.896 | +1.32% | gain |
| native_scalar | group_bytes_g1_mul_random256 | 34.137 | 33.714 | +1.24% | gain |
| native_scalar | group_bytes_g1_mul_random64 | 17.352 | 17.315 | +0.21% | overlap |
| native_scalar | group_bytes_g1_mul_random96 | 22.278 | 22.196 | +0.37% | gain |
| native_scalar | group_bytes_g1_mul_sparse | 20.435 | 20.379 | +0.27% | overlap |
| native_scalar | group_bytes_g1_mul_zero | 0.170 | 0.171 | -1.00% | overlap |
| generic | group_bytes_g1_mul_high_sparse | 37.746 | 36.531 | +3.22% | gain |
| generic | group_bytes_g1_mul_max | 37.333 | 36.759 | +1.54% | gain |
| generic | group_bytes_g1_mul_near_order | 0.907 | 0.915 | -0.85% | loss |
| generic | group_bytes_g1_mul_one | 0.172 | 0.173 | -0.83% | loss |
| generic | group_bytes_g1_mul_random128 | 33.721 | 33.710 | +0.03% | overlap |
| generic | group_bytes_g1_mul_random192 | 37.280 | 37.299 | -0.05% | overlap |
| generic | group_bytes_g1_mul_random224 | 37.409 | 37.056 | +0.94% | gain |
| generic | group_bytes_g1_mul_random256 | 37.193 | 36.840 | +0.95% | gain |
| generic | group_bytes_g1_mul_random64 | 18.868 | 18.838 | +0.16% | gain |
| generic | group_bytes_g1_mul_random96 | 24.135 | 24.143 | -0.03% | overlap |
| generic | group_bytes_g1_mul_sparse | 21.835 | 21.865 | -0.14% | loss |
| generic | group_bytes_g1_mul_zero | 0.170 | 0.173 | -1.59% | loss |

“Gain”/“loss” means both candidate 95% intervals lie wholly below/above
both baselines. Overlap does not establish equivalence; between-run
variation can also separate intervals for identical code.

## G13D: lower the checked-G2 GS cutoff

Decision: **keep**. Use the retained four-way joint-pair multiplication for dense scalars wider than 128 bits, instead of wider than 192 bits. The popcount guard and prior subgroup validation remain mandatory. Exact129 improves 5.74/9.13/9.87% for native/scalar/generic; random144–192 improve 4.97–11.49%, 8.63–13.94%, and 9.46–14.72% respectively. Every newly selected class has separated favorable intervals in all builds. Controls overlap except small generic random256 and zero gains; no row has separated unfavorable intervals. Arithmetic and pairing kernels are unchanged.

- Job: `847d73ee68d54c48962c8a101af029a4`.
- Source fingerprint: `9139d8eff610d68db9952aef4d27c6364f28a7700e81b625f46a51697186dd0a`.
- Fetched result: `/Users/samkim/.local/state/benchctl/results/847d73ee68d54c48962c8a101af029a4`.
- CPU 16; 100 samples, 1 s warm-up, 2 s measurement, ABBA.
- `native`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native`.
- `native_scalar`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native -C target-feature=-avx512ifma`.
- `generic`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=x86-64`.

```sh
benchctl submit --json --label bn254-G13D-gs-cutoff --timeout 2h --artifact group-experiment-results -- python3 scripts/benchmark-bn254-groups.py run --id G13D-gs-cutoff --filter 'group_bytes_g2_mul_(random(64|96|128|144|160|176|192|256)|exact129|sparse|high_sparse|zero)/solana-bn254/le$'
```

The job succeeded and `wait` returned zero. All queued correctness checks
completed successfully. Local candidate hashes match fetched metadata.

| Build | Case | Before (µs) | Candidate (µs) | Improvement | Intervals |
| --- | --- | ---: | ---: | ---: | --- |
| native | group_bytes_g2_mul_exact129 | 95.850 | 90.346 | +5.74% | gain |
| native | group_bytes_g2_mul_high_sparse | 108.753 | 109.138 | -0.35% | overlap |
| native | group_bytes_g2_mul_random128 | 94.533 | 94.577 | -0.05% | overlap |
| native | group_bytes_g2_mul_random144 | 97.608 | 92.756 | +4.97% | gain |
| native | group_bytes_g2_mul_random160 | 99.469 | 92.005 | +7.50% | gain |
| native | group_bytes_g2_mul_random176 | 100.476 | 90.945 | +9.49% | gain |
| native | group_bytes_g2_mul_random192 | 103.398 | 91.515 | +11.49% | gain |
| native | group_bytes_g2_mul_random256 | 90.960 | 90.942 | +0.02% | overlap |
| native | group_bytes_g2_mul_random64 | 67.531 | 67.503 | +0.04% | overlap |
| native | group_bytes_g2_mul_random96 | 75.423 | 75.447 | -0.03% | overlap |
| native | group_bytes_g2_mul_sparse | 66.841 | 66.859 | -0.03% | overlap |
| native | group_bytes_g2_mul_zero | 32.083 | 32.095 | -0.04% | overlap |
| native_scalar | group_bytes_g2_mul_exact129 | 109.824 | 99.802 | +9.12% | gain |
| native_scalar | group_bytes_g2_mul_high_sparse | 122.655 | 122.679 | -0.02% | overlap |
| native_scalar | group_bytes_g2_mul_random128 | 108.701 | 108.795 | -0.09% | overlap |
| native_scalar | group_bytes_g2_mul_random144 | 111.682 | 102.047 | +8.63% | gain |
| native_scalar | group_bytes_g2_mul_random160 | 113.607 | 101.454 | +10.70% | gain |
| native_scalar | group_bytes_g2_mul_random176 | 114.451 | 100.406 | +12.27% | gain |
| native_scalar | group_bytes_g2_mul_random192 | 117.340 | 100.984 | +13.94% | gain |
| native_scalar | group_bytes_g2_mul_random256 | 100.372 | 100.351 | +0.02% | overlap |
| native_scalar | group_bytes_g2_mul_random64 | 77.043 | 77.028 | +0.02% | overlap |
| native_scalar | group_bytes_g2_mul_random96 | 87.484 | 87.498 | -0.02% | overlap |
| native_scalar | group_bytes_g2_mul_sparse | 80.866 | 80.901 | -0.04% | overlap |
| native_scalar | group_bytes_g2_mul_zero | 36.948 | 36.935 | +0.03% | overlap |
| generic | group_bytes_g2_mul_exact129 | 116.506 | 105.004 | +9.87% | gain |
| generic | group_bytes_g2_mul_high_sparse | 130.061 | 129.985 | +0.06% | overlap |
| generic | group_bytes_g2_mul_random128 | 115.466 | 115.291 | +0.15% | overlap |
| generic | group_bytes_g2_mul_random144 | 118.679 | 107.453 | +9.46% | gain |
| generic | group_bytes_g2_mul_random160 | 120.660 | 106.774 | +11.51% | gain |
| generic | group_bytes_g2_mul_random176 | 121.735 | 105.682 | +13.19% | gain |
| generic | group_bytes_g2_mul_random192 | 124.560 | 106.223 | +14.72% | gain |
| generic | group_bytes_g2_mul_random256 | 105.833 | 105.697 | +0.13% | gain |
| generic | group_bytes_g2_mul_random64 | 81.268 | 81.245 | +0.03% | overlap |
| generic | group_bytes_g2_mul_random96 | 92.638 | 92.567 | +0.08% | overlap |
| generic | group_bytes_g2_mul_sparse | 86.092 | 86.102 | -0.01% | overlap |
| generic | group_bytes_g2_mul_zero | 39.002 | 38.971 | +0.08% | gain |

“Gain”/“loss” means both candidate 95% intervals lie wholly below/above
both baselines. Overlap does not establish equivalence; between-run
variation can also separate intervals for identical code.

## G13E: conditional raw G2 windows

Decision: **keep**. Keep conditional raw-G2 widths: after the existing >=96-bit / >32-set-bit guard, retain width 3 when popcount(s ^ (s >> 1)) <= 32; otherwise select width 5 above 192 bits and width 4 below. The full U256 is preserved on the entire twist, and G13B2 early returns remain; no forced outlining was reintroduced. Raw random256 improves 7.011% / 6.019% / 5.612% (native IFMA / native scalar / generic), saving about 8.0–8.1 us. Random96/112/128/144/192 and near-order classes also have separated favorable intervals in all three builds. Native configurations have no separated regression rows. Accept small separated generic costs: checked random256 +237.494 ns (0.225%), MAX +83.337 ns (0.081%), ones-runs +178.534 ns (0.247%), and raw zero/one +0.262/+0.266 ns (2.756%/2.799%). These costs are explicitly retained in exchange for the repeatable dense-scalar gains; unchanged source paths alone do not establish timing equivalence. All 45 group rows are recorded below. All three configurations passed queued correctness checks, including cross-implementation fixtures and independent raw full-twist oracles. Pairing was not timed in this raw-dispatch trial. The selector is a measured heuristic, not a proof of globally optimal cutoffs. Paused at the user request after this decision; G13F has not started.

- Job: `22c00201a18d4acca670530a598be886`.
- Source fingerprint: `8d3c44eec315c56c9705a879cfbd1796b3d5cb7876893fb50927f13529517764`.
- Fetched result: `/Users/samkim/.local/state/benchctl/results/22c00201a18d4acca670530a598be886`.
- CPU 16; 100 samples, 1 s warm-up, 2 s measurement, ABBA.
- `native`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native`.
- `native_scalar`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native -C target-feature=-avx512ifma`.
- `generic`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=x86-64`.

```sh
benchctl submit --json --label bn254-G13E-raw-widths --timeout 2h --artifact group-experiment-results -- python3 scripts/benchmark-bn254-groups.py run --id G13E-raw-widths --filter 'group_kernel_g2_raw_mul(_(random(64|96|112|128|144|192)|near_order|max|ones_runs|sparse|high_sparse|zero|one))?/solana-bn254$|group_bytes_g2_mul_random256/solana-bn254/le$'
```

The job succeeded and `wait` returned zero. All queued correctness checks
completed successfully. Local candidate hashes match fetched metadata.

| Build | Case | Before (µs) | Candidate (µs) | Improvement | Intervals |
| --- | --- | ---: | ---: | ---: | --- |
| native | group_bytes_g2_mul_random256 | 90.949 | 91.177 | -0.25% | overlap |
| native | group_kernel_g2_raw_mul | 115.545 | 107.444 | +7.01% | gain |
| native | group_kernel_g2_raw_mul_high_sparse | 73.883 | 73.570 | +0.42% | overlap |
| native | group_kernel_g2_raw_mul_max | 76.253 | 76.349 | -0.13% | overlap |
| native | group_kernel_g2_raw_mul_near_order | 108.381 | 103.756 | +4.27% | gain |
| native | group_kernel_g2_raw_mul_one | 0.014 | 0.014 | -6.61% | overlap |
| native | group_kernel_g2_raw_mul_ones_runs | 53.906 | 53.859 | +0.09% | overlap |
| native | group_kernel_g2_raw_mul_random112 | 49.845 | 48.743 | +2.21% | gain |
| native | group_kernel_g2_raw_mul_random128 | 56.865 | 55.174 | +2.97% | gain |
| native | group_kernel_g2_raw_mul_random144 | 63.516 | 61.330 | +3.44% | gain |
| native | group_kernel_g2_raw_mul_random192 | 83.881 | 80.070 | +4.54% | gain |
| native | group_kernel_g2_raw_mul_random64 | 35.654 | 35.635 | +0.05% | overlap |
| native | group_kernel_g2_raw_mul_random96 | 45.240 | 44.708 | +1.18% | gain |
| native | group_kernel_g2_raw_mul_sparse | 34.744 | 34.613 | +0.38% | overlap |
| native | group_kernel_g2_raw_mul_zero | 0.012 | 0.012 | +2.23% | overlap |
| native_scalar | group_bytes_g2_mul_random256 | 100.392 | 100.336 | +0.06% | gain |
| native_scalar | group_kernel_g2_raw_mul | 134.012 | 125.947 | +6.02% | gain |
| native_scalar | group_kernel_g2_raw_mul_high_sparse | 93.035 | 93.415 | -0.41% | overlap |
| native_scalar | group_kernel_g2_raw_mul_max | 96.410 | 96.030 | +0.39% | gain |
| native_scalar | group_kernel_g2_raw_mul_near_order | 127.669 | 122.723 | +3.87% | gain |
| native_scalar | group_kernel_g2_raw_mul_one | 0.014 | 0.014 | -2.02% | overlap |
| native_scalar | group_kernel_g2_raw_mul_ones_runs | 67.788 | 67.653 | +0.20% | overlap |
| native_scalar | group_kernel_g2_raw_mul_random112 | 58.397 | 57.161 | +2.12% | gain |
| native_scalar | group_kernel_g2_raw_mul_random128 | 66.690 | 64.842 | +2.77% | gain |
| native_scalar | group_kernel_g2_raw_mul_random144 | 74.491 | 72.104 | +3.20% | gain |
| native_scalar | group_kernel_g2_raw_mul_random192 | 98.440 | 94.471 | +4.03% | gain |
| native_scalar | group_kernel_g2_raw_mul_random64 | 40.289 | 40.295 | -0.01% | overlap |
| native_scalar | group_kernel_g2_raw_mul_random96 | 52.481 | 51.893 | +1.12% | gain |
| native_scalar | group_kernel_g2_raw_mul_sparse | 43.768 | 43.763 | +0.01% | overlap |
| native_scalar | group_kernel_g2_raw_mul_zero | 0.012 | 0.012 | +1.68% | overlap |
| generic | group_bytes_g2_mul_random256 | 105.614 | 105.851 | -0.22% | loss |
| generic | group_kernel_g2_raw_mul | 143.010 | 134.984 | +5.61% | gain |
| generic | group_kernel_g2_raw_mul_high_sparse | 100.049 | 99.917 | +0.13% | gain |
| generic | group_kernel_g2_raw_mul_max | 103.092 | 103.175 | -0.08% | loss |
| generic | group_kernel_g2_raw_mul_near_order | 135.791 | 131.040 | +3.50% | gain |
| generic | group_kernel_g2_raw_mul_one | 0.010 | 0.010 | -2.80% | loss |
| generic | group_kernel_g2_raw_mul_ones_runs | 72.260 | 72.439 | -0.25% | loss |
| generic | group_kernel_g2_raw_mul_random112 | 61.754 | 60.624 | +1.83% | gain |
| generic | group_kernel_g2_raw_mul_random128 | 70.502 | 68.826 | +2.38% | gain |
| generic | group_kernel_g2_raw_mul_random144 | 78.729 | 76.579 | +2.73% | gain |
| generic | group_kernel_g2_raw_mul_random192 | 104.293 | 100.501 | +3.64% | gain |
| generic | group_kernel_g2_raw_mul_random64 | 42.469 | 42.411 | +0.14% | gain |
| generic | group_kernel_g2_raw_mul_random96 | 55.458 | 54.952 | +0.91% | gain |
| generic | group_kernel_g2_raw_mul_sparse | 46.832 | 46.775 | +0.12% | gain |
| generic | group_kernel_g2_raw_mul_zero | 0.010 | 0.010 | -2.76% | loss |

“Gain”/“loss” means both candidate 95% intervals lie wholly below/above
both baselines. Overlap does not establish equivalence; between-run
variation can also separate intervals for identical code.

## G13F: G1 scalar centering selection

Decision: **discard**. Discard the G1 scalar-representative selector. The intended high-bit sparse cases regress consistently: high_sparse is 8.085% / 8.431% / 8.378% slower and sparse256 is 8.107% / 8.402% / 8.354% slower (native IFMA / native scalar / generic), with separated intervals in every build. This adds about 2.7–3.1 us per call relative to the retained centered/windowed implementation. The binary-work estimate therefore fails to choose the faster complete path on these inputs. Random256 also has separated losses of 0.187% native and 0.501% native scalar; generic overlaps. Small near-order gains in the native builds do not offset the sparse regressions. All 48 group rows and correctness checks completed; no pairing timings were requested. Restore only the checkpointed g1.rs, preserving G13C and all previously retained work. No centering follow-up is added to the remaining sequence.

- Job: `ba919ec1d28c4374bd36b71a236784db`.
- Source fingerprint: `644678f3fa4034773f5b6c6b77c3e0d11327fd6882c39ebcf328bbecfdceaf71`.
- Fetched result: `/Users/samkim/.local/state/benchctl/results/ba919ec1d28c4374bd36b71a236784db`.
- CPU 16; 100 samples, 1 s warm-up, 2 s measurement, ABBA.
- `native`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native`.
- `native_scalar`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native -C target-feature=-avx512ifma`.
- `generic`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=x86-64`.

```sh
benchctl submit --json --label bn254-G13F-g1-centering --timeout 2h --artifact group-experiment-results -- python3 scripts/benchmark-bn254-groups.py run --id G13F-g1-centering --filter 'group_bytes_g1_mul_(random(128|144|192|224|256)|exact129|sparse(128|192|256)?|high_sparse|ones_runs|near_order|max|zero|one)/solana-bn254/le$'
```

The job succeeded and `wait` returned zero. All queued correctness checks
completed successfully. Local candidate hashes match fetched metadata.

| Build | Case | Before (µs) | Candidate (µs) | Improvement | Intervals |
| --- | --- | ---: | ---: | ---: | --- |
| native | group_bytes_g1_mul_exact129 | 31.361 | 31.384 | -0.07% | loss |
| native | group_bytes_g1_mul_high_sparse | 33.456 | 36.161 | -8.09% | loss |
| native | group_bytes_g1_mul_max | 33.665 | 33.649 | +0.05% | overlap |
| native | group_bytes_g1_mul_near_order | 0.901 | 0.892 | +0.96% | gain |
| native | group_bytes_g1_mul_one | 0.185 | 0.186 | -0.49% | overlap |
| native | group_bytes_g1_mul_ones_runs | 29.915 | 29.926 | -0.04% | overlap |
| native | group_bytes_g1_mul_random128 | 30.946 | 30.956 | -0.03% | overlap |
| native | group_bytes_g1_mul_random144 | 32.054 | 32.058 | -0.01% | overlap |
| native | group_bytes_g1_mul_random192 | 34.137 | 34.166 | -0.09% | loss |
| native | group_bytes_g1_mul_random224 | 33.931 | 33.923 | +0.02% | overlap |
| native | group_bytes_g1_mul_random256 | 33.748 | 33.811 | -0.19% | loss |
| native | group_bytes_g1_mul_sparse | 20.438 | 20.391 | +0.23% | gain |
| native | group_bytes_g1_mul_sparse128 | 21.765 | 21.760 | +0.02% | overlap |
| native | group_bytes_g1_mul_sparse192 | 32.415 | 32.412 | +0.01% | overlap |
| native | group_bytes_g1_mul_sparse256 | 33.452 | 36.164 | -8.11% | loss |
| native | group_bytes_g1_mul_zero | 0.171 | 0.172 | -0.89% | overlap |
| native_scalar | group_bytes_g1_mul_exact129 | 31.395 | 31.510 | -0.37% | overlap |
| native_scalar | group_bytes_g1_mul_high_sparse | 33.471 | 36.293 | -8.43% | loss |
| native_scalar | group_bytes_g1_mul_max | 33.671 | 33.806 | -0.40% | loss |
| native_scalar | group_bytes_g1_mul_near_order | 0.901 | 0.886 | +1.66% | gain |
| native_scalar | group_bytes_g1_mul_one | 0.188 | 0.182 | +2.80% | overlap |
| native_scalar | group_bytes_g1_mul_ones_runs | 29.941 | 30.055 | -0.38% | overlap |
| native_scalar | group_bytes_g1_mul_random128 | 30.966 | 31.074 | -0.35% | overlap |
| native_scalar | group_bytes_g1_mul_random144 | 32.070 | 32.185 | -0.36% | overlap |
| native_scalar | group_bytes_g1_mul_random192 | 34.185 | 34.273 | -0.26% | overlap |
| native_scalar | group_bytes_g1_mul_random224 | 33.961 | 34.090 | -0.38% | loss |
| native_scalar | group_bytes_g1_mul_random256 | 33.801 | 33.970 | -0.50% | loss |
| native_scalar | group_bytes_g1_mul_sparse | 20.436 | 20.524 | -0.43% | overlap |
| native_scalar | group_bytes_g1_mul_sparse128 | 21.801 | 21.903 | -0.47% | overlap |
| native_scalar | group_bytes_g1_mul_sparse192 | 32.484 | 32.636 | -0.47% | overlap |
| native_scalar | group_bytes_g1_mul_sparse256 | 33.476 | 36.288 | -8.40% | loss |
| native_scalar | group_bytes_g1_mul_zero | 0.174 | 0.168 | +3.07% | overlap |
| generic | group_bytes_g1_mul_exact129 | 34.127 | 34.139 | -0.04% | overlap |
| generic | group_bytes_g1_mul_high_sparse | 36.505 | 39.563 | -8.38% | loss |
| generic | group_bytes_g1_mul_max | 36.756 | 36.725 | +0.08% | overlap |
| generic | group_bytes_g1_mul_near_order | 0.917 | 0.920 | -0.33% | overlap |
| generic | group_bytes_g1_mul_one | 0.177 | 0.174 | +1.54% | overlap |
| generic | group_bytes_g1_mul_ones_runs | 32.559 | 32.551 | +0.02% | overlap |
| generic | group_bytes_g1_mul_random128 | 33.698 | 33.698 | -0.00% | overlap |
| generic | group_bytes_g1_mul_random144 | 34.938 | 34.932 | +0.02% | overlap |
| generic | group_bytes_g1_mul_random192 | 37.253 | 37.258 | -0.01% | overlap |
| generic | group_bytes_g1_mul_random224 | 37.040 | 36.993 | +0.13% | gain |
| generic | group_bytes_g1_mul_random256 | 36.832 | 36.867 | -0.09% | overlap |
| generic | group_bytes_g1_mul_sparse | 21.869 | 21.869 | +0.00% | overlap |
| generic | group_bytes_g1_mul_sparse128 | 23.346 | 23.363 | -0.07% | loss |
| generic | group_bytes_g1_mul_sparse192 | 34.795 | 34.847 | -0.15% | loss |
| generic | group_bytes_g1_mul_sparse256 | 36.513 | 39.563 | -8.35% | loss |
| generic | group_bytes_g1_mul_zero | 0.175 | 0.173 | +1.26% | overlap |

“Gain”/“loss” means both candidate 95% intervals lie wholly below/above
both baselines. Overlap does not establish equivalence; between-run
variation can also separate intervals for identical code.

## G13G: G1 setup-cost estimate

Decision: **keep**. Keep the group-specific setup parameter with G1 at 40 and G2 unchanged at 100. Complete G1 random80 multiplication improves 1.747% / 1.786% / 1.798% (native IFMA / native scalar / generic), with both candidate intervals below both baselines in all three builds, saving about 0.35–0.39 us. Random64/128/256 and the G2 random256 control overlap in every build. Accept smaller separated control costs: native sparse/sparse192/sparse256 (0.337%/0.188%/0.124%); scalar sparse/near-order/one/zero (0.228%/0.427%/2.581%/4.265%); generic random96/sparse (0.074%/0.227%). The sparse costs are at most about 69 ns; the largest trivial-input cost is about 7 ns. All 42 group rows were collected, and queued correctness checks passed. The lower setup weight is a measured selector heuristic for the retained common-denominator implementation, not a universal operation-latency estimate. Pairing was not timed for this dispatch-only trial.

- Job: `a5b05d7de86343bf970d6309e6812336`.
- Source fingerprint: `a068311476abe630b12fe94eb01d5acaa62fc4eba1c8d623d7f75dd4bc790256`.
- Fetched result: `/Users/samkim/.local/state/benchctl/results/a5b05d7de86343bf970d6309e6812336`.
- CPU 16; 100 samples, 1 s warm-up, 2 s measurement, ABBA.
- `native`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native`.
- `native_scalar`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native -C target-feature=-avx512ifma`.
- `generic`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=x86-64`.

```sh
benchctl submit --json --label bn254-G13G-g1-setup --timeout 2h --artifact group-experiment-results -- python3 scripts/benchmark-bn254-groups.py run --id G13G-g1-setup --filter 'group_bytes_g1_mul_(random(64|80|96|128|256)|sparse(128|192|256)?|high_sparse|near_order|zero|one)/solana-bn254/le$|group_bytes_g2_mul_random256/solana-bn254/le$'
```

The job succeeded and `wait` returned zero. All queued correctness checks
completed successfully. Local candidate hashes match fetched metadata.

| Build | Case | Before (µs) | Candidate (µs) | Improvement | Intervals |
| --- | --- | ---: | ---: | ---: | --- |
| native | group_bytes_g1_mul_high_sparse | 33.460 | 33.491 | -0.09% | overlap |
| native | group_bytes_g1_mul_near_order | 0.901 | 0.901 | +0.06% | overlap |
| native | group_bytes_g1_mul_one | 0.186 | 0.185 | +0.55% | overlap |
| native | group_bytes_g1_mul_random128 | 30.946 | 30.948 | -0.01% | overlap |
| native | group_bytes_g1_mul_random256 | 33.773 | 33.799 | -0.08% | overlap |
| native | group_bytes_g1_mul_random64 | 17.340 | 17.340 | -0.00% | overlap |
| native | group_bytes_g1_mul_random80 | 20.134 | 19.782 | +1.75% | gain |
| native | group_bytes_g1_mul_random96 | 22.207 | 22.216 | -0.04% | overlap |
| native | group_bytes_g1_mul_sparse | 20.380 | 20.449 | -0.34% | loss |
| native | group_bytes_g1_mul_sparse128 | 21.744 | 21.767 | -0.11% | overlap |
| native | group_bytes_g1_mul_sparse192 | 32.392 | 32.453 | -0.19% | loss |
| native | group_bytes_g1_mul_sparse256 | 33.451 | 33.492 | -0.12% | loss |
| native | group_bytes_g1_mul_zero | 0.171 | 0.170 | +0.91% | overlap |
| native | group_bytes_g2_mul_random256 | 90.913 | 90.873 | +0.04% | overlap |
| native_scalar | group_bytes_g1_mul_high_sparse | 33.493 | 33.477 | +0.05% | overlap |
| native_scalar | group_bytes_g1_mul_near_order | 0.898 | 0.901 | -0.43% | loss |
| native_scalar | group_bytes_g1_mul_one | 0.183 | 0.187 | -2.58% | loss |
| native_scalar | group_bytes_g1_mul_random128 | 30.979 | 30.968 | +0.04% | overlap |
| native_scalar | group_bytes_g1_mul_random256 | 33.802 | 33.779 | +0.07% | overlap |
| native_scalar | group_bytes_g1_mul_random64 | 17.349 | 17.348 | +0.00% | overlap |
| native_scalar | group_bytes_g1_mul_random80 | 20.156 | 19.796 | +1.79% | gain |
| native_scalar | group_bytes_g1_mul_random96 | 22.245 | 22.237 | +0.04% | overlap |
| native_scalar | group_bytes_g1_mul_sparse | 20.431 | 20.477 | -0.23% | loss |
| native_scalar | group_bytes_g1_mul_sparse128 | 21.797 | 21.803 | -0.03% | overlap |
| native_scalar | group_bytes_g1_mul_sparse192 | 32.473 | 32.483 | -0.03% | overlap |
| native_scalar | group_bytes_g1_mul_sparse256 | 33.503 | 33.468 | +0.10% | gain |
| native_scalar | group_bytes_g1_mul_zero | 0.169 | 0.176 | -4.27% | loss |
| native_scalar | group_bytes_g2_mul_random256 | 100.415 | 100.435 | -0.02% | overlap |
| generic | group_bytes_g1_mul_high_sparse | 36.496 | 36.508 | -0.03% | overlap |
| generic | group_bytes_g1_mul_near_order | 0.914 | 0.918 | -0.36% | overlap |
| generic | group_bytes_g1_mul_one | 0.174 | 0.176 | -1.61% | overlap |
| generic | group_bytes_g1_mul_random128 | 33.694 | 33.703 | -0.03% | overlap |
| generic | group_bytes_g1_mul_random256 | 36.830 | 36.825 | +0.01% | overlap |
| generic | group_bytes_g1_mul_random64 | 18.845 | 18.846 | -0.00% | overlap |
| generic | group_bytes_g1_mul_random80 | 21.929 | 21.534 | +1.80% | gain |
| generic | group_bytes_g1_mul_random96 | 24.134 | 24.152 | -0.07% | loss |
| generic | group_bytes_g1_mul_sparse | 21.861 | 21.911 | -0.23% | loss |
| generic | group_bytes_g1_mul_sparse128 | 23.344 | 23.351 | -0.03% | overlap |
| generic | group_bytes_g1_mul_sparse192 | 34.801 | 34.808 | -0.02% | overlap |
| generic | group_bytes_g1_mul_sparse256 | 36.493 | 36.516 | -0.06% | overlap |
| generic | group_bytes_g1_mul_zero | 0.172 | 0.175 | -2.12% | overlap |
| generic | group_bytes_g2_mul_random256 | 105.879 | 105.855 | +0.02% | overlap |

“Gain”/“loss” means both candidate 95% intervals lie wholly below/above
both baselines. Overlap does not establish equivalence; between-run
variation can also separate intervals for identical code.

## G13H: G2 setup-cost estimate

Decision: **discard**. Discard the lower G2 setup estimate (100 -> 70). Random80 shows no established improvement in any build, and the primary random256 call overlaps in all three. Sparse128 regresses with separated intervals by 0.526% / 0.400% / 0.416% (native IFMA / native scalar / generic), adding roughly 0.34–0.37 us. Additional separated costs occur for scalar high_sparse/sparse and generic sparse192. The isolated generic random128 gain of 0.089% does not justify those costs. All 42 group rows were collected and all queued correctness checks passed; no pairing timing was requested. Guarded restoration keeps G13G's explicit setup parameter and G1 weight 40, while restoring the G2 weight to 100. No further setup-cutoff trial is added.

- Job: `9f889274b73a44e18b873e94d41ab2b9`.
- Source fingerprint: `f9771e5e1dbed194fe0f7ff3616d42a536906ad0cbf1aa160556a2162302b0b1`.
- Fetched result: `/Users/samkim/.local/state/benchctl/results/9f889274b73a44e18b873e94d41ab2b9`.
- CPU 16; 100 samples, 1 s warm-up, 2 s measurement, ABBA.
- `native`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native`.
- `native_scalar`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native -C target-feature=-avx512ifma`.
- `generic`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=x86-64`.

```sh
benchctl submit --json --label bn254-G13H-g2-setup --timeout 2h --artifact group-experiment-results -- python3 scripts/benchmark-bn254-groups.py run --id G13H-g2-setup --filter 'group_bytes_g2_mul_(random(64|80|96|128|256)|sparse(128|192|256)?|high_sparse|near_order|zero|one)/solana-bn254/le$|group_bytes_g1_mul_random256/solana-bn254/le$'
```

The job succeeded and `wait` returned zero. All queued correctness checks
completed successfully. Local candidate hashes match fetched metadata.

| Build | Case | Before (µs) | Candidate (µs) | Improvement | Intervals |
| --- | --- | ---: | ---: | ---: | --- |
| native | group_bytes_g1_mul_random256 | 33.759 | 33.767 | -0.02% | overlap |
| native | group_bytes_g2_mul_high_sparse | 108.735 | 108.705 | +0.03% | overlap |
| native | group_bytes_g2_mul_near_order | 33.103 | 33.129 | -0.08% | overlap |
| native | group_bytes_g2_mul_one | 32.083 | 32.092 | -0.03% | overlap |
| native | group_bytes_g2_mul_random128 | 94.366 | 94.567 | -0.21% | overlap |
| native | group_bytes_g2_mul_random256 | 90.933 | 90.885 | +0.05% | overlap |
| native | group_bytes_g2_mul_random64 | 67.495 | 67.510 | -0.02% | overlap |
| native | group_bytes_g2_mul_random80 | 71.215 | 71.230 | -0.02% | overlap |
| native | group_bytes_g2_mul_random96 | 75.386 | 75.456 | -0.09% | overlap |
| native | group_bytes_g2_mul_sparse | 66.858 | 66.918 | -0.09% | overlap |
| native | group_bytes_g2_mul_sparse128 | 69.576 | 69.942 | -0.53% | loss |
| native | group_bytes_g2_mul_sparse192 | 88.517 | 88.653 | -0.15% | overlap |
| native | group_bytes_g2_mul_sparse256 | 108.355 | 108.621 | -0.25% | overlap |
| native | group_bytes_g2_mul_zero | 32.082 | 32.102 | -0.06% | overlap |
| native_scalar | group_bytes_g1_mul_random256 | 33.816 | 33.817 | -0.00% | overlap |
| native_scalar | group_bytes_g2_mul_high_sparse | 122.566 | 122.778 | -0.17% | loss |
| native_scalar | group_bytes_g2_mul_near_order | 38.046 | 38.048 | -0.01% | overlap |
| native_scalar | group_bytes_g2_mul_one | 36.948 | 36.948 | +0.00% | overlap |
| native_scalar | group_bytes_g2_mul_random128 | 109.013 | 108.822 | +0.17% | overlap |
| native_scalar | group_bytes_g2_mul_random256 | 100.410 | 100.361 | +0.05% | overlap |
| native_scalar | group_bytes_g2_mul_random64 | 77.044 | 77.061 | -0.02% | overlap |
| native_scalar | group_bytes_g2_mul_random80 | 81.997 | 82.005 | -0.01% | overlap |
| native_scalar | group_bytes_g2_mul_random96 | 87.435 | 87.497 | -0.07% | overlap |
| native_scalar | group_bytes_g2_mul_sparse | 80.828 | 80.970 | -0.17% | loss |
| native_scalar | group_bytes_g2_mul_sparse128 | 84.227 | 84.564 | -0.40% | loss |
| native_scalar | group_bytes_g2_mul_sparse192 | 107.990 | 107.970 | +0.02% | overlap |
| native_scalar | group_bytes_g2_mul_sparse256 | 122.603 | 122.792 | -0.15% | overlap |
| native_scalar | group_bytes_g2_mul_zero | 36.953 | 36.956 | -0.01% | overlap |
| generic | group_bytes_g1_mul_random256 | 36.809 | 36.801 | +0.02% | overlap |
| generic | group_bytes_g2_mul_high_sparse | 130.104 | 130.315 | -0.16% | overlap |
| generic | group_bytes_g2_mul_near_order | 40.134 | 40.138 | -0.01% | overlap |
| generic | group_bytes_g2_mul_one | 39.000 | 38.996 | +0.01% | overlap |
| generic | group_bytes_g2_mul_random128 | 115.334 | 115.232 | +0.09% | gain |
| generic | group_bytes_g2_mul_random256 | 105.733 | 105.786 | -0.05% | overlap |
| generic | group_bytes_g2_mul_random64 | 81.244 | 81.360 | -0.14% | overlap |
| generic | group_bytes_g2_mul_random80 | 86.845 | 86.900 | -0.06% | overlap |
| generic | group_bytes_g2_mul_random96 | 92.578 | 92.652 | -0.08% | overlap |
| generic | group_bytes_g2_mul_sparse | 86.032 | 86.047 | -0.02% | overlap |
| generic | group_bytes_g2_mul_sparse128 | 89.570 | 89.943 | -0.42% | loss |
| generic | group_bytes_g2_mul_sparse192 | 115.477 | 115.620 | -0.12% | loss |
| generic | group_bytes_g2_mul_sparse256 | 130.191 | 130.311 | -0.09% | overlap |
| generic | group_bytes_g2_mul_zero | 38.995 | 38.998 | -0.01% | overlap |

“Gain”/“loss” means both candidate 95% intervals lie wholly below/above
both baselines. Overlap does not establish equivalence; between-run
variation can also separate intervals for identical code.

## G13I: IFMA-aware G2 doubling estimate

Decision: **discard**. Discard the IFMA-specific doubling-weight change (17 -> 14). Native-IFMA high_sparse and sparse256 become 1.600% and 1.831% slower, with separated intervals, adding about 1.74 and 1.99 us per complete call. No native G2 timing row establishes a gain; the primary random256 and shorter dense classes overlap. Scalar/generic weights were unchanged, but their executable hashes differ, so their small timing differences are not treated as identical-binary controls. They do not offset the regressions on the intended IFMA path. All 42 group rows were collected, and all queued correctness checks passed. No pairing timing was requested. Guarded restoration returns both selectors to doubling weight 17 while retaining G13G's G1 setup 40 and G2 setup 100. This finishes the planned optimization trials; only the two final cumulative/comparator runs remain.

- Job: `9d37f93c547c419bb22cd67338e3684c`.
- Source fingerprint: `a457398af378dfdac33fe8dc538a44132134524e2da6477cd8972e9df7947259`.
- Fetched result: `/Users/samkim/.local/state/benchctl/results/9d37f93c547c419bb22cd67338e3684c`.
- CPU 16; 100 samples, 1 s warm-up, 2 s measurement, ABBA.
- `native`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native`.
- `native_scalar`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native -C target-feature=-avx512ifma`.
- `generic`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=x86-64`.

```sh
benchctl submit --json --label bn254-G13I-ifma-cost --timeout 2h --artifact group-experiment-results -- python3 scripts/benchmark-bn254-groups.py run --id G13I-ifma-cost --filter 'group_bytes_g2_mul_(random(64|80|96|128|256)|sparse(128|192|256)?|high_sparse|near_order|zero|one)/solana-bn254/le$|group_bytes_g1_mul_random256/solana-bn254/le$'
```

The job succeeded and `wait` returned zero. All queued correctness checks
completed successfully. Local candidate hashes match fetched metadata.

| Build | Case | Before (µs) | Candidate (µs) | Improvement | Intervals |
| --- | --- | ---: | ---: | ---: | --- |
| native | group_bytes_g1_mul_random256 | 33.787 | 33.757 | +0.09% | gain |
| native | group_bytes_g2_mul_high_sparse | 108.539 | 110.275 | -1.60% | loss |
| native | group_bytes_g2_mul_near_order | 33.095 | 33.092 | +0.01% | overlap |
| native | group_bytes_g2_mul_one | 32.085 | 32.064 | +0.07% | overlap |
| native | group_bytes_g2_mul_random128 | 94.463 | 94.469 | -0.01% | overlap |
| native | group_bytes_g2_mul_random256 | 90.891 | 90.860 | +0.03% | overlap |
| native | group_bytes_g2_mul_random64 | 67.488 | 67.488 | +0.00% | overlap |
| native | group_bytes_g2_mul_random80 | 71.189 | 71.191 | -0.00% | overlap |
| native | group_bytes_g2_mul_random96 | 75.399 | 75.459 | -0.08% | overlap |
| native | group_bytes_g2_mul_sparse | 66.875 | 66.856 | +0.03% | overlap |
| native | group_bytes_g2_mul_sparse128 | 69.553 | 69.578 | -0.04% | overlap |
| native | group_bytes_g2_mul_sparse192 | 88.674 | 88.503 | +0.19% | overlap |
| native | group_bytes_g2_mul_sparse256 | 108.543 | 110.530 | -1.83% | loss |
| native | group_bytes_g2_mul_zero | 32.077 | 32.064 | +0.04% | overlap |
| native_scalar | group_bytes_g1_mul_random256 | 33.762 | 33.762 | -0.00% | overlap |
| native_scalar | group_bytes_g2_mul_high_sparse | 123.070 | 122.921 | +0.12% | overlap |
| native_scalar | group_bytes_g2_mul_near_order | 38.046 | 38.034 | +0.03% | overlap |
| native_scalar | group_bytes_g2_mul_one | 36.973 | 36.941 | +0.09% | overlap |
| native_scalar | group_bytes_g2_mul_random128 | 108.948 | 108.689 | +0.24% | overlap |
| native_scalar | group_bytes_g2_mul_random256 | 100.408 | 100.349 | +0.06% | overlap |
| native_scalar | group_bytes_g2_mul_random64 | 77.046 | 77.058 | -0.02% | overlap |
| native_scalar | group_bytes_g2_mul_random80 | 81.961 | 81.981 | -0.02% | overlap |
| native_scalar | group_bytes_g2_mul_random96 | 87.493 | 87.511 | -0.02% | overlap |
| native_scalar | group_bytes_g2_mul_sparse | 80.937 | 80.882 | +0.07% | overlap |
| native_scalar | group_bytes_g2_mul_sparse128 | 84.217 | 84.214 | +0.00% | overlap |
| native_scalar | group_bytes_g2_mul_sparse192 | 108.181 | 108.132 | +0.04% | overlap |
| native_scalar | group_bytes_g2_mul_sparse256 | 123.446 | 123.026 | +0.34% | overlap |
| native_scalar | group_bytes_g2_mul_zero | 36.949 | 36.941 | +0.02% | overlap |
| generic | group_bytes_g1_mul_random256 | 36.822 | 36.817 | +0.01% | overlap |
| generic | group_bytes_g2_mul_high_sparse | 130.117 | 130.035 | +0.06% | gain |
| generic | group_bytes_g2_mul_near_order | 40.160 | 40.139 | +0.05% | gain |
| generic | group_bytes_g2_mul_one | 39.019 | 39.003 | +0.04% | overlap |
| generic | group_bytes_g2_mul_random128 | 115.293 | 115.331 | -0.03% | overlap |
| generic | group_bytes_g2_mul_random256 | 105.783 | 105.695 | +0.08% | gain |
| generic | group_bytes_g2_mul_random64 | 81.302 | 81.277 | +0.03% | overlap |
| generic | group_bytes_g2_mul_random80 | 86.841 | 86.810 | +0.03% | overlap |
| generic | group_bytes_g2_mul_random96 | 92.666 | 92.602 | +0.07% | gain |
| generic | group_bytes_g2_mul_sparse | 86.051 | 86.003 | +0.06% | overlap |
| generic | group_bytes_g2_mul_sparse128 | 89.632 | 89.558 | +0.08% | overlap |
| generic | group_bytes_g2_mul_sparse192 | 115.552 | 115.456 | +0.08% | overlap |
| generic | group_bytes_g2_mul_sparse256 | 130.021 | 130.080 | -0.05% | overlap |
| generic | group_bytes_g2_mul_zero | 39.018 | 38.997 | +0.05% | gain |

“Gain”/“loss” means both candidate 95% intervals lie wholly below/above
both baselines. Overlap does not establish equivalence; between-run
variation can also separate intervals for identical code.

## G-final: first input seed

Decision: **confirm**. First final validation of the complete retained G1/G2 source against the original c9cf3a7 production files, using explicit seed 0x6731673262656e31. All 123 group rows and nine pairing rows have both retained-version intervals below both original baselines; no overlap or separated regression rows occur. Native IFMA cumulative gains are 20.623% G1 addition, 15.891% G2 addition, 8.354% G1 random256 multiplication and 28.692% G2 checked random256 multiplication. Native-scalar multiplication gains are 8.293% / 21.356%, and generic gains are 9.005% / 22.907% (G1 / G2). Native raw G2 random256 improves 41.273% and MAX improves 71.732%. Pairing improves 1.556–2.110% native, 0.604–0.736% scalar and 0.788–1.100% generic. The 36 fresh comparator rows put ours ahead of the Ark Solana adapter and the pinned native Firedancer build on all four primary operations in each Rust configuration. In native IFMA, G1/G2 multiplication are 1.669x/2.043x as fast as that Firedancer build; scalar ratios are 1.672x/1.851x. These comparator qualifications are the same as the workflow: Ark affine binary multiplication, Firedancer native ADX with s2n disabled. All queued correctness checks passed. Production hashes match the retained workspace. The second input seed remains required before the final report.

- Job: `9d90278f4a66484294c32bd909c60a52`.
- Source fingerprint: `40e8c282c9635bda7c52f617cb48ca99cb49ca65929f094e2790b9cd93b126f4`.
- Fetched result: `/Users/samkim/.local/state/benchctl/results/9d90278f4a66484294c32bd909c60a52`.
- CPU 16; 100 samples, 1 s warm-up, 2 s measurement, ABBA.
- `native`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native`.
- `native_scalar`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native -C target-feature=-avx512ifma`.
- `generic`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=x86-64`.
- Explicit fixture seed: `0x6731673262656e31`.

```sh
benchctl submit --json --label bn254-G-final-seed31 --timeout 2h --artifact group-experiment-results -- python3 scripts/benchmark-bn254-groups.py run --id G-final --seed 0x6731673262656e31 --comparison --comparison-variant candidate --comparison-filter 'group_bytes_g[12]_(add_random|mul_random256)/(solana-bn254|ark-bn254|firedancer)/le$' --pairing --filter 'group_bytes_g[12]_(add_(random|double)|mul_(random(64|80|96|128|144|192|256)|exact129|high_sparse|sparse|near_order|max|zero|one))/solana-bn254/le$|group_bytes_g2_add_full_twist/solana-bn254/le$|group_kernel_g2_(subgroup_(valid|invalid)|raw_mul(_(random128|high_sparse|max|zero|one))?)/solana-bn254$' --pairing-filter 'pairing_bytes_seeded_(1|4|16)/solana-bn254/le$'
```

The job succeeded and `wait` returned zero. All queued correctness checks
completed successfully. Local candidate hashes match fetched metadata.

| Build | Case | Before (µs) | Candidate (µs) | Improvement | Intervals |
| --- | --- | ---: | ---: | ---: | --- |
| native | group_bytes_g1_add_double | 1.365 | 1.087 | +20.36% | gain |
| native | group_bytes_g1_add_random | 1.343 | 1.066 | +20.62% | gain |
| native | group_bytes_g1_mul_exact129 | 34.546 | 31.386 | +9.15% | gain |
| native | group_bytes_g1_mul_high_sparse | 36.824 | 33.475 | +9.09% | gain |
| native | group_bytes_g1_mul_max | 37.074 | 33.705 | +9.09% | gain |
| native | group_bytes_g1_mul_near_order | 1.247 | 0.900 | +27.82% | gain |
| native | group_bytes_g1_mul_one | 0.399 | 0.185 | +53.71% | gain |
| native | group_bytes_g1_mul_random128 | 34.256 | 30.965 | +9.61% | gain |
| native | group_bytes_g1_mul_random144 | 34.981 | 32.063 | +8.34% | gain |
| native | group_bytes_g1_mul_random192 | 37.015 | 34.151 | +7.74% | gain |
| native | group_bytes_g1_mul_random256 | 36.869 | 33.789 | +8.35% | gain |
| native | group_bytes_g1_mul_random64 | 17.728 | 17.331 | +2.24% | gain |
| native | group_bytes_g1_mul_random80 | 21.124 | 19.780 | +6.36% | gain |
| native | group_bytes_g1_mul_random96 | 24.840 | 22.219 | +10.55% | gain |
| native | group_bytes_g1_mul_sparse | 20.710 | 20.435 | +1.33% | gain |
| native | group_bytes_g1_mul_zero | 0.382 | 0.170 | +55.41% | gain |
| native | group_bytes_g2_add_double | 1.912 | 1.614 | +15.61% | gain |
| native | group_bytes_g2_add_full_twist | 1.855 | 1.576 | +15.03% | gain |
| native | group_bytes_g2_add_random | 1.868 | 1.571 | +15.89% | gain |
| native | group_bytes_g2_mul_exact129 | 120.005 | 90.317 | +24.74% | gain |
| native | group_bytes_g2_mul_high_sparse | 128.595 | 108.584 | +15.56% | gain |
| native | group_bytes_g2_mul_max | 127.875 | 91.645 | +28.33% | gain |
| native | group_bytes_g2_mul_near_order | 39.237 | 33.094 | +15.65% | gain |
| native | group_bytes_g2_mul_one | 37.971 | 32.070 | +15.54% | gain |
| native | group_bytes_g2_mul_random128 | 119.035 | 94.512 | +20.60% | gain |
| native | group_bytes_g2_mul_random144 | 121.492 | 92.656 | +23.73% | gain |
| native | group_bytes_g2_mul_random192 | 128.235 | 91.443 | +28.69% | gain |
| native | group_bytes_g2_mul_random256 | 127.451 | 90.882 | +28.69% | gain |
| native | group_bytes_g2_mul_random64 | 78.470 | 67.475 | +14.01% | gain |
| native | group_bytes_g2_mul_random80 | 84.298 | 71.174 | +15.57% | gain |
| native | group_bytes_g2_mul_random96 | 93.419 | 75.393 | +19.30% | gain |
| native | group_bytes_g2_mul_sparse | 82.805 | 66.899 | +19.21% | gain |
| native | group_bytes_g2_mul_zero | 37.970 | 32.068 | +15.54% | gain |
| native | group_kernel_g2_raw_mul | 183.096 | 107.528 | +41.27% | gain |
| native | group_kernel_g2_raw_mul_high_sparse | 96.982 | 73.779 | +23.92% | gain |
| native | group_kernel_g2_raw_mul_max | 271.133 | 76.643 | +71.73% | gain |
| native | group_kernel_g2_raw_mul_one | 0.221 | 0.014 | +93.63% | gain |
| native | group_kernel_g2_raw_mul_random128 | 82.952 | 55.189 | +33.47% | gain |
| native | group_kernel_g2_raw_mul_zero | 0.211 | 0.012 | +94.47% | gain |
| native | group_kernel_g2_subgroup_invalid | 37.332 | 31.469 | +15.70% | gain |
| native | group_kernel_g2_subgroup_valid | 37.568 | 31.692 | +15.64% | gain |
| native | pairing_bytes_seeded_1 | 467.124 | 459.856 | +1.56% | gain |
| native | pairing_bytes_seeded_16 | 3393.645 | 3322.051 | +2.11% | gain |
| native | pairing_bytes_seeded_4 | 1055.900 | 1037.676 | +1.73% | gain |
| native_scalar | group_bytes_g1_add_double | 1.364 | 1.085 | +20.46% | gain |
| native_scalar | group_bytes_g1_add_random | 1.342 | 1.067 | +20.51% | gain |
| native_scalar | group_bytes_g1_mul_exact129 | 34.502 | 31.394 | +9.01% | gain |
| native_scalar | group_bytes_g1_mul_high_sparse | 36.824 | 33.485 | +9.07% | gain |
| native_scalar | group_bytes_g1_mul_max | 37.077 | 33.687 | +9.14% | gain |
| native_scalar | group_bytes_g1_mul_near_order | 1.251 | 0.900 | +28.05% | gain |
| native_scalar | group_bytes_g1_mul_one | 0.398 | 0.184 | +53.78% | gain |
| native_scalar | group_bytes_g1_mul_random128 | 34.233 | 30.965 | +9.55% | gain |
| native_scalar | group_bytes_g1_mul_random144 | 34.913 | 32.072 | +8.14% | gain |
| native_scalar | group_bytes_g1_mul_random192 | 36.992 | 34.154 | +7.67% | gain |
| native_scalar | group_bytes_g1_mul_random256 | 36.832 | 33.777 | +8.29% | gain |
| native_scalar | group_bytes_g1_mul_random64 | 17.722 | 17.339 | +2.16% | gain |
| native_scalar | group_bytes_g1_mul_random80 | 21.095 | 19.785 | +6.21% | gain |
| native_scalar | group_bytes_g1_mul_random96 | 24.816 | 22.222 | +10.45% | gain |
| native_scalar | group_bytes_g1_mul_sparse | 20.695 | 20.471 | +1.08% | gain |
| native_scalar | group_bytes_g1_mul_zero | 0.381 | 0.171 | +55.27% | gain |
| native_scalar | group_bytes_g2_add_double | 1.911 | 1.612 | +15.66% | gain |
| native_scalar | group_bytes_g2_add_full_twist | 1.854 | 1.572 | +15.21% | gain |
| native_scalar | group_bytes_g2_add_random | 1.867 | 1.565 | +16.16% | gain |
| native_scalar | group_bytes_g2_mul_exact129 | 119.996 | 99.743 | +16.88% | gain |
| native_scalar | group_bytes_g2_mul_high_sparse | 128.528 | 122.699 | +4.54% | gain |
| native_scalar | group_bytes_g2_mul_max | 127.950 | 101.073 | +21.01% | gain |
| native_scalar | group_bytes_g2_mul_near_order | 39.236 | 38.057 | +3.00% | gain |
| native_scalar | group_bytes_g2_mul_one | 37.965 | 36.929 | +2.73% | gain |
| native_scalar | group_bytes_g2_mul_random128 | 118.999 | 108.824 | +8.55% | gain |
| native_scalar | group_bytes_g2_mul_random144 | 121.468 | 102.093 | +15.95% | gain |
| native_scalar | group_bytes_g2_mul_random192 | 128.152 | 100.951 | +21.23% | gain |
| native_scalar | group_bytes_g2_mul_random256 | 127.626 | 100.370 | +21.36% | gain |
| native_scalar | group_bytes_g2_mul_random64 | 78.565 | 77.039 | +1.94% | gain |
| native_scalar | group_bytes_g2_mul_random80 | 84.374 | 81.995 | +2.82% | gain |
| native_scalar | group_bytes_g2_mul_random96 | 93.476 | 87.397 | +6.50% | gain |
| native_scalar | group_bytes_g2_mul_sparse | 82.431 | 80.878 | +1.88% | gain |
| native_scalar | group_bytes_g2_mul_zero | 37.963 | 36.937 | +2.70% | gain |
| native_scalar | group_kernel_g2_raw_mul | 183.574 | 126.030 | +31.35% | gain |
| native_scalar | group_kernel_g2_raw_mul_high_sparse | 96.345 | 93.961 | +2.47% | gain |
| native_scalar | group_kernel_g2_raw_mul_max | 271.535 | 96.083 | +64.61% | gain |
| native_scalar | group_kernel_g2_raw_mul_one | 0.220 | 0.014 | +93.70% | gain |
| native_scalar | group_kernel_g2_raw_mul_random128 | 82.927 | 64.840 | +21.81% | gain |
| native_scalar | group_kernel_g2_raw_mul_zero | 0.211 | 0.012 | +94.36% | gain |
| native_scalar | group_kernel_g2_subgroup_invalid | 37.331 | 36.396 | +2.51% | gain |
| native_scalar | group_kernel_g2_subgroup_valid | 37.582 | 36.634 | +2.52% | gain |
| native_scalar | pairing_bytes_seeded_1 | 518.737 | 514.919 | +0.74% | gain |
| native_scalar | pairing_bytes_seeded_16 | 3632.531 | 3606.805 | +0.71% | gain |
| native_scalar | pairing_bytes_seeded_4 | 1148.172 | 1141.236 | +0.60% | gain |
| generic | group_bytes_g1_add_double | 1.496 | 1.100 | +26.44% | gain |
| generic | group_bytes_g1_add_random | 1.474 | 1.078 | +26.85% | gain |
| generic | group_bytes_g1_mul_exact129 | 37.866 | 34.123 | +9.88% | gain |
| generic | group_bytes_g1_mul_high_sparse | 40.425 | 36.502 | +9.71% | gain |
| generic | group_bytes_g1_mul_max | 40.719 | 36.724 | +9.81% | gain |
| generic | group_bytes_g1_mul_near_order | 1.361 | 0.915 | +32.77% | gain |
| generic | group_bytes_g1_mul_one | 0.408 | 0.173 | +57.66% | gain |
| generic | group_bytes_g1_mul_random128 | 37.539 | 33.687 | +10.26% | gain |
| generic | group_bytes_g1_mul_random144 | 38.346 | 34.918 | +8.94% | gain |
| generic | group_bytes_g1_mul_random192 | 40.665 | 37.241 | +8.42% | gain |
| generic | group_bytes_g1_mul_random256 | 40.462 | 36.818 | +9.01% | gain |
| generic | group_bytes_g1_mul_random64 | 19.419 | 18.827 | +3.05% | gain |
| generic | group_bytes_g1_mul_random80 | 23.132 | 21.515 | +6.99% | gain |
| generic | group_bytes_g1_mul_random96 | 27.200 | 24.135 | +11.27% | gain |
| generic | group_bytes_g1_mul_sparse | 22.368 | 21.892 | +2.13% | gain |
| generic | group_bytes_g1_mul_zero | 0.391 | 0.172 | +55.99% | gain |
| generic | group_bytes_g2_add_double | 2.032 | 1.630 | +19.78% | gain |
| generic | group_bytes_g2_add_full_twist | 1.969 | 1.583 | +19.56% | gain |
| generic | group_bytes_g2_add_random | 1.976 | 1.576 | +20.28% | gain |
| generic | group_bytes_g2_mul_exact129 | 129.602 | 105.059 | +18.94% | gain |
| generic | group_bytes_g2_mul_high_sparse | 138.559 | 130.119 | +6.09% | gain |
| generic | group_bytes_g2_mul_max | 137.880 | 106.684 | +22.63% | gain |
| generic | group_bytes_g2_mul_near_order | 41.921 | 40.144 | +4.24% | gain |
| generic | group_bytes_g2_mul_one | 40.542 | 39.016 | +3.76% | gain |
| generic | group_bytes_g2_mul_random128 | 128.892 | 115.302 | +10.54% | gain |
| generic | group_bytes_g2_mul_random144 | 131.029 | 107.478 | +17.97% | gain |
| generic | group_bytes_g2_mul_random192 | 137.853 | 106.343 | +22.86% | gain |
| generic | group_bytes_g2_mul_random256 | 137.355 | 105.892 | +22.91% | gain |
| generic | group_bytes_g2_mul_random64 | 83.810 | 81.313 | +2.98% | gain |
| generic | group_bytes_g2_mul_random80 | 90.948 | 86.843 | +4.51% | gain |
| generic | group_bytes_g2_mul_random96 | 101.334 | 92.671 | +8.55% | gain |
| generic | group_bytes_g2_mul_sparse | 89.642 | 86.025 | +4.03% | gain |
| generic | group_bytes_g2_mul_zero | 40.556 | 39.012 | +3.81% | gain |
| generic | group_kernel_g2_raw_mul | 199.286 | 134.987 | +32.26% | gain |
| generic | group_kernel_g2_raw_mul_high_sparse | 105.181 | 100.619 | +4.34% | gain |
| generic | group_kernel_g2_raw_mul_max | 290.341 | 103.206 | +64.45% | gain |
| generic | group_kernel_g2_raw_mul_one | 0.224 | 0.010 | +95.64% | gain |
| generic | group_kernel_g2_raw_mul_random128 | 88.380 | 68.778 | +22.18% | gain |
| generic | group_kernel_g2_raw_mul_zero | 0.215 | 0.010 | +95.46% | gain |
| generic | group_kernel_g2_subgroup_invalid | 39.941 | 38.443 | +3.75% | gain |
| generic | group_kernel_g2_subgroup_valid | 40.172 | 38.654 | +3.78% | gain |
| generic | pairing_bytes_seeded_1 | 536.871 | 530.966 | +1.10% | gain |
| generic | pairing_bytes_seeded_16 | 3796.759 | 3758.609 | +1.00% | gain |
| generic | pairing_bytes_seeded_4 | 1195.614 | 1186.188 | +0.79% | gain |

“Gain”/“loss” means both candidate 95% intervals lie wholly below/above
both baselines. Overlap does not establish equivalence; between-run
variation can also separate intervals for identical code.

## G-final: second input seed and completion

Decision: **confirm**. Second final validation, with explicit seed 0x6731673262656e32, confirms the retained implementation on a separate group input pool. All 123 group and nine pairing rows again have both retained-version intervals below both original baselines, giving 264 separated favorable rows across the two final jobs and no overlap/regression rows. Native IFMA cumulative random256 multiplication gains are 7.745% G1 and 27.432% checked G2; native scalar gains are 7.677% / 19.872%, and generic gains are 8.187% / 21.318%. Native raw G2 random256 improves 41.554% and MAX improves 71.823%. Pairing improves 1.551–2.117% native, 0.524–0.694% scalar and 0.918–1.117% generic. All 36 fresh comparator timings again favor ours over the documented Ark Solana adapter and native Firedancer build. Native IFMA G1/G2 multiplication are 1.674x/1.988x as fast as that Firedancer build; scalar ratios are 1.671x/1.805x. The report generator verified matching production hashes, runner/harness, lockfile, compilers, flags, CPU, filters and sampling settings across both jobs; only the group fixture seed changes. All queued correctness checks passed, both exact waits returned zero, and both archives were fetched. The consolidated report is group-optimization-results.md. The planned G1/G2 sequence is complete; no task jobs remain running and Poseidon remains deferred.

- Job: `bea7e864d82f456089a46e1eea77457a`.
- Source fingerprint: `b27fcbfc85f4ab5277605916c879fde81f0e859db268032ffecdf0bd59893817`.
- Fetched result: `/Users/samkim/.local/state/benchctl/results/bea7e864d82f456089a46e1eea77457a`.
- CPU 16; 100 samples, 1 s warm-up, 2 s measurement, ABBA.
- `native`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native`.
- `native_scalar`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native -C target-feature=-avx512ifma`.
- `generic`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=x86-64`.
- Explicit fixture seed: `0x6731673262656e32`.

```sh
benchctl submit --json --label bn254-G-final-seed32 --timeout 2h --artifact group-experiment-results -- python3 scripts/benchmark-bn254-groups.py run --id G-final --seed 0x6731673262656e32 --comparison --comparison-variant candidate --comparison-filter 'group_bytes_g[12]_(add_random|mul_random256)/(solana-bn254|ark-bn254|firedancer)/le$' --pairing --filter 'group_bytes_g[12]_(add_(random|double)|mul_(random(64|80|96|128|144|192|256)|exact129|high_sparse|sparse|near_order|max|zero|one))/solana-bn254/le$|group_bytes_g2_add_full_twist/solana-bn254/le$|group_kernel_g2_(subgroup_(valid|invalid)|raw_mul(_(random128|high_sparse|max|zero|one))?)/solana-bn254$' --pairing-filter 'pairing_bytes_seeded_(1|4|16)/solana-bn254/le$'
```

The job succeeded and `wait` returned zero. All queued correctness checks
completed successfully. Local candidate hashes match fetched metadata.

| Build | Case | Before (µs) | Candidate (µs) | Improvement | Intervals |
| --- | --- | ---: | ---: | ---: | --- |
| native | group_bytes_g1_add_double | 1.365 | 1.086 | +20.47% | gain |
| native | group_bytes_g1_add_random | 1.347 | 1.067 | +20.75% | gain |
| native | group_bytes_g1_mul_exact129 | 34.744 | 31.462 | +9.45% | gain |
| native | group_bytes_g1_mul_high_sparse | 36.861 | 33.493 | +9.14% | gain |
| native | group_bytes_g1_mul_max | 37.148 | 33.684 | +9.32% | gain |
| native | group_bytes_g1_mul_near_order | 1.251 | 0.899 | +28.14% | gain |
| native | group_bytes_g1_mul_one | 0.402 | 0.185 | +54.07% | gain |
| native | group_bytes_g1_mul_random128 | 32.742 | 29.173 | +10.90% | gain |
| native | group_bytes_g1_mul_random144 | 34.856 | 31.861 | +8.59% | gain |
| native | group_bytes_g1_mul_random192 | 36.646 | 34.028 | +7.15% | gain |
| native | group_bytes_g1_mul_random256 | 36.605 | 33.770 | +7.74% | gain |
| native | group_bytes_g1_mul_random64 | 17.738 | 17.304 | +2.45% | gain |
| native | group_bytes_g1_mul_random80 | 20.993 | 19.704 | +6.14% | gain |
| native | group_bytes_g1_mul_random96 | 24.520 | 22.351 | +8.85% | gain |
| native | group_bytes_g1_mul_sparse | 20.750 | 20.459 | +1.40% | gain |
| native | group_bytes_g1_mul_zero | 0.385 | 0.171 | +55.62% | gain |
| native | group_bytes_g2_add_double | 1.910 | 1.615 | +15.42% | gain |
| native | group_bytes_g2_add_full_twist | 1.851 | 1.575 | +14.94% | gain |
| native | group_bytes_g2_add_random | 1.854 | 1.582 | +14.71% | gain |
| native | group_bytes_g2_mul_exact129 | 120.621 | 94.977 | +21.26% | gain |
| native | group_bytes_g2_mul_high_sparse | 128.921 | 108.511 | +15.83% | gain |
| native | group_bytes_g2_mul_max | 128.092 | 91.593 | +28.49% | gain |
| native | group_bytes_g2_mul_near_order | 39.180 | 33.065 | +15.61% | gain |
| native | group_bytes_g2_mul_one | 37.914 | 32.049 | +15.47% | gain |
| native | group_bytes_g2_mul_random128 | 114.562 | 89.819 | +21.60% | gain |
| native | group_bytes_g2_mul_random144 | 121.112 | 91.104 | +24.78% | gain |
| native | group_bytes_g2_mul_random192 | 126.638 | 92.490 | +26.97% | gain |
| native | group_bytes_g2_mul_random256 | 127.259 | 92.349 | +27.43% | gain |
| native | group_bytes_g2_mul_random64 | 78.409 | 67.535 | +13.87% | gain |
| native | group_bytes_g2_mul_random80 | 83.801 | 70.764 | +15.56% | gain |
| native | group_bytes_g2_mul_random96 | 92.667 | 75.822 | +18.18% | gain |
| native | group_bytes_g2_mul_sparse | 82.347 | 66.849 | +18.82% | gain |
| native | group_bytes_g2_mul_zero | 37.919 | 32.047 | +15.49% | gain |
| native | group_kernel_g2_raw_mul | 183.404 | 107.192 | +41.55% | gain |
| native | group_kernel_g2_raw_mul_high_sparse | 96.367 | 73.487 | +23.74% | gain |
| native | group_kernel_g2_raw_mul_max | 271.418 | 76.477 | +71.82% | gain |
| native | group_kernel_g2_raw_mul_one | 0.220 | 0.018 | +91.66% | gain |
| native | group_kernel_g2_raw_mul_random128 | 82.414 | 54.634 | +33.71% | gain |
| native | group_kernel_g2_raw_mul_zero | 0.211 | 0.016 | +92.37% | gain |
| native | group_kernel_g2_subgroup_invalid | 37.360 | 31.433 | +15.86% | gain |
| native | group_kernel_g2_subgroup_valid | 37.548 | 31.652 | +15.70% | gain |
| native | pairing_bytes_seeded_1 | 466.892 | 459.652 | +1.55% | gain |
| native | pairing_bytes_seeded_16 | 3392.571 | 3320.734 | +2.12% | gain |
| native | pairing_bytes_seeded_4 | 1055.625 | 1037.314 | +1.73% | gain |
| native_scalar | group_bytes_g1_add_double | 1.368 | 1.082 | +20.89% | gain |
| native_scalar | group_bytes_g1_add_random | 1.352 | 1.065 | +21.22% | gain |
| native_scalar | group_bytes_g1_mul_exact129 | 34.701 | 31.481 | +9.28% | gain |
| native_scalar | group_bytes_g1_mul_high_sparse | 36.822 | 33.490 | +9.05% | gain |
| native_scalar | group_bytes_g1_mul_max | 37.098 | 33.675 | +9.23% | gain |
| native_scalar | group_bytes_g1_mul_near_order | 1.250 | 0.895 | +28.43% | gain |
| native_scalar | group_bytes_g1_mul_one | 0.398 | 0.182 | +54.14% | gain |
| native_scalar | group_bytes_g1_mul_random128 | 32.705 | 29.190 | +10.75% | gain |
| native_scalar | group_bytes_g1_mul_random144 | 34.821 | 31.878 | +8.45% | gain |
| native_scalar | group_bytes_g1_mul_random192 | 36.619 | 34.033 | +7.06% | gain |
| native_scalar | group_bytes_g1_mul_random256 | 36.565 | 33.758 | +7.68% | gain |
| native_scalar | group_bytes_g1_mul_random64 | 17.726 | 17.314 | +2.33% | gain |
| native_scalar | group_bytes_g1_mul_random80 | 20.975 | 19.718 | +5.99% | gain |
| native_scalar | group_bytes_g1_mul_random96 | 24.490 | 22.367 | +8.67% | gain |
| native_scalar | group_bytes_g1_mul_sparse | 20.740 | 20.485 | +1.23% | gain |
| native_scalar | group_bytes_g1_mul_zero | 0.374 | 0.169 | +54.79% | gain |
| native_scalar | group_bytes_g2_add_double | 1.926 | 1.607 | +16.54% | gain |
| native_scalar | group_bytes_g2_add_full_twist | 1.870 | 1.569 | +16.08% | gain |
| native_scalar | group_bytes_g2_add_random | 1.873 | 1.573 | +16.02% | gain |
| native_scalar | group_bytes_g2_mul_exact129 | 120.591 | 104.421 | +13.41% | gain |
| native_scalar | group_bytes_g2_mul_high_sparse | 128.787 | 122.710 | +4.72% | gain |
| native_scalar | group_bytes_g2_mul_max | 127.944 | 101.029 | +21.04% | gain |
| native_scalar | group_bytes_g2_mul_near_order | 39.210 | 38.008 | +3.06% | gain |
| native_scalar | group_bytes_g2_mul_one | 37.943 | 36.934 | +2.66% | gain |
| native_scalar | group_bytes_g2_mul_random128 | 114.673 | 103.996 | +9.31% | gain |
| native_scalar | group_bytes_g2_mul_random144 | 121.260 | 100.559 | +17.07% | gain |
| native_scalar | group_bytes_g2_mul_random192 | 126.673 | 101.986 | +19.49% | gain |
| native_scalar | group_bytes_g2_mul_random256 | 127.053 | 101.806 | +19.87% | gain |
| native_scalar | group_bytes_g2_mul_random64 | 78.451 | 77.029 | +1.81% | gain |
| native_scalar | group_bytes_g2_mul_random80 | 83.825 | 81.563 | +2.70% | gain |
| native_scalar | group_bytes_g2_mul_random96 | 92.698 | 87.865 | +5.21% | gain |
| native_scalar | group_bytes_g2_mul_sparse | 82.397 | 80.892 | +1.83% | gain |
| native_scalar | group_bytes_g2_mul_zero | 37.944 | 36.933 | +2.67% | gain |
| native_scalar | group_kernel_g2_raw_mul | 183.306 | 126.104 | +31.21% | gain |
| native_scalar | group_kernel_g2_raw_mul_high_sparse | 96.270 | 93.822 | +2.54% | gain |
| native_scalar | group_kernel_g2_raw_mul_max | 271.738 | 95.909 | +64.71% | gain |
| native_scalar | group_kernel_g2_raw_mul_one | 0.220 | 0.013 | +93.87% | gain |
| native_scalar | group_kernel_g2_raw_mul_random128 | 82.435 | 64.242 | +22.07% | gain |
| native_scalar | group_kernel_g2_raw_mul_zero | 0.212 | 0.012 | +94.54% | gain |
| native_scalar | group_kernel_g2_subgroup_invalid | 37.470 | 36.314 | +3.08% | gain |
| native_scalar | group_kernel_g2_subgroup_valid | 37.671 | 36.533 | +3.02% | gain |
| native_scalar | pairing_bytes_seeded_1 | 519.080 | 515.479 | +0.69% | gain |
| native_scalar | pairing_bytes_seeded_16 | 3635.768 | 3613.083 | +0.62% | gain |
| native_scalar | pairing_bytes_seeded_4 | 1149.455 | 1143.429 | +0.52% | gain |
| generic | group_bytes_g1_add_double | 1.494 | 1.101 | +26.30% | gain |
| generic | group_bytes_g1_add_random | 1.470 | 1.078 | +26.68% | gain |
| generic | group_bytes_g1_mul_exact129 | 38.045 | 34.273 | +9.91% | gain |
| generic | group_bytes_g1_mul_high_sparse | 40.425 | 36.531 | +9.63% | gain |
| generic | group_bytes_g1_mul_max | 40.726 | 36.725 | +9.82% | gain |
| generic | group_bytes_g1_mul_near_order | 1.359 | 0.911 | +32.97% | gain |
| generic | group_bytes_g1_mul_one | 0.407 | 0.173 | +57.50% | gain |
| generic | group_bytes_g1_mul_random128 | 35.798 | 31.712 | +11.41% | gain |
| generic | group_bytes_g1_mul_random144 | 38.171 | 34.703 | +9.09% | gain |
| generic | group_bytes_g1_mul_random192 | 40.166 | 37.091 | +7.66% | gain |
| generic | group_bytes_g1_mul_random256 | 40.105 | 36.821 | +8.19% | gain |
| generic | group_bytes_g1_mul_random64 | 19.402 | 18.840 | +2.89% | gain |
| generic | group_bytes_g1_mul_random80 | 22.949 | 21.452 | +6.52% | gain |
| generic | group_bytes_g1_mul_random96 | 26.788 | 24.309 | +9.25% | gain |
| generic | group_bytes_g1_mul_sparse | 22.369 | 21.925 | +1.99% | gain |
| generic | group_bytes_g1_mul_zero | 0.390 | 0.171 | +56.09% | gain |
| generic | group_bytes_g2_add_double | 2.026 | 1.627 | +19.68% | gain |
| generic | group_bytes_g2_add_full_twist | 1.965 | 1.580 | +19.59% | gain |
| generic | group_bytes_g2_add_random | 1.968 | 1.582 | +19.62% | gain |
| generic | group_bytes_g2_mul_exact129 | 129.851 | 109.963 | +15.32% | gain |
| generic | group_bytes_g2_mul_high_sparse | 138.068 | 130.192 | +5.70% | gain |
| generic | group_bytes_g2_mul_max | 137.373 | 106.450 | +22.51% | gain |
| generic | group_bytes_g2_mul_near_order | 41.892 | 40.126 | +4.22% | gain |
| generic | group_bytes_g2_mul_one | 40.524 | 39.004 | +3.75% | gain |
| generic | group_bytes_g2_mul_random128 | 123.836 | 110.248 | +10.97% | gain |
| generic | group_bytes_g2_mul_random144 | 130.420 | 105.979 | +18.74% | gain |
| generic | group_bytes_g2_mul_random192 | 136.168 | 107.514 | +21.04% | gain |
| generic | group_bytes_g2_mul_random256 | 136.311 | 107.253 | +21.32% | gain |
| generic | group_bytes_g2_mul_random64 | 83.776 | 81.278 | +2.98% | gain |
| generic | group_bytes_g2_mul_random80 | 90.042 | 86.418 | +4.02% | gain |
| generic | group_bytes_g2_mul_random96 | 100.343 | 93.125 | +7.19% | gain |
| generic | group_bytes_g2_mul_sparse | 89.613 | 86.014 | +4.02% | gain |
| generic | group_bytes_g2_mul_zero | 40.525 | 38.988 | +3.79% | gain |
| generic | group_kernel_g2_raw_mul | 199.283 | 134.927 | +32.29% | gain |
| generic | group_kernel_g2_raw_mul_high_sparse | 105.641 | 100.213 | +5.14% | gain |
| generic | group_kernel_g2_raw_mul_max | 290.524 | 103.209 | +64.47% | gain |
| generic | group_kernel_g2_raw_mul_one | 0.231 | 0.010 | +95.77% | gain |
| generic | group_kernel_g2_raw_mul_random128 | 87.871 | 68.196 | +22.39% | gain |
| generic | group_kernel_g2_raw_mul_zero | 0.218 | 0.010 | +95.52% | gain |
| generic | group_kernel_g2_subgroup_invalid | 39.969 | 38.439 | +3.83% | gain |
| generic | group_kernel_g2_subgroup_valid | 40.172 | 38.646 | +3.80% | gain |
| generic | pairing_bytes_seeded_1 | 538.243 | 532.281 | +1.11% | gain |
| generic | pairing_bytes_seeded_16 | 3803.985 | 3761.512 | +1.12% | gain |
| generic | pairing_bytes_seeded_4 | 1198.211 | 1187.211 | +0.92% | gain |

“Gain”/“loss” means both candidate 95% intervals lie wholly below/above
both baselines. Overlap does not establish equivalence; between-run
variation can also separate intervals for identical code.
