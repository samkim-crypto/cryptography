# G1/G2 optimization results

Branch: `bn254-g1-opt`. The cumulative baseline is `c9cf3a7`; both builds
use the same final harness, lockfile and fixture pool within each run.
Every complete-call measurement includes decoding, required validation,
arithmetic, per-call table setup, normalization and encoding.

The planned G01–G13 sequence is complete. Of the final four trials,
G13G's G1 setup estimate was retained; G13F, G13H and G13I were discarded
after measured regressions. Poseidon remains deferred.

Arkworks 0.5 is measured through the unchanged Solana syscall adapters.
Their affine integer multiplication uses binary multiplication. Firedancer is pinned to
`20c3fa1ff2dab737ec075c3e3e302ba778fd98fe`, built with GCC native ADX
and s2n-bignum disabled. Firedancer keeps its native C flags in every row;
the build labels select the Rust flags for ours and Ark. Results describe
this server and these builds.

Both jobs succeeded, were waited/fetched, and passed all queued correctness
checks. Retained production hashes, benchmark harness, lockfile, compiler
versions, build flags and measurement settings match across the two jobs.

Detailed candidate decisions and accepted control costs are in
[the experiment ledger](group-optimization-experiments.md). Raw Criterion
samples, confidence intervals, assembly and hashes remain in the fetched artifacts.

## Run 1: seed 0x6731673262656e31

Across 123 group and nine pairing rows: 132 separated gains, 0 separated losses, and 0 overlaps.

Fresh comparator timings, in microseconds. Each implementation uses
the same pool of eight rotating inputs per case; tables are rebuilt on every call.

| Build | Operation | Ours | Ark adapter | Firedancer |
| --- | --- | ---: | ---: | ---: |
| native | G1 addition | 1.064 | 2.999 | 7.151 |
| native | G2 addition | 1.571 | 4.421 | 7.756 |
| native | G1 multiplication, random256 | 33.791 | 81.048 | 56.386 |
| native | G2 checked multiplication, random256 | 90.871 | 452.982 | 185.641 |
| native_scalar | G1 addition | 1.066 | 3.006 | 7.163 |
| native_scalar | G2 addition | 1.561 | 4.430 | 7.767 |
| native_scalar | G1 multiplication, random256 | 33.764 | 79.345 | 56.455 |
| native_scalar | G2 checked multiplication, random256 | 100.457 | 450.799 | 185.945 |
| generic | G1 addition | 1.087 | 3.315 | 7.162 |
| generic | G2 addition | 1.583 | 4.691 | 7.745 |
| generic | G1 multiplication, random256 | 36.832 | 82.685 | 56.516 |
| generic | G2 checked multiplication, random256 | 105.852 | 433.845 | 185.706 |

Cumulative ABBA comparison against the original source. Positive percentages
mean lower latency. The two seeds are separate input pools, not repeated
measurements of identical inputs.

| Build | Operation | Original (µs) | Retained (µs) | Improvement | Intervals |
| --- | --- | ---: | ---: | ---: | --- |
| native | G1 addition | 1.343 | 1.066 | +20.62% | gain |
| native | G2 addition | 1.868 | 1.571 | +15.89% | gain |
| native | G1 multiplication, random256 | 36.869 | 33.789 | +8.35% | gain |
| native | G2 checked multiplication, random256 | 127.451 | 90.882 | +28.69% | gain |
| native_scalar | G1 addition | 1.342 | 1.067 | +20.51% | gain |
| native_scalar | G2 addition | 1.867 | 1.565 | +16.16% | gain |
| native_scalar | G1 multiplication, random256 | 36.832 | 33.777 | +8.29% | gain |
| native_scalar | G2 checked multiplication, random256 | 127.626 | 100.370 | +21.36% | gain |
| generic | G1 addition | 1.474 | 1.078 | +26.85% | gain |
| generic | G2 addition | 1.976 | 1.576 | +20.28% | gain |
| generic | G1 multiplication, random256 | 40.462 | 36.818 | +9.01% | gain |
| generic | G2 checked multiplication, random256 | 137.355 | 105.892 | +22.91% | gain |

Selected decoded-kernel checks, excluding byte decoding/encoding.

| Build | Case | Original (µs) | Retained (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| native | group_kernel_g2_raw_mul/solana-bn254 | 183.096 | 107.528 | +41.27% |
| native | group_kernel_g2_raw_mul_max/solana-bn254 | 271.133 | 76.643 | +71.73% |
| native | group_kernel_g2_subgroup_invalid/solana-bn254 | 37.332 | 31.469 | +15.70% |
| native | group_kernel_g2_subgroup_valid/solana-bn254 | 37.568 | 31.692 | +15.64% |
| native_scalar | group_kernel_g2_raw_mul/solana-bn254 | 183.574 | 126.030 | +31.35% |
| native_scalar | group_kernel_g2_raw_mul_max/solana-bn254 | 271.535 | 96.083 | +64.61% |
| native_scalar | group_kernel_g2_subgroup_invalid/solana-bn254 | 37.331 | 36.396 | +2.51% |
| native_scalar | group_kernel_g2_subgroup_valid/solana-bn254 | 37.582 | 36.634 | +2.52% |
| generic | group_kernel_g2_raw_mul/solana-bn254 | 199.286 | 134.987 | +32.26% |
| generic | group_kernel_g2_raw_mul_max/solana-bn254 | 290.341 | 103.206 | +64.45% |
| generic | group_kernel_g2_subgroup_invalid/solana-bn254 | 39.941 | 38.443 | +3.75% |
| generic | group_kernel_g2_subgroup_valid/solana-bn254 | 40.172 | 38.654 | +3.78% |

Pairing regression checks use their original independent fixture seed.

| Build | Case | Original (µs) | Retained (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| native | pairing_bytes_seeded_1/solana-bn254/le | 467.124 | 459.856 | +1.56% |
| native | pairing_bytes_seeded_16/solana-bn254/le | 3393.645 | 3322.051 | +2.11% |
| native | pairing_bytes_seeded_4/solana-bn254/le | 1055.900 | 1037.676 | +1.73% |
| native_scalar | pairing_bytes_seeded_1/solana-bn254/le | 518.737 | 514.919 | +0.74% |
| native_scalar | pairing_bytes_seeded_16/solana-bn254/le | 3632.531 | 3606.805 | +0.71% |
| native_scalar | pairing_bytes_seeded_4/solana-bn254/le | 1148.172 | 1141.236 | +0.60% |
| generic | pairing_bytes_seeded_1/solana-bn254/le | 536.871 | 530.966 | +1.10% |
| generic | pairing_bytes_seeded_16/solana-bn254/le | 3796.759 | 3758.609 | +1.00% |
| generic | pairing_bytes_seeded_4/solana-bn254/le | 1195.614 | 1186.188 | +0.79% |

- Job: `9d90278f4a66484294c32bd909c60a52`.
- Source fingerprint: `40e8c282c9635bda7c52f617cb48ca99cb49ca65929f094e2790b9cd93b126f4`.
- Fetched path: `/Users/samkim/.local/state/benchctl/results/9d90278f4a66484294c32bd909c60a52`.
- CPU 16; 100 samples, 1 s warm-up, 2 s requested measurement, ABBA.
- `native`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native`.
- `native_scalar`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native -C target-feature=-avx512ifma`.
- `generic`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=x86-64`.
- C compiler: `gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`.
- C flags: `-std=gnu17 -O3 -march=native -mtune=native -fPIC -ffp-contract=off -fno-math-errno -fno-strict-aliasing -DFD_USING_GCC=1 -DFD_HAS_OPTIMIZATION=1 -DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 -DFD_HAS_X86=1 -DFD_HAS_SSE=1 -DFD_HAS_AVX=1 -DFD_HAS_AVX512=1 -DFD_HAS_S2NBIGNUM=0`.
- Firedancer archive SHA-256: `b8e1cd1a9fef961a9889bb29e5818ca53fcdd13e36dae9b2a6e85dc8c637fa2a`.
- Cargo.lock SHA-256: `e5a60b6137d2138cb24fc8a14556030a8685f78eb6268f22d5558981ec229626`.

```sh
benchctl submit --json --label bn254-G-final-seed31 --timeout 2h --artifact group-experiment-results -- python3 scripts/benchmark-bn254-groups.py run --id G-final --seed 0x6731673262656e31 --comparison --comparison-variant candidate --comparison-filter 'group_bytes_g[12]_(add_random|mul_random256)/(solana-bn254|ark-bn254|firedancer)/le$' --pairing --filter 'group_bytes_g[12]_(add_(random|double)|mul_(random(64|80|96|128|144|192|256)|exact129|high_sparse|sparse|near_order|max|zero|one))/solana-bn254/le$|group_bytes_g2_add_full_twist/solana-bn254/le$|group_kernel_g2_(subgroup_(valid|invalid)|raw_mul(_(random128|high_sparse|max|zero|one))?)/solana-bn254$' --pairing-filter 'pairing_bytes_seeded_(1|4|16)/solana-bn254/le$'
```

## Run 2: seed 0x6731673262656e32

Across 123 group and nine pairing rows: 132 separated gains, 0 separated losses, and 0 overlaps.

Fresh comparator timings, in microseconds. Each implementation uses
the same pool of eight rotating inputs per case; tables are rebuilt on every call.

| Build | Operation | Ours | Ark adapter | Firedancer |
| --- | --- | ---: | ---: | ---: |
| native | G1 addition | 1.066 | 2.960 | 7.163 |
| native | G2 addition | 1.578 | 4.515 | 7.752 |
| native | G1 multiplication, random256 | 33.766 | 81.166 | 56.529 |
| native | G2 checked multiplication, random256 | 92.305 | 453.238 | 183.492 |
| native_scalar | G1 addition | 1.066 | 2.971 | 7.164 |
| native_scalar | G2 addition | 1.572 | 4.437 | 7.772 |
| native_scalar | G1 multiplication, random256 | 33.779 | 79.505 | 56.459 |
| native_scalar | G2 checked multiplication, random256 | 101.813 | 450.143 | 183.799 |
| generic | G1 addition | 1.080 | 3.271 | 7.171 |
| generic | G2 addition | 1.584 | 4.690 | 7.762 |
| generic | G1 multiplication, random256 | 36.850 | 81.998 | 56.663 |
| generic | G2 checked multiplication, random256 | 107.455 | 432.736 | 183.775 |

Cumulative ABBA comparison against the original source. Positive percentages
mean lower latency. The two seeds are separate input pools, not repeated
measurements of identical inputs.

| Build | Operation | Original (µs) | Retained (µs) | Improvement | Intervals |
| --- | --- | ---: | ---: | ---: | --- |
| native | G1 addition | 1.347 | 1.067 | +20.75% | gain |
| native | G2 addition | 1.854 | 1.582 | +14.71% | gain |
| native | G1 multiplication, random256 | 36.605 | 33.770 | +7.74% | gain |
| native | G2 checked multiplication, random256 | 127.259 | 92.349 | +27.43% | gain |
| native_scalar | G1 addition | 1.352 | 1.065 | +21.22% | gain |
| native_scalar | G2 addition | 1.873 | 1.573 | +16.02% | gain |
| native_scalar | G1 multiplication, random256 | 36.565 | 33.758 | +7.68% | gain |
| native_scalar | G2 checked multiplication, random256 | 127.053 | 101.806 | +19.87% | gain |
| generic | G1 addition | 1.470 | 1.078 | +26.68% | gain |
| generic | G2 addition | 1.968 | 1.582 | +19.62% | gain |
| generic | G1 multiplication, random256 | 40.105 | 36.821 | +8.19% | gain |
| generic | G2 checked multiplication, random256 | 136.311 | 107.253 | +21.32% | gain |

Selected decoded-kernel checks, excluding byte decoding/encoding.

| Build | Case | Original (µs) | Retained (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| native | group_kernel_g2_raw_mul/solana-bn254 | 183.404 | 107.192 | +41.55% |
| native | group_kernel_g2_raw_mul_max/solana-bn254 | 271.418 | 76.477 | +71.82% |
| native | group_kernel_g2_subgroup_invalid/solana-bn254 | 37.360 | 31.433 | +15.86% |
| native | group_kernel_g2_subgroup_valid/solana-bn254 | 37.548 | 31.652 | +15.70% |
| native_scalar | group_kernel_g2_raw_mul/solana-bn254 | 183.306 | 126.104 | +31.21% |
| native_scalar | group_kernel_g2_raw_mul_max/solana-bn254 | 271.738 | 95.909 | +64.71% |
| native_scalar | group_kernel_g2_subgroup_invalid/solana-bn254 | 37.470 | 36.314 | +3.08% |
| native_scalar | group_kernel_g2_subgroup_valid/solana-bn254 | 37.671 | 36.533 | +3.02% |
| generic | group_kernel_g2_raw_mul/solana-bn254 | 199.283 | 134.927 | +32.29% |
| generic | group_kernel_g2_raw_mul_max/solana-bn254 | 290.524 | 103.209 | +64.47% |
| generic | group_kernel_g2_subgroup_invalid/solana-bn254 | 39.969 | 38.439 | +3.83% |
| generic | group_kernel_g2_subgroup_valid/solana-bn254 | 40.172 | 38.646 | +3.80% |

Pairing regression checks use their original independent fixture seed.

| Build | Case | Original (µs) | Retained (µs) | Improvement |
| --- | --- | ---: | ---: | ---: |
| native | pairing_bytes_seeded_1/solana-bn254/le | 466.892 | 459.652 | +1.55% |
| native | pairing_bytes_seeded_16/solana-bn254/le | 3392.571 | 3320.734 | +2.12% |
| native | pairing_bytes_seeded_4/solana-bn254/le | 1055.625 | 1037.314 | +1.73% |
| native_scalar | pairing_bytes_seeded_1/solana-bn254/le | 519.080 | 515.479 | +0.69% |
| native_scalar | pairing_bytes_seeded_16/solana-bn254/le | 3635.768 | 3613.083 | +0.62% |
| native_scalar | pairing_bytes_seeded_4/solana-bn254/le | 1149.455 | 1143.429 | +0.52% |
| generic | pairing_bytes_seeded_1/solana-bn254/le | 538.243 | 532.281 | +1.11% |
| generic | pairing_bytes_seeded_16/solana-bn254/le | 3803.985 | 3761.512 | +1.12% |
| generic | pairing_bytes_seeded_4/solana-bn254/le | 1198.211 | 1187.211 | +0.92% |

- Job: `bea7e864d82f456089a46e1eea77457a`.
- Source fingerprint: `b27fcbfc85f4ab5277605916c879fde81f0e859db268032ffecdf0bd59893817`.
- Fetched path: `/Users/samkim/.local/state/benchctl/results/bea7e864d82f456089a46e1eea77457a`.
- CPU 16; 100 samples, 1 s warm-up, 2 s requested measurement, ABBA.
- `native`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native`.
- `native_scalar`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=native -C target-feature=-avx512ifma`.
- `generic`: rustc 1.98.0 (88d9e12ae 2026-08-18); `-C target-cpu=x86-64`.
- C compiler: `gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0`.
- C flags: `-std=gnu17 -O3 -march=native -mtune=native -fPIC -ffp-contract=off -fno-math-errno -fno-strict-aliasing -DFD_USING_GCC=1 -DFD_HAS_OPTIMIZATION=1 -DFD_HAS_INT128=1 -DFD_HAS_DOUBLE=1 -DFD_HAS_ALLOCA=1 -DFD_HAS_X86=1 -DFD_HAS_SSE=1 -DFD_HAS_AVX=1 -DFD_HAS_AVX512=1 -DFD_HAS_S2NBIGNUM=0`.
- Firedancer archive SHA-256: `b8e1cd1a9fef961a9889bb29e5818ca53fcdd13e36dae9b2a6e85dc8c637fa2a`.
- Cargo.lock SHA-256: `e5a60b6137d2138cb24fc8a14556030a8685f78eb6268f22d5558981ec229626`.

```sh
benchctl submit --json --label bn254-G-final-seed32 --timeout 2h --artifact group-experiment-results -- python3 scripts/benchmark-bn254-groups.py run --id G-final --seed 0x6731673262656e32 --comparison --comparison-variant candidate --comparison-filter 'group_bytes_g[12]_(add_random|mul_random256)/(solana-bn254|ark-bn254|firedancer)/le$' --pairing --filter 'group_bytes_g[12]_(add_(random|double)|mul_(random(64|80|96|128|144|192|256)|exact129|high_sparse|sparse|near_order|max|zero|one))/solana-bn254/le$|group_bytes_g2_add_full_twist/solana-bn254/le$|group_kernel_g2_(subgroup_(valid|invalid)|raw_mul(_(random128|high_sparse|max|zero|one))?)/solana-bn254$' --pairing-filter 'pairing_bytes_seeded_(1|4|16)/solana-bn254/le$'
```

An interval marked gain/loss means both candidate 95% intervals lie
wholly below/above both baselines. Between-run variation can also separate
intervals for identical code; overlap does not establish equivalence.
