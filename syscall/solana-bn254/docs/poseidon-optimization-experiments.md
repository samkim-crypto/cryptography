# Poseidon optimization experiments

Branch: `poseidon-opt-final`, based on `bn254-g1-opt` at `ef8e211`.
The retained G1/G2 and pairing changes are the starting point. PR #141 is
independent and is not changed by these experiments.

The proposed families P01–P12 are described in
[the optimization review](g1-g2-poseidon-optimization-review.md). Each candidate
is checked, measured against its saved baseline in ABBA order, and retained only
when the complete-operation measurements justify it. A discarded implementation
is restored from its checkpoint; its patch remains in the fetched job artifacts.

## Measurement controls

- All builds, correctness checks and measurements use the shared benchctl queue
  on `solana-devserver`, Rust 1.98.0, CPU 16 for timed work.
- Native IFMA: `-C target-cpu=native`; native scalar:
  `-C target-cpu=native -C target-feature=-avx512ifma`; generic x86:
  `-C target-cpu=x86-64`. Configurations and variants have separate build trees.
- Eight rotating seeded messages per input count, all counts 1–12.
  Typed inputs and complete little-endian byte adapters are reported separately.
  Parameter construction is amortized for both Rust libraries; Firedancer uses
  compiled tables. Byte adapters include validation, conversion and output
  serialization. Light Poseidon uses Arkworks field arithmetic.
- Every baseline/candidate benchmark executable checks agreement with
  Light Poseidon and Firedancer before timing. Candidate crate tests cover
  full permutation states, custom parameters, canonical field boundaries,
  chained arithmetic and the retained curve/pairing operations.
- Default: 100 samples, one-second warmup, two-second measurement request.
  ABBA uses the geometric mean of each variant's two estimates; confidence
  interval separation is recorded, not assumed from a point estimate.
- Firedancer revision `20c3fa1ff2dab737ec075c3e3e302ba778fd98fe`, no tracked changes.
  Source archive SHA-256:
  `f44203e8dae57ee255e15e88bdc03bf433d033c6443284196c83f96bb2ea02f5`.
  GCC native ADX build with optional s2n-bignum disabled. Its flags are held fixed
  while the Rust configurations are compared, and are recorded in each result.

## Trial ledger

| Family | Candidate | Status |
| --- | --- | --- |
| P01 | Native ADX/BMI2 Fr multiplication, existing assembly with Fr parameters and canonical-input proof | **Kept** after two message pools; 7.31–7.65% IFMA and 9.70–9.78% scalar mean byte-hash latency reductions |
| P02 | Dedicated scalar Fr squaring | **Discarded**: mean byte-hash latency increased 1.96% IFMA, 2.74% scalar, 5.00% generic |
| P03 | Dedicated IFMA Fr squaring | **Kept**: repeated 6.66% S-box-chain gain; small complete-hash gains, no separated regressions |
| P04 | Packed built-in constants | P04A **kept** (4.07% mean gain); P04B **discarded** (mixed, no overall gain) |
| P05 | Pre-scaled fixed IFMA operands | **Kept**: 0.373% mean gain, ten separated gains, no separated regressions |
| P06 | IFMA sparse partial-round matrices | **Kept**: 13.231% mean gain, eleven separated gains |
| P07 | Packed state across full rounds | **Kept P07C**: T5/T7..T13, 1.256% mean gain; P07A/B rejected |
| P08 | Fused scalar sums of products | **Kept**: 0.306% IFMA, 11.621% native scalar, 15.585% generic mean gains |
| P09 | Fused IFMA matrix dot products | **Kept**: 9.699% mean gain, eleven separated gains |
| P10 | Private R=2^260 permutation representation | **Discarded**: 0.645% slower, six separated regressions |
| P11 | Bounded lazy S-box intermediates | P11A **discarded**; P11B **kept**, 0.781% mean IFMA hash gain |
| P12 | Retune scalar/IFMA routing by width | **Kept P12A2** selected IFMA final rows; other routing trials discarded; family complete |

## P01 — Fr ADX multiplication

**Decision: keep.** Two independent message pools improve every native byte-hash
width. Both jobs were waited successfully and fetched. Shared curve/pairing
checks remain within 0.45%; the isolated S-box slowdown is recorded below.

- UUID: `93a33f52831648bc8c504f95a8a60a49`.
- Source fingerprint: `5f1ab671a558bed825380099f0384bbb0afcfd5267c9c5afe7a57c1ee0d48f5e`.
- Rust 1.98.0; all three flags configurations above, CPU 16, seed 41.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P01-fr-adx --seed 41 --comparison baseline`.
- Fetched results: `/Users/samkim/.local/state/benchctl/results/93a33f52831648bc8c504f95a8a60a49/outputs/poseidon-experiment-results`.
  Criterion data is inside that directory; the default `target/criterion`
  artifact is intentionally unused by this custom ABBA runner.
- Correctness: 239 native IFMA tests, 229 native scalar tests, 229 generic
  tests (697 total), plus baseline/candidate comparator smoke checks.
  Both variants agree with Light Poseidon and Firedancer at every input count.

Complete byte-hash latency reductions:

| Inputs | Native IFMA | Native scalar |
| --- | ---: | ---: |
| 1 | 2.562% | 4.256% |
| 2 | 5.254% | 5.936% |
| 3 | 7.268% | 8.524% |
| 4 | 7.407% | 8.042% |
| 5 | 8.415% | 9.015% |
| 6 | 9.059% | 10.328% |
| 7 | 9.396% | 10.451% |
| 8 | 8.547% | 11.325% |
| 9 | 8.685% | 11.217% |
| 10 | 8.341% | 12.083% |
| 11 | 8.919% | 12.246% |
| 12 | 7.764% | 12.609% |

All 48 native typed/byte hash rows have both candidate confidence intervals
below both baseline intervals. Geometric-mean byte latency reductions are
7.653% IFMA and 9.703% native scalar. Generic baseline/candidate benchmark
binaries have identical SHA-256 hashes; their small timing differences are
noise, not an optimization gain.

The scalar multiplication/squaring chains improve, but the isolated scalar
S-box chain regresses by about 16.05% in both native builds. Complete hashes
improve at every width; retain this caveat for the scalar-square/routing trials.
The baseline comparator results are in each configuration's `comparison.json`;
they are not candidate-versus-Firedancer measurements.

Confirmation:

- UUID: `95b38e537ad544fdbaa2cc6f15e6eab7`.
- Source fingerprint: `eea97dd141314b32ec39c87f6c417914f3f364d776d8fd09adfbf4b4cd23d290`.
- Rust 1.98.0; native IFMA and native scalar flags above, CPU 16, Poseidon
  and group seed 42. Pairing retains its fixed harness seed.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P01-fr-adx --seed 42 --configs native native_scalar --filter 'poseidon_bytes_.*/solana-bn254$' --regressions`.
- Fetched results: `/Users/samkim/.local/state/benchctl/results/95b38e537ad544fdbaa2cc6f15e6eab7/outputs/poseidon-experiment-results`.
- All 24 complete hash rows again have separated favorable intervals:
  native IFMA 2.561–9.363% (geometric mean 7.308%); native scalar
  4.381–12.640% (mean 9.779%). Production file hashes match the first job.
- Representative G1/G2 addition/multiplication and 1/4/16-pair calls show
  changes between a 0.448% slowdown and a 0.194% improvement. Native G2
  addition's 0.448% slowdown has separated intervals; the remaining regression
  rows overlap. This small effect is recorded, not claimed as an improvement
  or hidden in the Poseidon average. No curve/pairing case moves by 0.5%.
- Crate tests and all three libraries' benchmark contract checks passed in
  both builds. The next trial is P02, dedicated scalar Fr squaring.

## P02 — dedicated scalar Fr squaring

Candidate: parameterize the retained integer-square/REDC kernel for Fq and Fr,
then use it for Fr squares instead of ADX `mul(a,a)`. Canonical input gives
`a² < r² < rR`; REDC returns below `2r < R` before its final subtraction.
Other field implementations retain their existing fallback.

The existing Fr square boundary/random/chain oracles and full-state/custom
Poseidon tests cover the new dispatch. Shared Fq square code is checked by
representative curve/pairing ABBA measurements as well as crate tests. This
trial times all twelve complete byte hash calls and the four arithmetic chains
in all three configurations; the initial job already established typed-input
and external-library baselines.

**Decision: discard and restore P01.** All correctness checks passed, but the
candidate slows complete hashes in all three configurations. The guarded
restore verified the measured candidate hashes before restoring both source
files; the candidate patch remains in the fetched results.

- UUID: `7d8efd4dbb634d5b9892d33c1beac312`; wait exit status 0, fetched.
- Source fingerprint: `21f6c1d3e7392683c8d9f2b45fb30a8ed9c692b79d7dfb5dd324cfbb70f06a8b`.
- Rust 1.98.0, all three flags configurations above, CPU 16, seed 43.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P02-fr-square --seed 43 --filter 'poseidon_bytes_.*/solana-bn254$|scalar_arithmetic/' --regressions`.
- Fetched results: `/Users/samkim/.local/state/benchctl/results/7d8efd4dbb634d5b9892d33c1beac312/outputs/poseidon-experiment-results`.

| Configuration | Mean byte-hash latency increase | Separated regressions / 12 hashes | Square-chain latency increase |
| --- | ---: | ---: | ---: |
| Native IFMA | 1.957% | 9 | 8.628% |
| Native scalar | 2.744% | 12 | 8.346% |
| Generic x86 | 4.996% | 12 | 18.148% |

No complete-hash row has separated favorable intervals. Fewer integer products
do not compensate for this square/reduction schedule on the measured CPU.

## P03 — dedicated IFMA Fr squaring

Candidate: square `4a` with fifteen distinct 52-bit products, then reduce with
`R=2^260` to obtain the existing `R=2^256` square. Cross terms are accumulated
once and doubled before adding diagonal terms. The kernel documents accumulator
and REDC bounds, normalizes limbs, and returns canonical residues. The IFMA
S-box uses two of these squares and one existing multiplication.

Independent Arkworks tests cover mixed lane boundaries, 4096 random lanes,
repeated squaring, exact raw residues, and normalization before unpacking.
An added IFMA S-box chain diagnoses the kernel; all twelve complete byte hash
cases decide retention. Only the IFMA module changes, so this trial measures the
native IFMA configuration. Scalar/generic production paths are unchanged.

- UUID: `f90a05d58b574bc09920af62a5abe59b`; wait exit 0, fetched.
- Source fingerprint: `c2111f74352a71b3d4159fd5cdd83236bf352618e1594ad2325cae6a411d3689`.
- Rust 1.98.0, `-C target-cpu=native`, CPU 16, seed 44.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P03-ifma-square --seed 44 --configs native --filter 'poseidon_bytes_.*/solana-bn254$|ifma_arithmetic/'`.

Initial result: 240 native crate tests and comparator checks pass. Mean byte-hash
latency is 0.290% lower, with six separated gains and no separated regressions;
the IFMA S-box chain is 6.660% faster. This small whole-hash gain needs confirmation.
Fetched results: `/Users/samkim/.local/state/benchctl/results/f90a05d58b574bc09920af62a5abe59b/outputs/poseidon-experiment-results`.

Confirmation:
- UUID: `9c9bd68c371f490bb866e38a80d53f7a`.
- Source fingerprint: `8bbfc56924d0ef6601f7a625d686dccdcdf555f7e4006fc7092515c20cbb0d5b`.
- Same Rust/native flags and CPU; seed 45, four-second measurement request.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P03-ifma-square --seed 45 --configs native --measurement 4 --filter 'poseidon_bytes_.*/solana-bn254$|ifma_arithmetic/'`.

**Decision: keep P03.** The second pool passes all correctness checks again;
the IFMA S-box chain repeats its 6.660% improvement. Mean complete byte-hash
latency is 0.444% lower, with four separated gains and no separated regressions.
T2/T5/T7 have separated gains in both jobs. Some other widths overlap and four
have slightly negative point estimates in the repeat; this is a small benefit,
not evidence of a significant speedup at every width. The largest apparent
repeat gains (T12/T13) have noisy baseline intervals and are not relied on.
The measured production candidate file hashes match across the two jobs.

Confirmation was waited with exit 0 and fetched to
`/Users/samkim/.local/state/benchctl/results/9c9bd68c371f490bb866e38a80d53f7a/outputs/poseidon-experiment-results`.

## P04A — prepacked dense matrix columns

Candidate: const-evaluate aligned IFMA columns from the existing public scalar
MDS and pre-sparse tables. A width and table-identity lookup selects them;
custom tables retain runtime packing. The public parameter structure and
numeric parameters are unchanged. Existing full-state, custom T2..T13/T17,
and external-library oracle checks cover both paths.

**Decision: keep P04A.** All native correctness checks pass. Every byte-hash
width has separated favorable intervals; mean latency falls 4.074%, ranging
from 0.100% (one input) to 8.482% (twelve inputs). Eight through twelve inputs
improve by 7.11–8.48%.

- UUID: `8b67ad23cbbe452b883dc30fdd17a7e8`; wait exit 0, fetched.
- Source fingerprint: `37976087204de8856f8a576ce984aa5e86baef27cf2a0b52f03f5c68a1edf62b`.
- Rust 1.98.0, native IFMA flags, CPU 16, seed 46, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P04A-packed-dense --seed 46 --configs native --filter 'poseidon_bytes_.*/solana-bn254$'`.
- Results: `/Users/samkim/.local/state/benchctl/results/8b67ad23cbbe452b883dc30fdd17a7e8/outputs/poseidon-experiment-results`.

## P04B — prepacked full-round constants

Candidate: const-evaluate full-round constant vectors and add them to the
already packed state before the IFMA S-box. Custom parameters retain scalar
constant addition. Lookup checks the table identity, round counts and offset;
a new metamorphic test covers a custom schedule reusing the built-in RC slice
versus an equal-valued copied slice, at all twelve supported widths.

- UUID: `8773beaa95e7431da5df086aa6162343`; wait exit 0, fetched.
- Source fingerprint: `a7f21a61b04f111da583267b519f4b55918dd278ac4eaefdb5c47c183ffa28a8`.
- Rust 1.98.0, native IFMA flags, CPU 16, seed 47, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P04B-packed-rounds --seed 47 --configs native --filter 'poseidon_bytes_.*/solana-bn254$'`.

**Decision: discard P04B and restore P04A.** Correctness passes, including the
custom-schedule cases, but mean byte-hash latency increases 0.081%. Four widths
have separated gains and four have separated regressions. The gain is not broad
enough to retain the extra path; round-constant packing can be reconsidered in
P07 when state also stays packed across dense layers. The guarded restore
verified and restored all three candidate files. Its patch is preserved.
Results: `/Users/samkim/.local/state/benchctl/results/8773beaa95e7431da5df086aa6162343/outputs/poseidon-experiment-results`.

## P05 — fixed IFMA coefficient radix

Candidate: const-evaluate each packed matrix coefficient as `16*c mod r`.
A private raw R260 reduction then multiplies it by the existing R256 state
without a runtime input shift. Custom matrices and general public multiplication
keep their existing correction. Coefficients stay canonical, so REDC is below
2r and the existing final subtraction remains valid. Independent raw Arkworks
oracles cover limb boundaries, mixed lanes, random operands, repeated products,
and normalization before unpacking; complete hash/full-state oracles cover the
constant-table conversion.

- UUID: `f1fde19dc72a499badf93553321bb9f8`; wait exit 0, fetched.
- Source fingerprint: `49618bc853047448af2d562ddfc090e8b0e502391310f53c714443ef6d163ec1`.
- Rust 1.98.0, native IFMA flags, CPU 16, seed 48, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P05-fixed-operands --seed 48 --configs native --filter 'poseidon_bytes_.*/solana-bn254$|ifma_arithmetic/'`.

**Decision: keep P05.** All 241 native tests and comparator checks pass. Mean
byte-hash latency decreases 0.373%, with ten separated gains and no separated
regressions. T2 and T6 overlap with negligible negative point estimates
(-0.021% and -0.069%); the other widths improve 0.108–0.842%. The general IFMA
S-box chain is unchanged within noise (-0.007%).
Results: `/Users/samkim/.local/state/benchctl/results/f1fde19dc72a499badf93553321bb9f8/outputs/poseidon-experiment-results`.

## P06 — IFMA sparse partial-round products

Candidate: prepack the T row products followed by the T-1 column products into
one stream of IFMA lanes. Widths T2/T3/T4 need only one vector multiplication
per partial round; wider widths need two to four. Gather row inputs before
column updates, cache the old state[0], and sum canonical terms. The single
S-box remains scalar. Built-in sparse-slice identity enables the fast path;
copied/custom tables retain scalar arithmetic. New copied-table tests compare
both paths, alongside the independent full-state and external-library oracles.

- UUID: `a72932ebf10c47c3ac31c733400b8124`; wait exit 0, fetched.
- Source fingerprint: `75d4953724363122473b800949a0f7d7afd357a7237c9cf6136697482a31290c`.
- Rust 1.98.0, native IFMA flags, CPU 16, seed 49, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P06-sparse-ifma --seed 49 --configs native --filter 'poseidon_bytes_.*/solana-bn254$'`.

**Decision: keep P06.** All 253 native tests and comparator checks pass.
Mean byte-hash latency falls 13.231%; eleven of twelve widths have separated
gains and none regress. The three-input case improves 23.496%. The four-input
case's 0.345% point estimate overlaps; other improvements range 1.239–19.605%.
Results: `/Users/samkim/.local/state/benchctl/results/a72932ebf10c47c3ac31c733400b8124/outputs/poseidon-experiment-results`.

## P07 — packed state across full-round layers

Candidate: retain one/two IFMA chunks through full-round constant addition,
S-boxes and dense matrices; broadcast matrix inputs from packed lanes. Convert
at the partial-round boundaries, and keep the scalar final-row pruning for
hash-only calls. Built-in table identity/count checks select the path; arbitrary
custom parameters retain the general implementation, including T17. The partial
rounds use one shared helper. Round-constant packing is reconsidered here as
part of a different state representation, not as a reintroduction of P04B's
per-layer packing. Custom schedules reusing the RC slice get explicit tests.

- UUID: `d0762230a72b4f7086ee5eb9d39a5418`; wait exit 0, fetched.
- Source fingerprint: `8d62e0616591f29b2e2e7711b5c7bb411806b052e4e9a1cdece7f1be39e15c81`.
- Rust 1.98.0, native IFMA flags, CPU 16, seed 50, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P07-packed-state --seed 50 --configs native --filter 'poseidon_bytes_.*/solana-bn254$'`.

**P07A decision: reject the all-width candidate.** Correctness passes and the
mean improves 2.860%, but T2 and T3 have separated regressions of 2.300% and
1.083%. Nine larger widths improve; T4 overlaps. The guarded restore completed,
and the measured patch is preserved at
`/Users/samkim/.local/state/benchctl/results/d0762230a72b4f7086ee5eb9d39a5418/outputs/poseidon-experiment-results`.

P07B keeps the same retained P06 baseline and adds a compile-time T>=5 gate
for packed full rounds. It is a separate measured variant, not an unmeasured
claim that a gate solves the regressions. Seed 51 repeats every width.

- P07B UUID: `c482d02979f14e7488e898d7bbbb6be9`; wait exit 0, fetched.
- Source fingerprint: `28e6fb8a56b3a5d5045d87e1375ef0394aad42f736ddcd80fba82a25c14000ce`.
- Rust 1.98.0, native IFMA flags, CPU 16, seed 51, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P07B-packed-wide --seed 51 --configs native --filter 'poseidon_bytes_.*/solana-bn254$'`.

**P07B decision: reject and restore P06.** All correctness checks pass. Mean
latency improves 1.114%, but T6 regresses 2.821% and T3 regresses 0.285% with
separated intervals. The wider wins mostly repeat at a smaller magnitude; the
first job's largest estimates are not representative of every input pool.
Results: `/Users/samkim/.local/state/benchctl/results/c482d02979f14e7488e898d7bbbb6be9/outputs/poseidon-experiment-results`.

P07C selects T5 and T7..T13 and preserves the original fallback loop/lookup
placement. Only the packed route uses the extracted partial-round helper.
It again compares against the retained P06 source, using seed 52.

- P07C UUID: `7e50bb2d73714905ad903bf81cf05fc5`; wait exit 0, fetched.
- Source fingerprint: `2555d659681d8664664508fb92446b51a27c72270d3b6bbb0a6c93a74e93c1ad`.
- Rust 1.98.0, native IFMA flags, CPU 16, seed 52, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P07C-packed-selected --seed 52 --configs native --filter 'poseidon_bytes_.*/solana-bn254$'`.

**P07C decision: keep.** All 265 native tests and comparator checks pass.
Every selected width has separated gains, ranging 1.447–2.844%; the all-width
mean decreases 1.256%. No width has separated regressions. T2/T3/T4 stay
within 0.03%; the inactive T6's -0.482% point estimate overlaps and is recorded
as noise, not as a gain. P07's earlier broad estimates are superseded by this
measured selection.
Results: `/Users/samkim/.local/state/benchctl/results/7e50bb2d73714905ad903bf81cf05fc5/outputs/poseidon-experiment-results`.

## P08 — fused scalar sums of products

Candidate: use four-term CIOS chunks for sparse first rows, final hash rows,
and scalar dense matrices. The intermediate bound `t<sum(b)+r<=5r<R256`
keeps the five-limb accumulator intact, and `4r²<rR256` ensures one final
subtraction per chunk. Independent Arkworks tests cover boundary/random dots,
lengths crossing chunk boundaries, and custom widths up to T17. This is a
Fr-only helper; it does not relax the public backend's canonical contract.
All three configurations are measured because scalar call sites are shared.

- P08 UUID: `013dfada118b4e53bfd4ae5be79159ab`; wait exit 0, fetched.
- Source fingerprint: `2f1f6479183c1b852ba8e5b8ad430584e6f38eee14488776550ea01c6615647c`.
- Rust 1.98.0, all three flags configurations, CPU 16, seed 53, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P08-scalar-dots --seed 53 --filter 'poseidon_bytes_.*/solana-bn254$'`.

**Decision: keep P08 in all configurations.** All correctness checks pass.
Native scalar improves at every width by 3.712–18.105% (mean 11.621%); generic
improves 9.727–22.776% (mean 15.585%). IFMA improves 0.306% on average with
eight separated gains; three small negative estimates overlap. No configuration
has separated regressions. Results:
`/Users/samkim/.local/state/benchctl/results/013dfada118b4e53bfd4ae5be79159ab/outputs/poseidon-experiment-results`.

## P09 — fused IFMA matrix dots

Candidate: accumulate up to thirteen lane products in ten vectors, then share
five REDC steps and one final subtraction. Coefficients remain canonical R260
values. `13r²<rR260` bounds the result below 2r; the documented product-half
count bounds every lane accumulator below 2^64. Built-in dense maps use this
kernel in both packed-state and scalar-boundary paths; custom matrices retain
the general multiplication loop. Independent Arkworks tests cover 1/2/4/8/13
terms, maximum canonical inputs, mixed lanes, random inputs, chains, and limb
normalization before unpacking.

- P09 UUID: `19b983b801eb4320815b1feb029880b3`; wait exit 0, fetched.
- Source fingerprint: `528c88fda42becc287dda4623176432cede43b6ea3e8c42e9ef9b309dafc6488`.
- Rust 1.98.0, native IFMA flags, CPU 16, seed 54, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P09-ifma-dots --seed 54 --configs native --filter 'poseidon_bytes_.*/solana-bn254$'`.

**Decision: keep P09.** All 267 native tests and comparator checks pass.
Mean byte-hash latency falls 9.699%, with positive point estimates at every
width (3.137–16.537%). Eleven widths have separated gains; T6 overlaps. No
width has a separated regression. Results:
`/Users/samkim/.local/state/benchctl/results/19b983b801eb4320815b1feb029880b3/outputs/poseidon-experiment-results`.

## P10 — private R260 permutation

Candidate: convert selected built-in states to R260 at entry, scale additive
constants at compile time, and use raw R260 IFMA squares/products. Matrix
coefficients/kernels already preserve this radix. The serial R256 x^5 incurs
16^4, corrected once by division by 2^16 modulo r; r==1 mod 2^28 permits a
four-small-product, five-limb correction with canonical output. Convert state0
back for hashes, or every coordinate for full permutations. Other widths and
custom full-round tables retain the existing path. The tested selection remains
T5/T7..T13, so unchanged widths are controls rather than R260 measurements.
Independent raw-R260 S-box and modular-division tests supplement the complete
permutation and custom-parameter oracles.

- P10 UUID: `ae1c989c24f6427e875002b85b39b6ce`; wait exit 0, fetched.
- Source fingerprint: `e7471483004dd1478cf8e9128453685f8f56e97d4150273c71ac03964eed268b`.
- Rust 1.98.0, native IFMA flags, CPU 16, seed 55, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P10-radix260 --seed 55 --configs native --filter 'poseidon_bytes_.*/solana-bn254$|ifma_arithmetic/'`.


**Decision: discard P10 and restore P09.** All 269 native tests and comparator
checks pass, but complete hashes slow by 0.645% on average. Six widths have
separated regressions and none has a separated gain. Among the selected widths,
T5 regresses 4.229%, T7 0.311%, T9 1.532%, T11 0.506%, T12 0.690%, and
T13 0.517%; T8/T10 overlap. Unchanged widths and the public R256 S-box chain
remain within noise. The guarded restore verified and restored all four files.
This rejects this prototype, rather than all possible R260 implementations.
Results: `/Users/samkim/.local/state/benchctl/results/ae1c989c24f6427e875002b85b39b6ce/outputs/poseidon-experiment-results`.

## P11 — bounded lazy S-box intermediates

P11A candidate: inline Fr-only CIOS multiplication with private inputs/output
below 2r, then canonicalize once after two squares and a multiplication.
`4r<R256` ensures `ab<rR256` and REDC<2r; the CIOS invariant
`t<b+r<3r<R256` bounds the carry. Public backend contracts are unchanged.
On native scalar paths this also replaces native ADX assembly with inline
Rust CIOS; the timing measures both changes together. Independent BigUint
oracles check intermediate bounds, maximum lazy inputs, limb boundaries,
random products, exact raw x^5, and chains. All three configurations are tested.

- P11A UUID: `17b0dab24f9b4c75b810c02886ad305c`; wait exit 0, fetched.
- Source fingerprint: `6e5b4feecf1fe7d31566b258bc18b8e2f386bb310ebde5ba5bfd288130c24234`.
- Rust 1.98.0, all three flags configurations, CPU 16, seed 56, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P11A-scalar-lazy --seed 56 --filter 'poseidon_bytes_.*/solana-bn254$|scalar_arithmetic/'`.


**P11A decision: discard and restore P09.** Correctness passes in all three
configurations. Native means improve, but the benefit is inconsistent by width:

| Configuration | Mean byte-hash latency reduction | Separated gains | Separated regressions |
| --- | ---: | ---: | ---: |
| Native IFMA | 0.841% | 8 | 1 (T4: -0.893%) |
| Native scalar | 0.743% | 6 | 3 (T8/T12/T13: -0.154%/-1.501%/-0.869%) |
| Generic x86 | -0.127% | 7 | 5 (largest: T2 -2.354%) |

The isolated scalar S-box improves 10.22–10.25% in native builds, but worsens
4.175% in generic. This is insufficient to retain a change that regresses
complete hashes. The guarded restore completed both files; the new scalar
S-box module is removed. Results:
`/Users/samkim/.local/state/benchctl/results/17b0dab24f9b4c75b810c02886ad305c/outputs/poseidon-experiment-results`.

P11B candidate: keep normalized IFMA square outputs below 2r through x²/x⁴,
and canonicalize the final multiplication. `16(2r)²<rR260` follows from
`4r<R256`, so both square intermediates and the final product fit the existing
reduction schedule. No limb normalization is removed. The public multiplication
contract stays canonical; the S-box calls the private broader-bound kernel.
Independent BigUint tests cover maximum lazy inputs, mixed lane boundaries,
random inputs, repeated lazy squares, integer bounds before modular equality,
normalized limbs before unpacking, and exact canonical x⁵ outputs.

The user revoked the planned pause after P11. Continue through P12 and the
fresh final comparison after the P11B decision.

- P11B UUID: `e9cbcec8e90e4e599de0bae92aeaa733`; wait exit 0, fetched.
- Source fingerprint: `f957b2bf0f7e9618bb9d70993134954699caaf1198b6b972418db4b0f476ad64`.
- Rust 1.98.0, native IFMA flags, CPU 16, seed 57, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P11B-ifma-lazy --seed 57 --configs native --filter 'poseidon_bytes_.*/solana-bn254$|ifma_arithmetic/'`.


**P11B decision: keep.** All 268 native tests and comparator checks pass.
Mean complete byte-hash latency falls 0.781%; all twelve point estimates
improve (0.502–1.066%), eleven have separated gains, and none regresses.
T6 overlaps. The IFMA S-box chain improves 10.287%. Candidate source hashes
match the fetched metadata. Results:
`/Users/samkim/.local/state/benchctl/results/e9cbcec8e90e4e599de0bae92aeaa733/outputs/poseidon-experiment-results`.

## P12 — scalar/IFMA routing with the retained kernels

P12A candidate: prepack the final dense row into one/two coefficient vectors,
use IFMA products and a scalar horizontal sum, and consume the already packed
state directly when available. Custom matrix identities keep the P08 scalar
dot fallback. Compare every built-in width before choosing a route; no other
matrix rows are computed for hash-only calls.

- P12A UUID: `1cf0ff79e7d347fb869751898ece9006`; wait exit 0, fetched.
- Source fingerprint: `352fb2d9c05a7932f8fff8c9cd0eed712ba17b26b7e73107f75d4ff8168f6ae2`.
- Rust 1.98.0, native IFMA flags, CPU 16, seed 58, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P12A-ifma-row0 --seed 58 --configs native --filter 'poseidon_bytes_.*/solana-bn254$'`.


**P12A decision: reject the all-width version.** All correctness checks pass,
but mean complete-hash latency increases 0.112%. T2/T3/T6 regress by
0.500%/0.927%/3.558%, with separated intervals. Five widths have separated
gains: T4 0.351%, T5 0.398%, T8 1.357%, T9 0.757%, and T12 0.210%.
Other widths overlap. The guarded restore completed all three files.
Results: `/Users/samkim/.local/state/benchctl/results/1cf0ff79e7d347fb869751898ece9006/outputs/poseidon-experiment-results`.

P12A2 selects only those five widths for IFMA final-row arithmetic and preserves
the prior scalar path at every other width. It is measured against the retained
P11B baseline with a new input pool, rather than assuming the selection works.

- P12A2 UUID: `236dc047b0394010b1c4998a5b97e99d`; wait exit 0, fetched.
- Source fingerprint: `548e4185c3d1db30b0d3851ab2c45f01d69e42ad40fb9de5d3e375f4672bde49`.
- Rust 1.98.0, native IFMA flags, CPU 16, seed 59, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P12A2-selected-row0 --seed 59 --configs native --filter 'poseidon_bytes_.*/solana-bn254$'`.


**P12A2 decision: keep, with a small recorded T2 tradeoff.** Correctness passes.
The main selected-width gains repeat: T4 0.322%, T5 0.376%, T8 1.597%, and
T9 0.774%, all separated. T12 improves 0.119% but overlaps in this pool.
The all-width mean falls 0.393%. The unchanged T2 route has a separated
0.073% regression (5.87 ns); retain the repeated selected-width gains while
recording this small cost rather than calling the result regression-free.
Unselected T7/T10 also improve; those changes cannot be attributed directly to
IFMA final-row arithmetic. All other points improve or overlap. Candidate
source hashes match the fetched metadata. Results:
`/Users/samkim/.local/state/benchctl/results/236dc047b0394010b1c4998a5b97e99d/outputs/poseidon-experiment-results`.

P12B candidate: remove the old T2/T3/T4/T6 exclusion from packed full rounds,
now that fused matrix dots and lazy IFMA S-boxes have changed their costs.
Keep the selected final-row routes. This measures every width against P12A2;
only those four widths intentionally change full-round representation.

- P12B UUID: `b5fe7925e16d44ceb27c96ae7f929b65`; wait exit 0, fetched.
- Source fingerprint: `33bc520a5e9c94002ce79c93f0578801a04d0d95ac593f4c16915349909cc8c3`.
- Rust 1.98.0, native IFMA flags, CPU 16, seed 60, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P12B-packed-all --seed 60 --configs native --filter 'poseidon_bytes_.*/solana-bn254$'`.


**P12B decision: discard the all-width packed-state version.** Correctness
passes, but mean latency increases 0.462%. T2/T3 regress 2.470%/2.035%,
T4 overlaps, and T6 improves 0.709%. Unchanged T7/T8/T9 also regress with
separated intervals (1.189%/0.190%/0.272%), demonstrating why each routing
variant must be measured as compiled. The guarded restore completed.
Results: `/Users/samkim/.local/state/benchctl/results/b5fe7925e16d44ceb27c96ae7f929b65/outputs/poseidon-experiment-results`.

P12B2 adds only T6 to the packed-state selection. It compares against retained
P12A2 with a new message pool; all widths are measured again.

- P12B2 UUID: `a8c9dc7e8a564ffd832c6374e3362418`; wait exit 0, fetched.
- Source fingerprint: `f2b65a86ab4f2617e3e31b897ba5f80f0648ac813403acf3049253310f8f5248`.
- Rust 1.98.0, native IFMA flags, CPU 16, seed 61, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P12B2-packed-t6 --seed 61 --configs native --filter 'poseidon_bytes_.*/solana-bn254$'`.


**P12B2 decision: discard and restore P12A2.** Correctness passes. T6 improves
1.129%, but T5/T7 regress 0.254%/0.941% with separated intervals. Other
widths overlap and the mean is 0.048% slower. The selective gate does not earn
its compiled effects on other widths. The original T5/T7..T13 packed-state
selection is retained. Results:
`/Users/samkim/.local/state/benchctl/results/a8c9dc7e8a564ffd832c6374e3362418/outputs/poseidon-experiment-results`.

P12C candidate: use the existing scalar S-box and P08 fused scalar matrix dots
for full rounds at every built-in width. Keep IFMA sparse partial-round
products and the retained final-row selection. This directly measures scalar
versus IFMA full-round execution, including underfilled narrow SIMD states.
Custom widths outside 2..13 retain their prior general path.

- P12C UUID: `6210848d0f0f4e42a45c62ee3c9644c8`; wait exit 0, fetched.
- Source fingerprint: `046c3d3ec635191862dba58db7f8ab41abc2833e19558639229e345d90f3476f`.
- Rust 1.98.0, native IFMA flags, CPU 16, seed 62, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P12C-scalar-full --seed 62 --configs native --filter 'poseidon_bytes_.*/solana-bn254$'`.


**P12C decision: reject the all-width scalar-full-round version.** Correctness
passes, but eleven widths regress by 8.533–62.438%; the mean is 32.277% slower.
Only T2 improves, by 0.767% with separated intervals. The guarded restore
completed both files. Results:
`/Users/samkim/.local/state/benchctl/results/6210848d0f0f4e42a45c62ee3c9644c8/outputs/poseidon-experiment-results`.

P12C2 selects scalar S-box/dense full-round layers only for T2 (one input).
The existing packed-state gate already excludes T2, so simd.rs is unchanged.
All other widths retain their previous layers. This last P12 confirmation
measures every input count against retained P12A2 with a new input pool.

- P12C2 UUID: `c5d1b1d2f91a4d449c6b3009d2c6d060`; wait exit 0, fetched.
- Source fingerprint: `70d16e99794c3be602f02df4d29bcaf81711754d5ad2c207ab58d6cbae191cb7`.
- Rust 1.98.0, native IFMA flags, CPU 16, seed 63, default sampling controls.
- Command: `python3 scripts/benchmark-bn254-poseidon.py run --id P12C2-scalar-t2 --seed 63 --configs native --filter 'poseidon_bytes_.*/solana-bn254$'`.


**P12C2 decision: discard and restore P12A2.** Correctness passes. T2 improves
0.476%, but T4 regresses 0.474%, both with separated intervals. The overall
point estimate is 0.575% slower; large apparent losses at T6/T9 vary between
passes and overlap, so they are not treated as established regressions.
The isolated narrow-width gain does not justify the confirmed T4 cost and
inconsistent overall result. The guarded restore completed. Results:
`/Users/samkim/.local/state/benchctl/results/c5d1b1d2f91a4d449c6b3009d2c6d060/outputs/poseidon-experiment-results`.

**P12 is complete.** Keep the P12A2 final-row selection at T4/T5/T8/T9/T12
(inputs 3/4/7/8/11). Full rounds retain IFMA execution with the earlier
T5/T7..T13 packed-state gate. Scalar/generic full-round routes are unchanged.
No planned optimization families remain. Final combined validation/comparison
is complete below.

## Final retained source versus the starting revision

The final job compares retained production/test source against `ef8e211` in
all three configurations with one frozen harness and new input pool (seed 64).
It measures the complete byte hashes in ABBA order and fresh candidate typed
and byte library comparisons. Source comments/formatting are finalized before
the snapshot. Total gains below come from this direct comparison, not from multiplying
the incremental trial estimates.

For this final comparison, `--ark-asm` explicitly enables Arkworks 0.5.0's
optional assembly feature, which the workspace's default dependency settings
do not enable. Native targets can use its ADX/BMI2 path; the generic target
still selects portable arithmetic. Baseline and candidate get the same feature
setting. Earlier trial/comparator results used Arkworks defaults. Production
Cargo manifests and Cargo.lock are unchanged. Firedancer retains its pinned
native GCC/ADX configuration for all three Rust configurations.

- Final UUID: `4b698daff36e4b7a9e9eeb1b7b9b5290`; wait exit 0, fetched.
- Source fingerprint: `ad1c6653cf422bf8ed4ec399381e872b62e277a661fed5d316a55ca50d11d595`.
- Rust 1.98.0, all three flag configurations above, CPU 16, seed 64;
  100 samples, one-second warmup, two-second measurement request.
- Submitted command:
  `benchctl submit --json --label poseidon-final-vs-start --timeout 2h --artifact poseidon-experiment-results -- python3 scripts/benchmark-bn254-poseidon.py run --id P-final-vs-start --seed 64 --comparison candidate --ark-asm --filter 'poseidon_bytes_.*/solana-bn254$'`.

**Final result: complete.** The job succeeded (wait exit 0) and was fetched.
All 268 native IFMA, 254 native scalar, and 254 generic unit/integration test
executions passed (776 total), along with baseline/candidate agreement checks
against Light Poseidon and Firedancer. All 36 complete-hash comparisons against
`ef8e211` have separated favorable confidence intervals; none regresses.

Current hashes match the fetched candidate for all ten source/test paths
(including the absent, discarded scalar S-box module), the benchmark, and the
runner. Cargo manifests and Cargo.lock are unchanged. The final source remains
on `poseidon-opt-final` as working-tree changes; no commits or pushes were made.

Hardware: AMD EPYC 9354P, CPU 16. Rust 1.98.0 (`88d9e12ae`, 2026-08-18);
Firedancer compiled with GCC 13.3.0. These are measurements on this server,
with the flags and controls above. Light Poseidon 0.4.0 uses Arkworks 0.5.0;
its optional assembly feature is enabled for the final comparison.

Geometric means across all twelve complete byte-hash input counts:

| Build | Latency decrease vs start | Speedup vs Firedancer | Speedup vs Light Poseidon / Arkworks |
| --- | ---: | ---: | ---: |
| Native IFMA | 33.02% | 1.90× | 5.20× |
| Native scalar (IFMA disabled) | 20.36% | 1.37× | 3.73× |
| Generic x86 | 15.55% | 1.29× | 3.61× |

All three builds beat both comparison libraries at every input count.
IFMA is fastest from two through twelve inputs. At one input, generic x86
is fastest in this run (7.684 µs), followed by native scalar (7.816 µs),
then native IFMA (8.122 µs). The geometric means do not hide that exception.

### Direct improvement by input count

Percent decrease in latency against the frozen starting source, using ABBA:

| Inputs | Native IFMA | Native scalar | Generic x86 |
| --- | ---: | ---: | ---: |
| 1 | 8.64% | 7.90% | 9.99% |
| 2 | 24.92% | 15.19% | 16.27% |
| 3 | 35.95% | 20.79% | 19.88% |
| 4 | 17.23% | 15.32% | 10.84% |
| 5 | 23.14% | 18.71% | 13.61% |
| 6 | 30.98% | 19.22% | 13.82% |
| 7 | 38.26% | 25.20% | 19.29% |
| 8 | 37.81% | 21.34% | 13.83% |
| 9 | 39.87% | 24.67% | 16.12% |
| 10 | 42.53% | 22.90% | 15.21% |
| 11 | 45.75% | 28.30% | 22.80% |
| 12 | 41.22% | 22.73% | 13.99% |

### Native IFMA library comparison

Complete little-endian byte calls; times are microseconds. Speedup is the
comparison library’s latency divided by this crate’s latency. Firedancer uses
its native GCC/ADX build even in the generic-Rust comparison.

| Inputs | This crate (µs) | Firedancer (µs) | Speedup vs FD | Light / Arkworks (µs) | Speedup vs Light |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 8.122 | 9.900 | 1.22× | 16.882 | 2.08× |
| 2 | 8.912 | 13.918 | 1.56× | 25.801 | 2.89× |
| 3 | 9.438 | 17.999 | 1.91× | 35.786 | 3.79× |
| 4 | 15.301 | 23.699 | 1.55× | 51.633 | 3.37× |
| 5 | 16.537 | 28.592 | 1.73× | 68.840 | 4.16× |
| 6 | 17.842 | 35.117 | 1.97× | 93.045 | 5.22× |
| 7 | 18.435 | 41.146 | 2.23× | 120.275 | 6.52× |
| 8 | 24.198 | 46.728 | 1.93× | 148.114 | 6.12× |
| 9 | 24.730 | 51.475 | 2.08× | 175.605 | 7.10× |
| 10 | 27.294 | 61.228 | 2.24× | 232.550 | 8.52× |
| 11 | 26.197 | 64.819 | 2.47× | 255.776 | 9.76× |
| 12 | 32.218 | 75.197 | 2.33× | 321.115 | 9.97× |

### Native scalar (IFMA disabled) library comparison

Complete little-endian byte calls; times are microseconds. Speedup is the
comparison library’s latency divided by this crate’s latency. Firedancer uses
its native GCC/ADX build even in the generic-Rust comparison.

| Inputs | This crate (µs) | Firedancer (µs) | Speedup vs FD | Light / Arkworks (µs) | Speedup vs Light |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 7.816 | 9.871 | 1.26× | 17.138 | 2.19× |
| 2 | 10.402 | 13.909 | 1.34× | 25.201 | 2.42× |
| 3 | 12.758 | 18.007 | 1.41× | 36.114 | 2.83× |
| 4 | 17.839 | 23.680 | 1.33× | 51.663 | 2.90× |
| 5 | 21.118 | 28.673 | 1.36× | 68.429 | 3.24× |
| 6 | 26.435 | 35.106 | 1.33× | 92.408 | 3.50× |
| 7 | 28.362 | 41.042 | 1.45× | 119.135 | 4.20× |
| 8 | 34.578 | 46.732 | 1.35× | 146.987 | 4.25× |
| 9 | 36.591 | 51.472 | 1.41× | 174.203 | 4.76× |
| 10 | 44.758 | 61.171 | 1.37× | 231.736 | 5.18× |
| 11 | 44.134 | 64.907 | 1.47× | 253.682 | 5.75× |
| 12 | 55.152 | 75.150 | 1.36× | 317.530 | 5.76× |

### Generic x86 library comparison

Complete little-endian byte calls; times are microseconds. Speedup is the
comparison library’s latency divided by this crate’s latency. Firedancer uses
its native GCC/ADX build even in the generic-Rust comparison.

| Inputs | This crate (µs) | Firedancer (µs) | Speedup vs FD | Light / Arkworks (µs) | Speedup vs Light |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 7.684 | 9.893 | 1.29× | 17.519 | 2.28× |
| 2 | 10.398 | 13.908 | 1.34× | 26.062 | 2.51× |
| 3 | 13.058 | 17.949 | 1.37× | 36.586 | 2.80× |
| 4 | 19.151 | 23.687 | 1.24× | 52.148 | 2.72× |
| 5 | 22.680 | 28.567 | 1.26× | 70.146 | 3.09× |
| 6 | 27.671 | 35.057 | 1.27× | 94.822 | 3.43× |
| 7 | 30.424 | 41.150 | 1.35× | 122.528 | 4.03× |
| 8 | 37.731 | 46.799 | 1.24× | 151.198 | 4.01× |
| 9 | 40.215 | 51.543 | 1.28× | 178.161 | 4.43× |
| 10 | 48.650 | 61.349 | 1.26× | 237.235 | 4.88× |
| 11 | 46.863 | 64.797 | 1.38× | 260.468 | 5.56× |
| 12 | 60.633 | 75.175 | 1.24× | 327.282 | 5.40× |

Fetched results (including Criterion samples, estimates, source hashes and
compiler metadata):
`/Users/samkim/.local/state/benchctl/results/4b698daff36e4b7a9e9eeb1b7b9b5290/outputs/poseidon-experiment-results`.

The baseline/candidate ABBA results are `summary.json`; each configuration’s
fresh library comparison is `comparison.json`. Typed-input measurements are
also included there. Job logs/runtime/source specification are in
`/Users/samkim/.local/state/benchctl/results/4b698daff36e4b7a9e9eeb1b7b9b5290/metadata`. The missing default `target/criterion` artifact is
expected because this runner exports the custom result directory instead.

**All planned P01–P12 families are settled.** Retained: P01, P03, P04A, P05,
P06, P07C, P08, P09, P11B, and P12A2. Rejected alternatives and their exact
patches remain recorded above and in the fetched trial artifacts.
