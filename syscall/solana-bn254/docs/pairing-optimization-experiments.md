**Sequential pairing optimization experiments**

The user authorized independent implementation, remote measurement through
benchctl, and a keep/discard decision for each item in
[the review](pairing-optimization-review.md). Preserve unrelated working-tree
edits and untracked files. Each retained change becomes the next baseline.

Checkpoints in `.benchctl-inputs/pairing-experiments/` preserve exact pre-change
bytes for the affected files. The runner builds baseline and candidate within
one frozen benchctl job, verifies the candidate with library/integration tests
and all three implementations' contract fixtures, and measures baseline,
candidate, candidate, baseline on the same CPU. The compiler and native flags
remain unchanged. Initial measurements use 100 samples, one-second warmup,
a three-second measurement target, and 95% intervals; Criterion can extend the
sampling duration to collect the requested samples. Near-noise findings require a
confirmation run before being kept; candidates with no repeatable benefit can
be conservatively discarded. CPU affinity does not isolate unrelated activity.

Keep changes with repeatable improvements beyond measurement uncertainty and
no material regressions in the other applicable cases. Evaluate specialized
workload optimizations on their intended workload and check general cases for
regressions. Discard candidates that do not establish an improvement. Record
failed attempts, patches, exact job UUIDs, source fingerprints, commands, and
fetched results. Restore only the current experiment's edits when discarding.

| ID | Optimization | Status |
|---|---|---|
| A01 | Modular halving | **Kept**: 1.61% seeded geometric-mean improvement |
| A02 | Specialized Frobenius | **Discarded**: no repeatable overall gain |
| A03 | Final correction line only | **Kept**: 0.32% seeded geometric-mean improvement |
| A04 | Move factor of three to G1 | **Kept**: 0.47% seeded geometric-mean improvement |
| A05 | Firedancer fixed exponent chain | **Kept**: 0.91% seeded geometric-mean improvement |
| A06 | ADX/BMI2 field kernel | **Kept**: 9.20% seeded geometric-mean improvement |
| A07 | Inlining and register pressure | **Discarded**: 1.06% seeded slowdown |
| A08 | Streaming byte adapter | **Discarded**: no nonempty gain; special cases regressed |
| B01 | Newer fixed exponent chain | **Discarded**: 0.46% seeded slowdown |
| B02 | Sparse line fusion | **Kept**: small-input gains; repeated-16 improved 2.3% |
| B03 | Accumulator initialization | **Kept** after confirmation: small-input and cancellation gains |
| B04 | Hoist invariant coordinates | **Discarded**: larger inputs faster, small/special calls regressed |
| B05 | Fused sums and reductions | **Kept**: 4.41% seeded geometric-mean improvement |
| B06 | Fused Fq2 scalar assembly | **Discarded**: 7.99% seeded slowdown versus retained B05 |
| B07 | IFMA pairing arithmetic | **Kept**: 7.11% seeded geometric-mean improvement |
| B08 | Dedicated base-field square | **Kept**: 0.28% seeded gain; clearer small/special-case gains |
| B09 | Batch subgroup normalization | **Kept** after single-pair refinement: 0.92% seeded gain |
| B10 | Identity after easy exponent | **Discarded**: special cases faster, ordinary calls regressed |
| B11 | Combine repeated arguments | **Discarded**: repeated inputs much faster; ordinary calls 0.99% slower |
| B12 | Prepared G2 API | **Discarded**: reused inputs 25–52% faster; existing small/special calls regressed |
| B13 | Batch size and layout | **Discarded**: size/adaptive tradeoffs and no clear batched gain from aligned coordinates |

**A01: modular halving**

Replaces the four base-field multiplications used for halving in every Miller
doubling with conditional modulus addition and shifts. The new arithmetic is
checked against independent BigUint modular division on boundary and random
residues for both Fq and Fr; existing pairing tests cover exact Gt outputs.

Initial job: `2c21211ff3f7476d9bb3d103e146dc71`.
Source fingerprint: `9e59a193e06416367093097514a00e88ce5db4ebd0a8b2dd394beeff10521ca3`.
Command: `benchctl submit --json --label bn254-A01-halving --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id A01-halving`.

The first job stopped before timing because the new no_std unit test needed an
explicit std Vec import. Its failed logs were fetched to
`/Users/samkim/.local/state/benchctl/results/2c21211ff3f7476d9bb3d103e146dc71`.
The corrected candidate ran as `ee8559b546d448f4b88f1a4ab05f6d43`, source
fingerprint `f3a09fa80861d440b4396aed8bb8b88df0c95789e77a6e63871edbd20e8dc941`,
using the same command with label `bn254-A01-halving-v2`.

**Decision: keep.** Job `ee8559b546d448f4b88f1a4ab05f6d43` completed successfully
and was fetched to `/Users/samkim/.local/state/benchctl/results/ee8559b546d448f4b88f1a4ab05f6d43`.
The candidate passed 221 unit/integration tests and all 90 comparison smoke
cases; each timed process rechecked 39 contract fixtures in both byte orders
and 120 timing fixtures against all three implementations.

Measured on CPU 16 of the EPYC 9354P with Rust 1.98.0 and
`RUSTFLAGS="-C target-cpu=native"`, using the baseline/candidate/candidate/baseline
schedule. Seeded nonempty calls improved 0.92–1.92% (1.61% geometric mean).
Both candidate runs' upper confidence bounds were below both baseline runs'
lower bounds for all 28 nonempty cases, including repeated/cancelling/identity
cases. No nonempty case regressed. Empty-input differences were noisy and were
excluded from the decision. No additional confirmation run was needed.

| Example, little endian | Baseline µs | Candidate µs | Improvement |
|---|---:|---:|---:|
| One pair | 630.188 | 624.369 | 0.92% |
| Four pairs | 1375.946 | 1355.939 | 1.45% |
| Sixteen pairs | 4330.310 | 4250.686 | 1.84% |
| Thirty-two pairs | 8262.444 | 8104.594 | 1.91% |
| Repeated sixteen | 3971.647 | 3894.845 | 1.93% |

Per-round estimates and raw Criterion samples are in
`outputs/pairing-experiment-results/` under the fetched directory. The missing
default `target/criterion` artifact is expected because the runner gives each
round a distinct `CRITERION_HOME` inside that fetched directory.

**A02: specialized Frobenius maps**

Combines Fq12 tower coefficients, uses base-field scaling for even Frobenius
powers, directly conjugates the sixth power, and implements the G2 second
Frobenius with a real X coefficient and Y negation. Both subgroup checking and
the Miller correction use the direct G2 map. Existing field-power and exact-Gt
oracles cover the maps; the projective G2 oracle now also checks the direct map
on arbitrary twist points and nontrivial projective scalings.

Job: `b8bd6f21c1db44e3b66799f2319b1620`.
Source fingerprint: `08890fe1527740770f0a009342268eecb3cfcf557a47ef1e739a17c6ab2de34b`.
Command: `benchctl submit --json --label bn254-A02-frobenius --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id A02-frobenius`.
Baseline includes the retained A01 halving change.

**Decision: discard this implementation.** The job passed all 221 tests and
comparison smoke/contract checks. Results were fetched to
`/Users/samkim/.local/state/benchctl/results/b8bd6f21c1db44e3b66799f2319b1620`.
With the same CPU 16, Rust 1.98.0, native flags, and ABBA measurement protocol,
the seeded geometric-mean improvement was only 0.0019%. The candidate repeats
varied: one was approximately 0.26% slower and the other 0.27% faster than the
baselines. No seeded case had both candidate confidence intervals below both
baseline intervals. Repeated-16 regressed by 0.41–0.42% with separated intervals.
This does not establish a repeatable benefit, so the six affected files were
restored to their saved pre-A02 bytes. A01 remains retained. The candidate patch,
source hashes, and per-round results remain in the fetched artifact directory.
This rejects the measured implementation, not all possible Frobenius variants.

**A03: final correction line only**

Computes the last mixed-addition line without updating unused homogeneous point
coordinates. The existing affine-geometry oracle now checks this helper before
ordinary mixed additions and both correction steps, including scaled points.

Job: `b8ccefd497a041c9985de1556b6a1337`.
Source fingerprint: `8780e7a0d2163b9b8b94bf81379862e3f001f7093365b3a1e06aaf30f9e3f25e`.
Command: `benchctl submit --json --label bn254-A03-final-line --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id A03-final-line`.
Baseline includes A01; A02 was discarded.

**Decision: keep.** Job `b8ccefd497a041c9985de1556b6a1337` passed all 221 tests,
comparison smoke checks, and per-process contract checks. Results were fetched to
`/Users/samkim/.local/state/benchctl/results/b8ccefd497a041c9985de1556b6a1337`.
The seeded geometric-mean improvement was 0.316%. Both candidate intervals were
below both baseline intervals in 24 of 28 nonempty cases: all seeded cases with
at least three pairs and all special workloads. One- and two-pair improvements
were smaller (0.09–0.18%) with overlapping intervals. No nonempty case regressed.
The larger-case gain is repeatable within the ABBA job, so it is retained; the
smallest-case estimates are not claimed as established improvements. Empty input
remained noisy and was excluded. CPU 16, Rust 1.98.0, native flags, and timing
parameters were unchanged. Little-endian four-pair calls improved from
1355.606 to 1351.393 µs, and 32-pair calls from 8106.926 to 8073.338 µs.

**A04: move the tangent-line factor of three to G1**

The doubling line retains X²; evaluation multiplies it by 3*Px computed in Fq,
saving one pair of Fq additions per line. A distinct tangent-line type preserves
the ordinary line representation. Independent affine-geometry and dense-product
oracles cover both representations.

Job: `8592d9e14cd247b5bc1ea4b80856c0f1`.
Source fingerprint: `3dcbb825d5245d48a0df67d182e94636751621dbfd6d63677eeca2ee447d12d0`.
Command: `benchctl submit --json --label bn254-A04-g1-factor --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id A04-g1-factor`.
Baseline includes A01 and A03.

**Decision: keep.** The job passed all 221 tests and comparison checks, then was
fetched to `/Users/samkim/.local/state/benchctl/results/8592d9e14cd247b5bc1ea4b80856c0f1`.
The seeded geometric-mean improvement was 0.472%, ranging from 0.33% to 0.54%.
Both candidate confidence intervals were below both baseline intervals for all
28 nonempty cases. Special workloads improved 0.19–0.48%; no nonempty case
regressed. Empty-input estimates were noisy and excluded. CPU 16, Rust 1.98.0,
native flags, and the ABBA parameters were unchanged. Little-endian one-pair
calls improved from 623.899 to 621.464 µs; 32-pair calls improved from 8071.308
to 8029.149 µs. The locally retained source matches the measured candidate hashes.

**A05: Firedancer fixed-exponent chain with compressed runs**

Replaces the signed-window exponentiation by the 62-square/17-multiply chain
used in Firedancer, evaluated at the inverse to preserve exp_by_neg_x. Long
square runs retain this crate's Karabina compression. The exponent was checked
symbolically before submission; the existing independent generic-power and
Arkworks exact-normalization tests exercise the candidate.

Job: `4fb2461c251d47a893f6afcd4e184708`.
Source fingerprint: `8c2952cc09b9e5d107461a37bdff9fe2ef0a164e8ee0fb34162739a914186c4b`.
Command: `benchctl submit --json --label bn254-A05-fd-chain --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id A05-fd-chain`.
Baseline includes A01, A03, and A04. Starting with this job, the runner also
captures native symbols, section sizes, and crate assembly before timing, for
review of later kernel and inlining experiments.

**Decision: keep.** The job passed all 221 tests and comparison checks, and was
fetched to `/Users/samkim/.local/state/benchctl/results/4fb2461c251d47a893f6afcd4e184708`.
The seeded geometric-mean improvement was 0.907%. One-pair calls improved
2.39–2.42%; the final exponent has a smaller share at larger counts, where gains
were 0.31–0.76%. Both candidate intervals were below both baseline intervals for
all 28 nonempty cases. Special cases improved 0.50–0.81%, with no nonempty
regressions. CPU 16, Rust 1.98.0, native flags, and ABBA parameters were unchanged.
Little-endian one-pair latency decreased from 621.697 to 606.839 µs, and four-pair
latency from 1347.100 to 1330.713 µs. Retained source matches measured hashes.

**A06: native ADX/BMI2 Montgomery multiplication**

Adapts Firedancer's unrolled CIOS assembly to Rust inline assembly with register
outputs, preserving its attribution and Apache license notice. Dispatch is
restricted to Fq on Linux x86_64 builds with ADX and BMI2 enabled. Other fields
and targets retain portable arithmetic. The private lazy Fq2 sums also use this
kernel: a,b<2q and 4q<R prove the spare-limb and single-subtraction bounds. The
existing 4096-case BigUint oracle covers these unreduced private inputs; field
and pairing tests exercise canonical outputs and exact target-group results.

Job: `9fe250f5864643e68aafa514ae1f74e3`.
Source fingerprint: `0316be59a9412c1d28ca55ff6dc207468fa7f61aca5b8770d843c6eb45e8d5a8`.
Command: `benchctl submit --json --label bn254-A06-adx --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id A06-adx`.
Baseline includes A01, A03, A04, and A05. Compiler/native flags are unchanged.

**Decision: keep.** All 221 tests and comparison checks passed. Results were
fetched to `/Users/samkim/.local/state/benchctl/results/9fe250f5864643e68aafa514ae1f74e3`.
The seeded geometric-mean improvement was 9.202%, with every seeded nonempty
case improving 9.11–9.65%. Special workloads improved 9.78–11.00%. Both candidate
confidence intervals were below both baseline intervals for all 28 nonempty
cases, with no regression. CPU 16, Rust 1.98.0, native flags, and ABBA parameters
were unchanged. Little-endian one-pair latency fell from 606.947 to 548.381 µs;
16-pair latency from 4196.831 to 3814.580 µs; and 32-pair latency from 8015.221
to 7282.529 µs. Source hashes match the retained candidate.

The emitted Miller function grew from 0x3556 bytes in the preceding retained
build to 0x91eb bytes in this candidate. This supports testing explicit helper
boundaries next; assembly size alone is not evidence of an additional speedup.
A final generic-x86 correctness run will also exercise the preserved fallback.

**A07: explicit Fq2 and Fq6 multiplication boundaries**

Marks the two substantial field multiplication helpers inline(never), leaving
smaller helpers unchanged. Both variants use the same benchmark harness, which
now also supports a separate fixed-count profiling path. The primary decision
still uses the 30 complete-byte-call ABBA cases. After timing, the runner tries
perf counters on 5,000 seeded-16 little-endian calls per variant; unavailability
is recorded without modifying server permissions. Counters include fixture
setup and four checking calls; the separately printed elapsed time excludes
setup. Generic cache counters do not specifically identify instruction misses.

Job: `2f9bb54685774af8b640676a444ee52d`.
Source fingerprint: `bf715a9c036955a78415b03de59edc4c3899545a548fc74d2cddc68f56798bfa`.
Command: `benchctl submit --json --label bn254-A07-boundaries --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id A07-boundaries --profile`.
Baseline includes A01, A03, A04, A05, and A06. Rust/native flags are unchanged.

**Decision: discard these boundaries.** All 221 tests and comparison checks
passed, and results were fetched to
`/Users/samkim/.local/state/benchctl/results/2f9bb54685774af8b640676a444ee52d`.
Seeded calls slowed by 1.060% geometrically (0.84–1.20% per case), with separated
intervals in both repeats for every seeded nonempty case. Repeated-16 slowed
1.12–1.15%. The small mixed-identity changes were within repeat uncertainty.

Profiling succeeded without any permission changes. For 5,000 seeded-16 LE
calls, elapsed time increased from 19.046 to 19.195 seconds; user cycles rose
from 72.356 to 72.929 billion, despite slightly fewer instructions (184.579 to
184.089 billion) and fewer aggregate cache misses (1,056,850 to 969,516).
These counters include setup and are supporting evidence, not the primary
latency estimates. The Miller function shrank only from 0x91eb to 0x908a bytes;
the larger effect was consolidating local helper copies. Reduced code size did
not improve this workload. Restore only Fq2/Fq6 attributes; retain the shared
profiling harness and the previously accepted native kernel.

**A08: bounded streaming byte adapter**

Adds an allocation-free owned-pair API with a bounded decoded-point buffer and
one final exponentiation. The byte adapter decodes into that iterator and rejects
any decoding failure after consuming a prefix. Its iterator is fused, so an
iterator that resumes after None cannot add extra points beyond the first end.
Existing exact-Gt, batch-boundary, identity, cancellation, and invalid-input
oracles now also cover the owned API; an additional test covers resuming iterators.

Job: `ad4d0964a2614618b89c488c729b7609`.
Source fingerprint: `a13ea238bff49d99efeafa8655b5bac30f253421231a1bd6e11f6b82d2949b7c`.
Command: `benchctl submit --json --label bn254-A08-streaming --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id A08-streaming`.
Baseline includes A01, A03, A04, A05, and A06; A07 was discarded. The four-path
checkpoint includes the API, Miller constant visibility, adapter, and tests.

**Decision: discard.** All 222 tests and comparison checks passed. The job was
waited to successful completion and fetched to
`/Users/samkim/.local/state/benchctl/results/ad4d0964a2614618b89c488c729b7609`.
Seeded nonempty latency was essentially unchanged (0.027% geometric-mean
slowdown), with no case separating both candidate intervals from both baseline
intervals in the favorable direction. Cancelling pairs slowed 0.57–0.61%, and
mixed-identity calls slowed 0.65–0.67%, with separated intervals in both repeats.
Empty input improved from about 46 to 25 ns, but that does not establish a
pairing speedup. Restore all four experiment paths using the guarded restore;
the patch and raw measurements remain in the fetched artifact directory.
CPU 16, Rust 1.98.0, native flags, and ABBA parameters were unchanged.

**B01: newer fixed exponent chain**

Tests gnark's newer 60-square/17-multiply chain against the retained Firedancer
chain, preserving compressed square runs and the exact negative exponent. The
integer chain was checked symbolically; existing generic-power and exact-Gt
oracles cover the implementation.

Job: `574aa36db3c345d69c604736646ffcd6`.
Source fingerprint: `dc48cd99a5854aa18a97e56a5424fd79ced925150f9edeb67c80864e2a0c931d`.
Command: `benchctl submit --json --label bn254-B01-new-chain --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B01-new-chain`.
Baseline includes A01, A03, A04, A05, and A06.

**Decision: discard.** All 221 tests and comparison checks passed. The job was
waited to successful completion and fetched to
`/Users/samkim/.local/state/benchctl/results/574aa36db3c345d69c604736646ffcd6`.
Seeded nonempty latency slowed 0.458% geometrically, ranging from 0.28% to 0.72%.
Twenty-seven of 28 nonempty cases had both candidate confidence intervals above
both baseline intervals; the remaining 32-pair LE case also had a slower point
estimate. Cancellation slowed 0.93–0.96%, mixed identities 1.26–1.27%, and
repeated-16 0.39–0.41%. Fewer nominal squarings did not improve this compressed
implementation. Restore final_exp.rs to the retained A05 chain. CPU 16, Rust
1.98.0, native flags, and ABBA parameters were unchanged.

**B02: sparse line fusion**

Combines pairs of sparse Miller lines using six Fq2 multiplications and applies
the resulting five-coefficient value with 17, replacing two 13-product updates.
Nonzero loop digits combine each point's tangent and addition; zero digits pair
adjacent tangents; the two correction lines are combined. Point-update order
within each input is preserved. A new 128-case independent Arkworks dense-product
oracle covers both the sparse product and its application to an accumulator.

Job: `b79d798bcfb74ecba182a682dfaddc19`.
Source fingerprint: `7660f954216cbd56e1ed8ed1c29f2181601ed3aa81c011a19e6571b61bca3eef`.
Command: `benchctl submit --json --label bn254-B02-line-fusion --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B02-line-fusion`.
Baseline retains A01, A03, A04, A05, and A06; B01 was discarded.

**Decision: keep.** All 222 tests and comparison checks passed; the completed
job was fetched to
`/Users/samkim/.local/state/benchctl/results/b79d798bcfb74ecba182a682dfaddc19`.
Seeded geometric-mean latency improved 0.164%, but the benefit depends on the
workload. All seeded cases with one through eight pairs improved 0.16–0.50%,
with both candidate intervals below both baseline intervals. Repeated-16
improved 2.29–2.36%, cancellation 0.57–0.62%, and mixed identities 0.70–0.74%,
also with separated intervals in both repeats. Larger seeded cases were
essentially flat (−0.004% to +0.108%) and had overlapping intervals; no speedup
is established for those cases. No material nonempty regression was observed.
Retain for the repeatable small-input and special-workload improvements, rather
than interpreting the operation-count saving as a universal speedup. CPU 16,
Rust 1.98.0, native flags, and ABBA parameters were unchanged. Both retained
source files match the measured hashes.

**B03: direct accumulator initialization**

Assigns the first two-line product directly to the Miller accumulator, then
assigns the first completed batch directly to the total product. Empty and
all-identity iterators still return identity, and later invalid inputs remain
checked. The schedule asserts that its first processed digit is nonzero.
Existing exact-Gt, identity, cancellation, and boundary oracles cover the change.

Job: `cc16ecc7718848d9a73e14a4d92d1729`.
Source fingerprint: `d1513ba7d3b43f88814a516b7c134a8de22796241f5650681283c39fcb0c540c`.
Command: `benchctl submit --json --label bn254-B03-initialize --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B03-initialize`.
Baseline includes the retained B02 sparse-line fusion. The runner now writes
file hashes before compilation so a failed build/test would still support
guarded restoration; timing parameters and benchmark work are unchanged.

The initial job passed 222 tests and comparison checks, completed successfully,
and was fetched to
`/Users/samkim/.local/state/benchctl/results/cc16ecc7718848d9a73e14a4d92d1729`.
Its seeded geometric-mean improvement was 0.184%, but no seeded case separated
both candidate confidence intervals from both baseline intervals. The first
baseline was slower than the last; for example, 16-pair LE changed from
3812.748 to 3794.711 µs, while candidates were 3794.665 and 3796.400 µs.
Cancellation improved 0.57% and mixed identities 0.44%, with separated intervals
in both repeats. No decision yet: confirm these small findings in another full
ABBA job, with identical source code and timing parameters.

Confirmation job: `c0ef305c039046cfa2190ff2c8113c50`.
Source fingerprint: `2f14a99c47ce2813d97cf27435d530c92daf675a1d54769dc234e4c9bc77e822`.
Command: `benchctl submit --json --label bn254-B03-confirm --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B03-initialize`.

**Decision: keep after confirmation.** The confirmation again passed 222 tests
and comparison checks, completed successfully, and was fetched to
`/Users/samkim/.local/state/benchctl/results/c0ef305c039046cfa2190ff2c8113c50`.
Both jobs measured identical baseline/candidate Miller source bytes. The second
job's seeded geometric-mean improvement was 0.451%; one-to-eight-pair cases
improved 0.33–1.51% with both candidate intervals below both baseline intervals.
Cancellation improved 1.68–1.71%, and mixed identities 1.58–1.60%, also with
separated intervals. Larger seeded cases and repeated-16 had small positive
estimates with overlapping intervals. No nonempty case had a slower point
estimate in either job. Retain for the confirmed small-input/special-workload
benefit, while reporting that magnitudes varied between jobs: the earlier
seeded aggregate was 0.184%, and its special-case gains were 0.44–0.57%.
Do not claim an established large-input speedup. CPU 16, Rust 1.98.0, native
flags, and sampling parameters were unchanged.

**B04: cached coordinate factors and signs**

Caches 3*Px, -Px, -Py, and -Qy once per active entry. Raw tangent/addition line
signs move to the corresponding cached G1 factors; independent affine-geometry
and dense-product oracles still compare canonical mathematical lines. Entry
storage grows from 208 to 392 bytes on x86_64, or from 6.5 to 12.25 KiB for
32 entries. Stack-bound checks account for alignment, and API documentation
records this tradeoff. Arithmetic temporaries use additional stack space.

Job: `ada4cfc31d2d4a05943e4bbce05f844f`.
Source fingerprint: `e973733f303631ed33a75670d485e38a49a4411ffd9dace2e5361ce9158f6b86`.
Command: `benchctl submit --json --label bn254-B04-coordinate-cache --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B04-coordinate-cache`.
Baseline includes retained B02 and B03. The checkpoint covers Miller code and
both public descriptions of its stack storage.

**Decision: discard this implementation.** All 222 tests and comparison checks
passed. The completed job was fetched to
`/Users/samkim/.local/state/benchctl/results/ada4cfc31d2d4a05943e4bbce05f844f`.
Seeded geometric-mean latency improved 0.153%. Four-to-33-pair seeded calls
improved 0.19–0.40% with separated intervals in both repeats, but one-pair calls
regressed 0.76–0.78%, cancellation 0.59–0.67%, and mixed identities 0.52–0.59%,
also with separated intervals. Repeated-16 was flat. The larger workspace and
established regressions make this unsuitable as the general default. All three
checkpointed files were restored exactly, retaining B03. This does not rule out
size-dependent caching. CPU 16, Rust 1.98.0, native flags, and ABBA parameters
were unchanged; source hashes were checked before restoration.

**B05: wide Fq2 products with two Montgomery reductions**

Computes three unreduced 512-bit Karatsuba products and reduces the real and
imaginary results once each. Negative real differences are adjusted by qR;
explicit bounds keep both reduction inputs below qR. New independent BigUint
oracles cover 4096 wide products, reduction boundaries, and random reductions;
existing Fq2/extension/pairing tests check the composed arithmetic. Public field
values remain canonical. This candidate replaces native scalar Fq2 products;
it does not assume fewer reductions imply lower latency.

Job: `8c53979798fd4bddb1b1191fb0b63a8f`.
Source fingerprint: `58422f19952c288fdbf611dcbba644ea630bb5a9e83c0a934676448a9446fdbf`.
Command: `benchctl submit --json --label bn254-B05-wide-reductions --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B05-wide-reductions`.
Baseline retains B03; B04 was discarded. Three source paths are checkpointed.

**Decision: keep.** All 223 tests and comparison checks passed. The completed
job was fetched to
`/Users/samkim/.local/state/benchctl/results/8c53979798fd4bddb1b1191fb0b63a8f`.
Seeded geometric-mean latency improved 4.408%; every nonempty case had both
candidate confidence intervals below both baseline intervals. Seeded gains
ranged from 3.92% to 6.07%; repeated-16 improved 3.13–3.14%, cancellation
9.87–9.89%, and mixed identities 9.68–9.69%. Little-endian one-pair calls changed
from 549.055 to 515.752 µs, and 32-pair calls from 7283.747 to 6996.322 µs.
No nonempty regression was observed. All retained file hashes match the measured
candidate. CPU 16, Rust 1.98.0, native flags, and ABBA parameters were unchanged.

**B06: fused scalar Fq2 assembly**

On Linux x86_64 with ADX/BMI2, computes three Karatsuba CIOS products under one
assembly register-save/restore boundary, then reconstructs canonical Fq2
coefficients. Input/output buffers have fixed 96-byte sizes; assembly declares
its memory effects and preserves its private stack and all undeclared registers.
The retained B05 wide-product implementation remains the generic fallback.
Independent boundary and 4096 random integer-oracle cases directly exercise all
three native products with operands below 2q. This prototype fuses multiplication,
not Fq2 squaring; fewer assembly boundaries need not beat B05's two reductions.

Job: `5981be04457c42d89a4ece08c5028ff2`.
Source fingerprint: `0769e69ca2b6f50ac15ff13cd7177d3d3f6b4d0016b30974bdc817c285fab1e0`.
Command: `benchctl submit --json --label bn254-B06-fused-adx --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B06-fused-adx`.
Baseline includes retained B05. Four source paths are checkpointed.

**Decision: discard this three-CIOS assembly prototype.** All 223 tests and
comparison checks passed. The completed job was fetched to
`/Users/samkim/.local/state/benchctl/results/5981be04457c42d89a4ece08c5028ff2`.
Seeded geometric-mean latency regressed 7.989%; every nonempty case had both
candidate confidence intervals above both baseline intervals. Seeded regressions
were 7.54–9.60%, repeated-16 about 8%, cancellation 15.86–15.93%, and mixed
identities 15.47–15.50%. The shared assembly boundary did not compensate for
this prototype's product/reduction and buffer costs compared with B05. Timings
do not isolate those individual causes. All four checkpointed paths were
restored exactly; B05 remains retained. This does not reject other fused assembly
layouts or a native implementation of B05's two-reduction algorithm. CPU 16,
Rust 1.98.0, native flags, and ABBA parameters were unchanged.

**B07: Fq IFMA products inside Fq6 multiplication**

Packs the six independent Fq2 products in Fq6 multiplication into AVX-512 lanes,
keeping packed coefficients across the three Karatsuba products and their
reconstruction. Two lanes contain zero. The Fq-specific 52-bit constants are
independently derived; input scaling reconciles the private 260-bit Montgomery
radix with the crate's 256-bit representation. Private operands remain below
2q, and every returned coefficient is canonical. The native path requires
AVX-512 F/DQ/IFMA; the scalar fallback is preserved. Three independent tests
cover canonical boundaries/random inputs, six Fq2 products, and 4096 lazy-range
lane products. This tests SIMD within Fq6 multiplication, not a fully vectorized
tower or a Miller loop that keeps all point state in vectors.

Job: `38aa9999fe06442380bcda5c87df11ae`.
Source fingerprint: `eec4c92469fb768eeb7f1f55973d2424cc6f33496f5b620f51845cc83674e18f`.
Command: `benchctl submit --json --label bn254-B07-fq-ifma --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B07-fq-ifma`.
Baseline retains B05; B06 was discarded. Three source paths are checkpointed.

**Decision: keep.** All 226 tests and comparison checks passed. The completed
job was fetched to
`/Users/samkim/.local/state/benchctl/results/38aa9999fe06442380bcda5c87df11ae`.
Seeded geometric-mean latency improved 7.111%; both candidate confidence intervals
were below both baseline intervals for every nonempty case. Seeded gains ranged
from 5.99% to 9.34%; repeated-16 improved 6.97–6.98%, cancellation 9.61–9.73%,
and mixed identities 9.62–9.68%. Little-endian one-pair calls changed from
516.524 to 468.330 µs, and 32-pair calls from 7005.784 to 6578.251 µs.
No nonempty regression was observed. Retained source hashes match the measured
candidate. CPU 16, Rust 1.98.0, native flags, and ABBA parameters were unchanged.
These gains describe the EPYC 9354P and this vectorization scope; generic-x86
correctness is checked separately at the end of the experiment series. The
captured native assembly contains vpmadd52huq/vpmadd52luq in Fq6 multiplication,
confirming the measured vector path is present in the executable.

**B08: dedicated base-field Montgomery square**

Uses ten distinct 64×64 products in an explicitly unrolled integer square,
followed by Montgomery reduction. Doubled cross terms enter a 192-bit column
accumulator through carries, avoiding 129-bit overflow in a u128 temporary.
Only Fq squaring changes; Fr and other backend fields retain their existing
path. Independent integer and field oracles cover boundaries, all single-bit
inputs, and 4096 random full-width values. Fq2's two-multiplication square is
unchanged, so fewer integer products may have limited complete-call impact.

Job: `abb237852ebd4e9e9fae72b3f9156322`.
Source fingerprint: `711da9a33e6e37aa1dc50b0496974f4bfc60bbf5273b5c172a2de38ca3f1614a`.
Command: `benchctl submit --json --label bn254-B08-dedicated-square --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B08-dedicated-square`.
Baseline includes retained B07. Two source paths are checkpointed.

**Decision: keep.** All 227 tests and comparison checks passed. The completed
job was fetched to
`/Users/samkim/.local/state/benchctl/results/abb237852ebd4e9e9fae72b3f9156322`.
Seeded geometric-mean latency improved 0.276%. Both candidate confidence
intervals were below both baseline intervals in 26 of 28 nonempty cases.
One-pair calls improved 0.72–0.80%, cancellation 1.31–1.33%, and mixed identities
1.18–1.24%, all with separated intervals. Other seeded estimates improved
0.11–0.43%; 33-pair LE and repeated-16 LE had overlapping intervals, so those
individual improvements are not established. No nonempty point estimate
regressed. Retain for the repeatable small/special-input gains and supported
broader gains, without attributing every timing difference solely to the
integer multiplication count. Retained source hashes match the measurements.
CPU 16, Rust 1.98.0, native flags, and ABBA parameters were unchanged.

**B09: batch the subgroup-check normalization**

Shares normalization of each fixed-chain 3Q precomputation through one zero-aware
Fq2 inverse per bounded chunk. Every Q still passes the original full-twist
subgroup relation, including Q paired with G1 identity. Single-point chunks
check directly. Raw-reference buffering preserves the original grouping of
32 active Miller pairs; validation can consume a chunk before reporting a
nonmember. The declared buffers add 8.75 KiB at this batch size, plus arithmetic
temporaries, and the API/implementation documentation records the workspace.
An independent full-[r] oracle checks valid, identity, arbitrary-twist, and
torsion inputs, with invalid points at several chunk positions.

Job: `074bfbba18a3479590686692d088025d`.
Source fingerprint: `e0d5b4d10e88fa3a9a5faa4a4545184f5074cb3c17f0a1771854aaba61a1b289`.
Command: `benchctl submit --json --label bn254-B09-batch-subgroup --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B09-batch-subgroup`.
Baseline includes retained B08. Four source/documentation paths are checkpointed.

The initial B09 job passed 228 tests and comparison checks, completed successfully,
and was fetched to
`/Users/samkim/.local/state/benchctl/results/074bfbba18a3479590686692d088025d`.
Seeded geometric-mean improvement was 0.577%. Two-to-33-pair calls improved
0.31–0.85%, repeated-16 about 0.48%, and cancellation 0.21–0.24%, with both
candidate intervals below both baseline intervals. Mixed identities were flat
with overlapping intervals. One-pair calls regressed 0.21–0.24% with separated
intervals. Before deciding, revise the candidate to dispatch a single pair
through a one-entry Miller workspace outside the larger batched helper; the
same subgroup/identity checks are retained. Remeasure against the original
pre-B09 checkpoint with the same protocol. The first candidate's patch and
hashes remain in its fetched results.

Revised B09 job: `c59d2d365e3045f39775b520978a60c7`.
Source fingerprint: `ec0d59efa2a1b7ecd28b4e4b08382facb7f409e1e07a58be75456fc1fc7a0d61`.
Command: `benchctl submit --json --label bn254-B09-single-path --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B09-batch-subgroup`.
The baseline checkpoint is unchanged. Only the candidate's Miller dispatch
changes relative to the first attempt; correctness and timing parameters remain
identical.

**Decision: keep the revised candidate.** The second job passed all 228 tests
and comparison checks, completed successfully, and was fetched to
`/Users/samkim/.local/state/benchctl/results/c59d2d365e3045f39775b520978a60c7`.
Both jobs used identical baseline source hashes. The revised candidate improved
seeded geometric-mean latency 0.922%, with both candidate confidence intervals
below both baseline intervals for every nonempty case. One-pair calls improved
0.68–0.69%, removing the original candidate's regression; other seeded cases
improved 0.77–1.08%. Repeated-16 improved 0.60–0.62%, cancellation 1.01–1.10%,
and mixed identities 0.82–0.87%. Empty calls regressed roughly 7 ns and remain
excluded from the nonempty pairing decision. Retained source hashes match the
revised measurements. The larger documented batch workspace is retained, with
a one-entry path for single-pair calls. CPU 16, Rust 1.98.0, native flags, and
ABBA parameters were unchanged.

**B10: identity after the easy final exponent**

Returns identity when the easy exponent maps a nonzero Miller value to one,
avoiding the hard fixed-exponent chain. The existing raw-ONE shortcut remains.
This applies to a subset of true pairing products; a true result does not in
general imply the easy part is already one. All point/subgroup validation still
precedes final exponentiation. An independent integer-power oracle exercises
nontrivial nonzero Fq6 inputs that become one after the easy exponent, while
existing arbitrary-field and exact-Gt tests continue to cover the full chain.

Job: `c0fc757696fb490894a9c8bb901ce2ee`.
Source fingerprint: `fccb87d48bf028084713bea03bba6cb84b3acd6dff6c6a46db77495a33f6e5b3`.
Command: `benchctl submit --json --label bn254-B10-easy-identity --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B10-easy-identity`.
Baseline includes the retained revised B09 candidate. One source path is
checkpointed.

**Decision: discard this implementation.** All 229 tests and comparison checks
passed. The completed job was fetched to
`/Users/samkim/.local/state/benchctl/results/c0fc757696fb490894a9c8bb901ce2ee`.
Cancellation improved 29.12–29.16% and mixed identities 26.83–26.89%, with
separated confidence intervals. However, seeded geometric-mean latency
regressed 0.256%; 4–33-pair cases regressed 0.22–0.34% and repeated-16 regressed
0.30–0.31%, with both candidate intervals above both baseline intervals.
Small seeded cases overlapped. Native symbol inspection shows final exponentiation
grew from 11843 to 12207 bytes; Miller and Fq6 multiplication sizes were unchanged,
although their addresses moved. This does not establish the cause of the
regressions or justify ignoring them. Under the stated no-material-regression
rule, restore the one checkpointed source file, including the candidate-only
test. The candidate patch and results remain available for a future specialized
API or a different implementation. Guarded restoration verified its measured
source hash. CPU 16, Rust 1.98.0, native flags, and ABBA parameters were unchanged.

**B11: combine repeated G2 arguments**

Within a bounded group table, equal canonical G2 points share subgroup validation
and a projective G1 sum. A zero G1 sum never skips validation. Pending groups
are checked before accepting duplicates or processing a batch, so an infinite
stream of repeated valid points cannot defer an earlier invalid point forever.
The B09 one-pair path remains. At 32 groups, declared arrays total 20.25 KiB
on 64-bit targets, plus arithmetic temporaries. Tests exercise cancellation of
invalid repeated Q inputs around batch boundaries and bounded rejection with
an infinite repeated-input iterator.

Job: `6c68df64671e40398fae99be671c0817`.
Source fingerprint: `a934c681c6f1feb230d6b7bb0d49e93d0f2f7d0472d956ba4485f6414b03feb9`.
Command: `benchctl submit --json --label bn254-B11-repeat-groups --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B11-repeat-groups`.
Baseline includes retained B09; B10 was discarded. Five source/test/documentation
paths are checkpointed.

**Paused at the user's request after cycle 18.** Cycle 19 (B11) had already
started when the pause arrived. Cancelled only job
`6c68df64671e40398fae99be671c0817` and waited for its terminal cancelled state
(exit 130, 2026-09-21 07:05 UTC). Its logs, candidate patch, source hashes, and
partial timing data were fetched to
`/Users/samkim/.local/state/benchctl/results/6c68df64671e40398fae99be671c0817`.
The candidate passed 230 tests and comparison checks, but the four timing rounds
were not completed. No performance decision is made from these partial results.
Guarded restoration verified all five measured candidate hashes and restored
exact pre-B11 bytes. The working source therefore contains only the 11 retained
optimizations among the first 18 completed ideas; seven were discarded.

To resume, reapply this fetched candidate patch to the restored baseline and
submit a **new** B11 job using the existing `B11-repeat-groups` checkpoint.
Do not reuse partial timing rounds as a completed comparison. B12 (prepared G2)
and B13 (batch size/layout) remain untested; drafts are under the ignored
`target/pairing-experiment-plans/` directory. Final documentation cleanup,
generic-x86 tests, and a fresh full three-way comparison remain pending.
There are no running jobs belonging to this task.

**Cycle 19 resumed at the user's request.** Reapplied the saved candidate patch
only after verifying all five checkpoint baseline hashes. All restored candidate
hashes match the cancelled job. A new complete ABBA run will decide this cycle;
partial timings from the cancelled job are excluded. The user requested another
pause after this cycle, before any B12 work or later jobs.

Resumed job: `23307b9e1e8442feb5b4bd39bbfa99ac`.
Source fingerprint: `23241d2c67f2ea244e6d653dff754b979736329433d906f07be0cebc67e82e1a`.
Command: `benchctl submit --json --label bn254-B11-repeat-groups-resume --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B11-repeat-groups`.
The checkpoint and candidate source bytes are unchanged from the cancelled
attempt. Rust 1.98.0, native flags, CPU 16, and the full ABBA protocol remain.

**Decision: discard this implementation.** Resumed job
`23307b9e1e8442feb5b4bd39bbfa99ac` passed all 230 candidate tests and the
three-implementation comparison checks, completed the full four-round schedule,
and returned exit 0. Results were fetched to
`/Users/samkim/.local/state/benchctl/results/23307b9e1e8442feb5b4bd39bbfa99ac`.
All five local candidate source hashes matched the measured snapshot.

Repeated-16 latency improved 84.18%, cancellation 92.42%, and mixed identities
92.78%, with both candidate confidence intervals below both baseline intervals.
However, every nonempty seeded case regressed with separated intervals: latency
increased 0.77–1.30%, or 0.991% by geometric mean. The two baseline geometric
means were 2188.882 and 2188.558 microseconds; the candidate rounds were 2220.442
and 2200.443 microseconds. The candidate rounds varied in magnitude, but both
were slower than both baselines on every nonempty seeded case. The single-pair
case also regressed despite retaining its direct path, so these timings alone
do not attribute the cost solely to duplicate lookup. Empty timings overlapped
and were excluded from the decision.

| Example, little endian | Baseline µs | Candidate µs | Latency reduction |
|---|---:|---:|---:|
| One pair | 463.734 | 469.170 | -1.17% |
| Four pairs | 1053.186 | 1066.745 | -1.29% |
| Sixteen pairs | 3390.318 | 3420.464 | -0.89% |
| Thirty-two pairs | 6498.030 | 6550.939 | -0.81% |
| Repeated sixteen | 3039.398 | 480.737 | 84.18% |
| Cancelling two | 515.586 | 39.087 | 92.42% |
| Mixed identities | 550.631 | 39.757 | 92.78% |

Under the established no-material-regression rule for the ordinary API,
restore all five checkpointed source/test/documentation paths. The large
specialized gains justify retaining the patch and results for possible future
explicit grouping support; they do not establish a universal improvement for
this automatic implementation. Guarded restoration verified the measured
candidate hashes before writing and the saved baseline hashes afterward.
Rust 1.98.0, `RUSTFLAGS="-C target-cpu=native"`, CPU 16 on the EPYC 9354P,
and the ABBA timing parameters were unchanged. No confirmation job was needed
to keep a near-noise gain because this candidate is being discarded.

**Paused after cycle 19, as requested.** Nineteen of 21 ideas have completed
implementation, measurement, and decision: 11 retained, eight discarded.
The source is back at the retained post-cycle-18 baseline. No task job remains
running. B12 (prepared G2, cycle 20) and B13 (batch size/layout, cycle 21)
remain untested and were not started during this resumed cycle. Final generic-x86
correctness checks, documentation cleanup, and a fresh comparison are also
pending until the work resumes.

**B12 / cycle 20: reusable checked G2 preparation**

Adds a private 87-line table behind `pairing::PreparedG2`, constructed only after
G2 subgroup validation, and public single/product APIs for reuse. The ordinary
pairing API and its validation remain unchanged. B11 grouping was discarded and
is not included here. Table coefficients occupy 16,704 bytes plus the identity
flag/alignment; the benchmark prints the actual object size. Prepared products
share a single Miller schedule over the caller's slice and one final exponent,
with no library heap allocation. Exact Arkworks comparisons exercise identities,
cancellation, sizes through 65, shared versus separately prepared equal-Q tables,
and rejection of nonmembers at construction.

The runner now supports a separate reused-input workload and configurable case
counts. Both variants use a shared benchmark hook: the baseline calls ordinary
pairing on decoded inputs; the candidate calls prepared pairing, with table
construction outside the warm timing. Both rotate the same four fixtures. Seven
warm cases join the 30 unchanged fresh-byte cases in each ABBA round. Cold table
construction is measured separately after ABBA and never included in warm ratios.
Warm savings are not presented as fresh-byte comparisons against Firedancer.
Five candidate source/test/documentation/benchmark paths are checkpointed under
`B12-prepared-g2`. The user requested a pause after the cycle-20 decision.

Job: `41ffcb72d85145469abdb15cb62b097d`.
Source fingerprint: `7d46fe39da05ab1134a45c7a33e0fb66515921576fc8fd2d7c7c410d37997a1f`.
Command: `benchctl submit --json --label bn254-B12-prepared-g2 --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B12-prepared-g2 --prepared --expected-cases 37`.
Baseline includes the 11 retained optimizations through B09. B10 and B11 are
absent. Rust 1.98.0, native flags, CPU 16, and ABBA parameters are unchanged.

The first B12 job completed successfully, passed 229 tests and comparison
checks, and was fetched to
`/Users/samkim/.local/state/benchctl/results/41ffcb72d85145469abdb15cb62b097d`.
All five candidate hashes match its metadata. Every warm case improved with
separated intervals: 25.28–51.93% for seeded sizes 1–32, 47.30% for repeated-16,
and 35.05% for cancellation. The measured seeded-Q construction cost was
88.589 microseconds (95% interval 88.566–88.611); identity construction was
0.888 microseconds. The table object occupies 16,712 bytes on x86-64.

The ordinary byte-call seeded geometric mean regressed 0.227%. Most larger
cases had overlapping intervals, but one-pair calls regressed 0.619%, two-pair
BE 0.412%, cancellation 1.17–1.34%, and mixed identities 1.21–1.23%, with both
candidate intervals above both baseline intervals. This is not accepted as-is.
Native symbols show `Homogeneous::line_to` became an outlined function when the
prepared constructor added its second caller; the Miller batch shrank from
30,519 to 28,012 bytes. Double/add and final-exponentiation sizes were unchanged.
Before deciding, mark only the correction-line helper `inline(always)` to retain
its original integration into the Miller hot path, then rerun against the same
pre-B12 checkpoint. This is a targeted inlining refinement; it does not change
field formulas or the prepared API contract. The original patch and complete
measurements remain saved. No cycle-21 work has started.

Revised B12 job: `7ca41c5d03cb4e21850efeeb6f51cf3e`.
Source fingerprint: `a1f1fd38e2338a94a16f649a4375fe2670ed5bed526c1ca9d2983b5da38d7b8b`.
Command: `benchctl submit --json --label bn254-B12-inline-correction --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B12-prepared-g2 --prepared --expected-cases 37`.
The pre-B12 checkpoint is unchanged. Hash comparison confirms the candidate
differs from the first attempt only by `#[inline(always)]` on `line_to`.
This job entered the shared benchctl queue; no work bypasses its execution slot.

**Decision: discard this implementation after the inlining refinement.** Revised
job `7ca41c5d03cb4e21850efeeb6f51cf3e` completed all four timing rounds and cold
preparation measurements, returned exit 0, and was fetched to
`/Users/samkim/.local/state/benchctl/results/7ca41c5d03cb4e21850efeeb6f51cf3e`.
All 229 candidate tests passed, including exact prepared-Gt comparisons against
Arkworks. Each comparison process validated 39 contract fixtures in both byte
orders and 120 timing fixtures against all three implementations. All five
local candidate hashes matched the revised snapshot; both B12 jobs used the
same checkpoint baseline hashes.

The revised warm results again have both candidate confidence intervals below
both baseline intervals. These comparisons use already decoded inputs and
exclude table construction; they are not fresh-input speedups over Firedancer.

| Reused-input workload | Baseline µs | Prepared µs | Latency reduction |
|---|---:|---:|---:|
| One pair | 463.910 | 346.327 | 25.35% |
| Two pairs | 656.815 | 438.865 | 33.18% |
| Four pairs | 1052.169 | 622.581 | 40.83% |
| Sixteen pairs | 3385.109 | 1692.783 | 49.99% |
| Thirty-two pairs | 6493.665 | 3118.087 | 51.98% |
| Repeated sixteen | 3035.183 | 1597.315 | 47.37% |
| Cancelling two | 513.333 | 333.901 | 34.95% |

Constructing one representative seeded-Q table cost 88.745 microseconds
(95% interval 88.682–88.809); identity construction cost 0.878 microseconds.
The prepared object occupies 16,712 bytes on x86-64. These separate cold and
warm measurements do not establish an end-to-end first-use improvement.

Ordinary byte-call seeded geometric-mean latency regressed 0.183%. Both
candidate intervals exceeded both baseline intervals for seeded sizes 1–4:
one-pair calls regressed 0.42–0.49%, two-pair calls 0.29–0.31%, three-pair
calls 0.24–0.26%, and four-pair calls 0.23%. Larger seeded and repeated-16
cases had overlapping intervals. Cancellation regressed 0.91–0.99%, and
mixed identities 1.03%, also with separated intervals. Empty timings overlapped
and are excluded from the nonempty decision.

The refinement removed the standalone `Homogeneous::line_to` symbol. The
ordinary Miller batch is now 30,181 bytes versus 30,519 in the baseline;
double/add and final-exponentiation sizes remain unchanged. Restoring inlining
therefore did not restore identical ordinary-path code generation or eliminate
the measured regressions. The measurements do not identify every cause of the
remaining slowdown. Under the established no-material-regression rule, the
large reused-input gains do not justify retaining this implementation. Both
candidate patches, complete results, and native assembly remain saved for a
future implementation that avoids the ordinary-path regressions.

Guarded restoration checked all five measured candidate hashes before writing
and verified all five saved baseline hashes afterward. Then removed this cycle's
new benchmark helper and shared benchmark hook; the harness hash exactly matches
the pre-cycle-20 manifest. The library, tests, and API documentation are back at
their pre-B12 bytes. General experiment-runner support and the frozen checkpoint
remain; replaying B12 requires restoring its baseline benchmark helper and hook
before applying the saved candidate patch. No unrelated edits were restored.

Both B12 runs used Rust 1.98.0, `RUSTFLAGS="-C target-cpu=native"`, CPU 16 on
the EPYC 9354P, and the same ABBA parameters: 100 samples, one-second warmup,
three-second measurement target, and 95% intervals. All builds, tests, and
timings ran through the shared benchctl queue. The fetched custom artifact
contains the Criterion results under `outputs/pairing-experiment-results`;
the absent default `target/criterion` artifact is expected for this runner.

**Paused after cycle 20, as requested.** Twenty of 21 ideas have completed
implementation, measurement, and decision: 11 retained, nine discarded.
The source retains the same optimizations as before this cycle. No task job
remains running. B13 (batch size/layout, cycle 21) is the one remaining cycle
and was not started. Final generic-x86 checks, documentation cleanup, and the
fresh three-way comparison remain pending until the work resumes.


**B13 / cycle 21: batch size and point-state layout**

Resumed at the user's request. Test fixed sizes 16 and 64 against the retained
32-entry implementation, deciding each variant before proceeding, then test a
separate-coordinate layout at the retained size. Each candidate must improve
applicable workloads without material regressions in ordinary small/special
calls. Near-noise gains require confirmation before retention. These are
variants of the final optimization cycle, not additional numbered cycles.

The common benchmark fixture generator now adds sizes 63, 64, and 65 after
constructing all original 33-point pools, preserving the previous input bytes.
Each ABBA round measures 36 cases total, covering both byte orders and rotating
four fixtures per case. The runner default is updated to expect this expanded
matrix; every B13 command also selects the count explicitly. Existing exact-Arkworks, product-of-singles, cancellation, identity,
and invalid-input tests already exercise boundaries through 65 and larger
cancelling products. No correctness requirement or subgroup check is relaxed.

First candidate: size 16, checkpoint `B13-batch16`. This changes both active
Miller and bounded raw subgroup-validation chunks, while preserving the direct
single-pair path and all arithmetic formulas. The deliberate point-state bound
is 3.25 KiB, plus 4.375 KiB of declared validation buffers (7.625 KiB total on
64-bit targets, excluding arithmetic temporaries), versus 6.5 + 8.75 = 15.25 KiB
for the retained size 32. The workspace-bound assertion and API documentation
are updated with the candidate rather than silently weakening the assertion.
The benchmark expansion is shared by both variants and remains independent of
the three checkpointed source/documentation files.

Size-16 job: `c853f2543b294058b021e57d567f0b4e`.
Source fingerprint: `b40df7445fa41aed4d5a2bb812c6957c69de0bc6878186f012f68f1e60861b50`.
Command: `benchctl submit --json --label bn254-B13-batch16 --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B13-batch16 --expected-cases 36 --cpu 16`.
Rust 1.98.0, `RUSTFLAGS="-C target-cpu=native"`, CPU 16 on the EPYC 9354P,
and the full ABBA schedule are unchanged. The job was accepted by the shared
queue; the local checkpoint makes an exact guarded rollback available.

**Size-16 decision: discard.** Job `c853f2543b294058b021e57d567f0b4e`
completed successfully, passed all 228 candidate tests and comparison checks,
and was fetched to
`/Users/samkim/.local/state/benchctl/results/c853f2543b294058b021e57d567f0b4e`.
Each comparison process validated 39 contract fixtures in both byte orders and
144 timing fixtures against all three implementations. All three current
candidate hashes matched the measured snapshot before guarded restoration;
all three baseline hashes were verified afterward.

Seeded geometric-mean latency regressed 0.720% over the expanded matrix and
0.600% over the original sizes through 33. At 17 pairs the regression was
1.95%; sizes 31–65 regressed 1.13–1.18%, with both candidate confidence
intervals above both baseline intervals. Most smaller seeded sizes also
regressed with separated intervals (0.15–0.25%); size two and the special
workloads overlapped. The smaller workspace did not establish a speed benefit.
The baseline remains size 32. The patch and complete measurements are saved.

Second candidate: size 64, checkpoint `B13-batch64`, from the restored size-32
baseline. Both Miller and validation chunks grow together. Declared point state
is 13 KiB plus 17.5 KiB of validation buffers: 30.5 KiB total on 64-bit targets,
excluding arithmetic temporaries. The workspace assertion and documentation
explicitly record this increase. Single-pair handling and formulas are unchanged.

Size-64 job: `ac843f3fb13d4601b5b6432e763ffb00`.
Source fingerprint: `d2f9fe0143cf12044055210629b595dc111444cc38787bb820c9160e06dbef2e`.
Command: `benchctl submit --json --label bn254-B13-batch64 --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B13-batch64 --expected-cases 36 --cpu 16`.
The same Rust 1.98.0/native compiler settings, CPU 16, expanded fixtures, and
ABBA parameters apply. No compilation or performance work runs locally.

**Fixed-size-64 decision: do not retain as-is; test adaptive workspace selection.**
Job `ac843f3fb13d4601b5b6432e763ffb00` passed all 228 tests and comparison
checks, completed all four rounds, returned exit 0, and was fetched to
`/Users/samkim/.local/state/benchctl/results/ac843f3fb13d4601b5b6432e763ffb00`.
All three candidate hashes matched the measured snapshot. Guarded restoration
then restored and verified all three size-32 baseline hashes.

The expanded seeded geometric mean improved only 0.087%; the original sizes
through 33 were effectively flat (-0.004%). Size 33 improved 0.82–0.84%, and
sizes 63–65 improved 0.41–0.43%, with separated intervals. However, sizes four,
15, and 31 regressed 0.08–0.12% in both byte orders, and size two BE regressed
0.09%, with both candidate intervals above both baseline intervals. Other
small seeded cases overlapped. Mixed identities improved 0.20–0.23%; one
repeated-16 byte order also separated. Doubling workspace for every multipair
call is not retained on the strength of this near-flat aggregate and mixed
small-input results.

The boundary gains justify one targeted refinement: choose a 64-entry workspace
only when the remaining iterator's lower length hint exceeds 32, otherwise use
32. Unknown-length iterators keep the existing bounded size. A non-inlined
large-workspace wrapper keeps its stack frame out of short calls; the size-32
path retains normal compiler inlining. Hints never cap iteration, skip validation,
or determine acceptance. A new exact-value and invalid-input test varies hints,
including unknown and exaggerated hints, across the boundaries. The single-pair
path remains. Candidate checkpoint: `B13-adaptive`, four source/test/docs paths.

Adaptive job: `079fd66b418342b39dc425c3ab55f9f7`.
Source fingerprint: `cba3d3cf387ef462fffbc9ef5dfe4669404aa0510fd619e04a3295cc774b3317`.
Command: `benchctl submit --json --label bn254-B13-adaptive --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B13-adaptive --expected-cases 36 --cpu 16`.
This compares against fixed size 32 with the same native toolchain, flags,
fixtures, CPU, and ABBA settings. Fixed size 64 is absent from the baseline.


**Adaptive decision: discard.** Job `079fd66b418342b39dc425c3ab55f9f7`
passed all 229 tests and comparison checks, completed ABBA, and returned exit 0.
Results were fetched to
`/Users/samkim/.local/state/benchctl/results/079fd66b418342b39dc425c3ab55f9f7`.
All four current candidate hashes matched the snapshot. Guarded restoration
verified and restored all four baseline source/test/documentation paths.

Expanded seeded geometric-mean improvement was only 0.038%; the original
sizes through 33 regressed 0.062%. Size 33 improved 0.80–0.81% and sizes
63–65 improved 0.39–0.42%, with separated intervals. However, sizes eight,
15–17, and 31–32 regressed 0.17–0.21%, also with both candidate intervals
above both baselines. Three-pair LE regressed 0.15% with separated intervals.
Cancellation regressed 0.32–0.33% and mixed identities 0.37–0.50%; BE intervals
separated for both workloads, while LE overlapped. The refinement did not meet
the retention rule. Its saved patch includes the iterator-hint correctness test.
Fixed size 32 remains the baseline; no further batch-policy tuning is planned
in this cycle.

Final variant: `B13-soa`, separate 64-byte-aligned X/Y/Z arrays plus immutable
input-reference pairs, at retained size 32. Mutable coordinate views let the
existing double/add/correction formulas update the arrays in place. The layout
exposes contiguous Fq2 coordinate streams for SIMD lane packing, while this
experiment reuses the existing arithmetic kernels. A static source comparison
confirmed all three formulas are unchanged after normalizing dereferences.
The declared 32-point state remains 6.5 KiB (plus 8.75 KiB validation buffers,
frame alignment, and arithmetic temporaries); the existing workspace-bound
assertion now checks the complete array structure. Geometry, exact-Gt, and
boundary tests exercise the same production formulas through mutable views.
Three source/documentation paths are checkpointed; the adaptive policy and its
candidate-only test are absent.

Aligned-layout job: `19f7f6e21d20471a81c33942e9b59082`.
Source fingerprint: `5fad4ce072d97fa95c1f238a2d801a31e6504d6d064f09288870d3bd94cea904`.
Command: `benchctl submit --json --label bn254-B13-soa --artifact pairing-experiment-results -- python3 scripts/benchmark-bn254-experiment.py run --id B13-soa --expected-cases 36 --cpu 16`.
The same Rust 1.98.0/native settings, CPU 16, expanded byte fixtures, and full
ABBA protocol apply. The fixed-size-32 baseline matches the earlier B13 runs.


**Aligned-layout decision: discard.** Job `19f7f6e21d20471a81c33942e9b59082`
passed all 228 candidate tests and comparison checks, completed all four rounds,
and returned exit 0. Results were fetched to
`/Users/samkim/.local/state/benchctl/results/19f7f6e21d20471a81c33942e9b59082`.
All three current candidate hashes matched the measured snapshot. Guarded
restoration then restored the exact prior source and API-documentation bytes.
All paths across the four B13 checkpoints now match their saved size-32 baseline
hashes, including removal of the adaptive candidate's added test.

The expanded seeded geometric mean regressed 0.051%; the original sizes through
33 regressed 0.034%, and added sizes 63–65 regressed 0.110%. These are essentially
flat results: all batched cases had overlapping intervals across the two
candidate and two baseline rounds. Their small negative point estimates are
not presented as established regressions. One-pair BE improved 0.47% with
separated intervals; one-pair LE improved 0.24% with overlap. Special workloads
also overlapped. The isolated single-pair finding did not establish a benefit
for the batched point access targeted by this representation change. The
candidate is conservatively discarded rather than retaining a broader layout
rewrite without a clear batched gain. The patch, source hashes, and emitted
assembly remain available for future SIMD arithmetic work. Native Miller code
grew from 30,519 to 31,330 bytes; this alone does not establish the cause of any
timing difference.

| Cycle-21 variant | Expanded seeded latency reduction | Decision |
|---|---:|---|
| Fixed size 16 | -0.720% | Discard: clear ordinary and boundary regressions |
| Fixed size 64 | 0.087% | Discard: boundary gains, small-input regressions |
| Adaptive 32/64 | 0.038% | Discard: boundary gains, ordinary/special regressions |
| Aligned X/Y/Z arrays, size 32 | -0.051% | Discard: no clear batched benefit |

Positive reductions mean lower latency. Aggregates include the 28 nonempty
seeded case/byte-order combinations, with each weighted equally by geometric
mean; they exclude repeated, cancellation, identity, and empty workloads.
Those additional cases are evaluated individually. Original-size aggregates
above keep comparison with the previous matrix explicit. Decisions use the
individual intervals and workload tradeoffs, not only aggregate signs.

All four jobs used Rust 1.98.0, `RUSTFLAGS="-C target-cpu=native"`, CPU 16 on
the EPYC 9354P, the same locked dependencies, and the full ABBA protocol:
100 samples, one-second warmup, three-second measurement target, and 95%
intervals. Each comparison process checked 39 contract fixtures in both byte
orders and 144 timing fixtures against all three implementations. Candidate
test totals were 228, 228, 229, and 228 respectively. Every job was waited to
terminal success and fetched. Criterion data are in the custom
`outputs/pairing-experiment-results` artifact; the missing default
`target/criterion` artifact is expected. No additional confirmation job was
used to retain a near-noise result because no B13 candidate is being retained.

**Cycle 21 complete.** All 21 optimization ideas have completed implementation,
remote measurement, and a keep/discard decision: 11 retained, ten discarded.
The library, tests, and API documentation are back at their pre-cycle-21 bytes,
with fixed size 32 and the original entry layout. The benchmark fixture
expansion, matching runner default, benchmark guide, checkpoints, patches, and
result records remain. The expanded three-way harness has 108 measurements.
No job belonging to this task remains running. Final generic-x86 validation,
documentation cleanup, and a fresh full three-way performance comparison are
separate pending wrap-up work; this cycle does not claim those checks or new
Arkworks/Firedancer performance ratios.
