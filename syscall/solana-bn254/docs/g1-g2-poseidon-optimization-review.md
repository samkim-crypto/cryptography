# G1, G2, and Poseidon optimization experiments

Reviewed on 2026-09-22 against `bn254-gt` at `c9cf3a7` and the local
Firedancer checkout at `20c3fa1ff2dab737ec075c3e3e302ba778fd98fe`.
The original review below describes unmeasured candidates and the pre-experiment
implementation; its proposed speedups were not predictions.

Status on 2026-09-23: the user chose G1/G2 first. The planned G01–G13 trials
are settled on `bn254-g1-opt`; see the [measured decisions](group-optimization-experiments.md).
Both final source/comparator runs passed; see the
[consolidated results](group-optimization-results.md). Poseidon P01–P12 remains
deferred. The original suggested ordering below is superseded by that user-selected scope.

There are 25 primary experiment families: P01-P12 and G01-G13. Start with P01
and P02, which address a concrete gap between our Fq and Fr backends, then run
the G sequence and the remaining P sequence in order. Within a family, each
alternative is its own change/measure/keep-or-discard trial. A retained change
becomes the baseline for the next trial. Dependencies on discarded changes
must be reassessed rather than silently reintroducing them.

## Baseline optimizations and gaps before the experiments

- G1 and subgroup-checked G2 already use two-dimensional GLV, simple joint
  sparse form, a cheap `P + phi(P) = -phi^2(P)` table entry, and binary/GLV cost
  selection. Adding GLV or joint signed recoding is not a new experiment.
- Their GLV tables still compute `phi(P) - P` by affine addition, which costs
  an inversion. Final projective normalization costs another inversion.
- Raw G2 multiplication operates on the entire twist and remains binary.
  Its scalar must not be reduced modulo the subgroup order. The checked API
  must reject a non-subgroup point even when the scalar is zero.
- G2 already has the fast Frobenius subgroup test and a fixed signed chain for
  the BN parameter. A standalone check still normalizes its `3P` table entry.
  Pairing's batch subgroup check already shares these inversions.
- Inversion already uses Bernstein-Yang divsteps. Its inner batch still
  performs 62 single-bit iterations; the opportunity is to improve that
  implementation, not replace exponentiation-based inversion.
- Fq already has native ADX multiplication and a dedicated square. Fr, used by
  Poseidon, still uses Rust CIOS multiplication and `mul(a, a)` for squaring.
- Poseidon already has transformed round constants, sparse partial-round
  matrices, final-output-row pruning, and IFMA full-round S-boxes and dense
  matrix multiplication. Dense output accumulators already stay packed for
  a complete dot product. Existing width-specific code generation choices
  must be measured, not assumed to be accidental.
- Poseidon still packs matrix constants at runtime, converts state between
  scalar and packed representations between layers, and uses scalar arithmetic
  for the entire partial round. Although a partial round has only one S-box,
  its sparse matrix still has `2*T - 1` independent products to schedule.

Relevant local sources are [G1](../src/curve/g1.rs), [G2](../src/curve/g2.rs),
[GLV](../src/curve/glv.rs), [portable arithmetic](../src/backend/portable.rs),
[inversion](../src/backend/portable/inversion.rs), [Fq2](../src/backend/fq2.rs),
[Poseidon](../src/poseidon/mod.rs), and [Fr IFMA](../src/backend/avx512/math.rs).

## Baseline before the experiments

Add a G1/G2 comparison target; none exists in this checkout. Extend the
Poseidon comparison to Firedancer: the current benchmark compares typed field
inputs against light-poseidon on Arkworks and reuses one seeded input per
width. The current Firedancer snapshot runner captures BN254 dependencies,
but must be extended to capture Poseidon source and constants too.

Measure these separately:

- G1/G2 addition, doubling, and scalar multiplication on decoded points;
  subgroup checking by itself; and complete decoding/checking/arithmetic/
  encoding calls. Compare ours, Arkworks, and Firedancer at equivalent
  validation boundaries. Use an explicit harness for raw full-twist G2
  arithmetic where a comparator's public syscall exposes only checked G2.
- Small, 64-bit, 128-bit, random full-width, sparse, and near-order scalars
  across multiple seeded point pools. Include all per-call table work and
  final normalization in variable-base scalar multiplication measurements.
- Poseidon at every supported input count, 1-12 (`T=2..13`), with rotating
  seeded input pools. Report typed-input hashing separately from complete
  byte-input adapters. Include equivalent validation and serialization in
  the latter; record whether parameter initialization is amortized.
- Correctness fixtures for identity, equal/opposite points, full-width scalars,
  noncanonical encodings, arbitrary twist points, cofactor torsion, and invalid
  subgroups. Poseidon must preserve both complete permutation outputs and
  circom-compatible digests, including boundary field inputs and custom
  parameter support.

Use benchctl on `solana-devserver`, the shared queue, Rust 1.98.0, locked
dependencies, and recorded CPU affinity. Keep three explicitly named Rust
configurations: generic x86 (`-C target-cpu=x86-64`), native scalar
(`-C target-cpu=native -C target-feature=-avx512ifma`), and native IFMA
(`-C target-cpu=native`). Confirm the intended feature selection in each
build. Do not call both generic x86 and native scalar merely "regular".

Freeze the Firedancer source and compiler configuration for the series.
Its existing pairing comparator uses GCC native ADX with the optional
s2n-bignum backend disabled; that configuration is not a claim about every
possible Firedancer build. Record the C flags separately from Rust flags.

For each trial, run correctness checks, then baseline/candidate/candidate/
baseline measurements under the same conditions. Keep only repeatable gains
in the affected complete operations, with no material regressions in other
supported cases. Microbenchmarks explain a result; they do not override an
end-to-end regression. Recheck pairing/GT when shared Fq/Fq2 code changes.
Wait for and fetch each exact job UUID, retaining source fingerprints, flags,
commands, and result paths as described in [BENCHMARKING.md](../BENCHMARKING.md).

## Poseidon sequence

| ID | Change to test | Why it could help; main qualification |
| --- | --- | --- |
| P01 | Native ADX/BMI2 Montgomery multiplication for Fr. Adapt the retained Fq kernel to Fr's modulus and inverse. | Partial rounds and scalar builds currently miss this kernel. Firedancer already has native Fr multiplication [FD-Fr]. Preserve the generic fallback and re-establish the Fr bounds. |
| P02 | Dedicated scalar Fr squaring. | Each `x^5` S-box needs two squares and one multiplication. Symmetric products can make a square cheaper than `mul(a,a)`. Firedancer's native Fr square also delegates to multiplication, so this is an opportunity beyond that implementation. |
| P03 | Dedicated IFMA Fr squaring. | Replace the two general multiplications used as squares in each packed S-box. The five-limb product has 15 distinct square terms rather than 25 ordered multiplication terms; reduction still costs work. Account for the current `2^256`/`2^260` radix correction when exploiting symmetry [IFMA-square]. |
| P04 | Generate packed 52-bit matrix and round constants for the built-in parameter sets. | Remove recurring column gathering and 64-to-52-bit conversion. Keep the custom-parameter path valid and measure the larger constant tables' cache cost. This goes beyond the already-retained packed dense accumulators. |
| P05 | Pre-scale fixed multiplication operands for the IFMA radix correction. | The current general multiply scales one operand by 16 on every call. Store fixed matrix operands in the required scaled form and use a private constant-multiply entry point. Those operands have a different range contract from ordinary canonical field elements. |
| P06 | IFMA sparse-matrix multiplication in partial rounds. | Parallelize the row-dot-product terms and the independent column updates, initially keeping the single S-box scalar. Width-dependent packing and horizontal summation costs can erase the gain, especially at small widths. |
| P07 | Keep state packed across full-round layers. | Carry packed state through round-constant addition, S-box, and dense matrix multiplication, converting at the scalar partial-round boundary. This removes conversions between layers, not merely within an existing matrix dot product. |
| P08 | Fused scalar Fr sums of products for matrix rows. | Share Montgomery reduction across several products instead of reducing each product and each sum separately. Apply first to the sparse first row and final hash row; use it in scalar dense matrices where beneficial. Longa provides the general sums-of-products technique [sums]. |
| P09 | Fused IFMA matrix dot products. | Accumulate multiple product contributions before carry/reduction work, replacing the current canonical `mul_8x` plus `add_8x` per term. This requires a separate vector accumulator proof and scheduling experiment; a win for P08 does not establish a win here. |
| P10 | A private `R=2^260` Montgomery representation for the permutation. | Remove repeated radix correction by converting at the permutation boundaries. Prototype a complete compatible path, including the serial partial S-box; conversions on every partial round could defeat the benefit. Larger reduction headroom may also improve P09. Higher implementation cost. |
| P11 | Bounded lazy intermediates within `x^5`. | Test carrying noncanonical but explicitly bounded values through `x^2`, `x^4`, and `x^5`, then canonicalizing at the boundary. Scalar and IFMA variants are separate trials. Limb normalization needed by IFMA cannot simply be omitted. |
| P12 | Choose scalar/IFMA execution per width using the improved kernels. | Small states leave SIMD lanes idle; widths 9-13 need a partially filled second vector. Retune compile-time selection after the kernel experiments rather than assuming IFMA wins at every width. Preserve benefits at each input count instead of optimizing only an aggregate mean. |

For P08/P09, a 64-bit-radix Montgomery reducer that promises a result below
`2r` cannot accept an arbitrary 13-term unreduced dot product. For canonical
operands and `R=2^256`, chunks of at most five products satisfy `5r < R`;
six do not. Use bounded chunks or prove a different accumulator/reducer.
P10 changes the radix and therefore requires a new analysis, not reuse of
the old bounds. These are implementation changes to the existing
[Poseidon permutation](https://eprint.iacr.org/2019/458), preserving its
parameters and exact outputs.

## G1/G2 sequence

| ID | Change to test | Why it could help; main qualification |
| --- | --- | --- |
| G01 | Skip runs of divsteps using trailing-zero counts. | Improve the existing variable-time inverse, benefiting affine addition, GLV preparation, and final normalization. Start with equivalent transition matrices and retain the existing integer-oracle tests. libsecp256k1 demonstrates this technique [safegcd]. |
| G02 | Dedicated wide-product Fq2 squaring. | Compare the existing two CIOS products with a square-specific schedule using the retained wide-product/reduction machinery. Multiplication is already wide Karatsuba; this experiment is specifically about squaring. Re-run pairing regressions. |
| G03 | Retune point-doubling formulas. | Compare `3M+4S` with `2M+5S` separately for G1 and G2 after the field changes. They currently choose different formulas; the best choice depends on the new square/multiply cost and modular additions, not an operation count alone [EFD]. |
| G04 | Retune mixed-addition formulas. | Compare the current `8M+3S` schedule with `7M+4S`, including extra additions and exceptional cases. Treat it independently from G03 so the measured cause remains clear [EFD]. |
| G05 | Specialize exact integer products in GLV decomposition. | Replace generic wide products with bounded-width products and high-product helpers for the fixed constants. Firedancer uses specialized helpers [FD-GLV]. Retain all carries that affect the high half and verify reciprocal boundaries with integer oracles. |
| G06 | Remove the GLV table's setup inversion with a common denominator. | Construct the table projectively, use a global-Z/isomorphic-curve representation, and fold its denominator into final normalization. This targets the remaining `phi(P)-P` inversion while retaining cheap mixed additions. libsecp256k1 provides a related table technique [global-Z]. |
| G07 | Wider signed windows for two-way GLV. | Compare widths 3, 4, and 5 against current joint sparse form; derive endomorphism images cheaply and include table construction/normalization in every call. Additional tables must earn back their preparation and cache costs. |
| G08 | Signed-window multiplication for raw G2. | Replace binary multiplication on the full twist with ordinary windowed multiplication over the original 256-bit integer. This path can reduce additions without assuming subgroup membership or reducing modulo `r`. Include small/torsion-point exceptions in table preparation. |
| G09 | Avoid normalizing `3P` in the standalone G2 subgroup chain. | Keep that entry projective and compare its extra addition costs against the saved Fq2 inverse. Any alternative fixed chain is a separate trial. Keep the full-twist semantics required by a membership test; pairing's existing batched normalization remains a separate workload. |
| G10 | Fuse bounded point-formula linear combinations. | Reduce repeated modular corrections in expressions such as `3A`, `4XB`, and `8C`, using private range-checked helpers. An expression like `8C` can exceed 256 bits, so merely deleting reductions is invalid. Return canonical public coordinates. |
| G11 | Four-way Frobenius decomposition for checked G2. | Test a Galbraith-Scott-style decomposition over `P`, `psi(P)`, `psi^2(P)`, and `psi^3(P)` against two-way GLV. Shorter components reduce serial doublings, but extra decomposition and joint-table work may offset them [pairing-groups]. Restrict it to validated subgroup points. |
| G12 | IFMA scheduling within point arithmetic. | Reuse the retained Fq IFMA kernels to group independent products/squares, especially Fq2 components, and retain packed coordinates across a scalar loop where useful. This is a single-operation latency experiment; packing costs and dependency chains are the principal risks. |
| G13 | Retune scalar strategy selection after the preceding changes. | Update the current fixed doubling/addition/setup weights using complete-call measurements. Compare binary, centered-scalar, two-way GLV, wider windows, and four-way G2 only where valid. Keep setup inexpensive for small/sparse scalars and measure the selector's own cost. |

G01 may motivate a later, separate inversion experiment using shrinking active
limb lengths, as in libsecp256k1. Keep that out of the first trailing-zero
change so its effect can be measured independently.

## Conditional retest and additional workloads

Direct G2 `psi^2` is a conditional retest, not a fresh high-priority idea.
It was included in the discarded A02 pairing/Frobenius change. If standalone
G2 profiling justifies it, isolate that map, measure subgroup checking and
checked multiplication, and recheck pairing before retaining a shared helper.
See the [A02 record](pairing-optimization-experiments.md).

The earlier B13 pairing batch/layout experiments likewise do not establish
the outcome of G12, but they are a reason to measure packing overhead early.

Three additional experiments concern amortized work or throughput and should
have their own benchmarks and API decisions:

1. Prepared G1/G2 bases that reuse subgroup validation and multiplication
   tables across calls. Report preparation time and the reuse break-even
   point; do not compare a prepared call with Firedancer's fresh-base call.
2. Batched point operations with zero-aware batch normalization and independent
   points across IFMA lanes. Report batch throughput and single-call latency
   separately.
3. Eight independent Poseidon hashes across IFMA lanes. This also parallelizes
   partial-round S-boxes, including at small widths; require enough independent
   inputs and report latency plus hashes per second.

## References

The references describe techniques or existing implementations; their reported
speedups are not estimates for this crate or this devserver.

- **FD-Fr:** [Firedancer scalar arithmetic](https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bn254/fd_bn254_scalar.h),
  [native multiplication](https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bigint/fd_uint256_mul.h),
  and [Poseidon](https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/poseidon/fd_poseidon.c).
- **FD-GLV:** [Firedancer GLV integer helpers](https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bn254/fd_bn254_glv.h).
- **safegcd:** [libsecp256k1's safegcd explanation, section 6](https://github.com/bitcoin-core/secp256k1/blob/master/doc/safegcd_implementation.md)
  and [64-bit implementation](https://github.com/bitcoin-core/secp256k1/blob/master/src/modinv64_impl.h),
  building on [Bernstein-Yang](https://eprint.iacr.org/2019/266).
- **EFD:** [Explicit-Formulas Database: Jacobian coordinates, a=0](https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html).
- **global-Z:** [libsecp256k1 multiplication tables and isomorphism](https://github.com/bitcoin-core/secp256k1/blob/master/src/ecmult_impl.h).
- **pairing-groups:** Bos, Costello, and Naehrig,
  [Exponentiating in Pairing Groups, section 2.2](https://eprint.iacr.org/2013/458.pdf).
- **IFMA-square:** Drucker and Gueron,
  [Fast modular squaring with AVX512IFMA](https://eprint.iacr.org/2018/335).
- **sums:** Longa,
  [Efficient Algorithms for Large Prime Characteristic Fields and Their Application to Bilinear Pairings](https://eprint.iacr.org/2022/367).

[FD-Fr]: https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bn254/fd_bn254_scalar.h
[FD-GLV]: https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bn254/fd_bn254_glv.h
[safegcd]: https://github.com/bitcoin-core/secp256k1/blob/master/doc/safegcd_implementation.md
[EFD]: https://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
[global-Z]: https://github.com/bitcoin-core/secp256k1/blob/master/src/ecmult_impl.h
[pairing-groups]: https://eprint.iacr.org/2013/458.pdf
[IFMA-square]: https://eprint.iacr.org/2018/335
[sums]: https://eprint.iacr.org/2022/367
