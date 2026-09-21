**BN254 pairing optimization review — 2026-09-21**

The clearest immediate opportunities are modular halving, specialized Frobenius
maps, and Miller-loop cleanup. Fused field arithmetic and an AVX-512 IFMA pairing
backend offer larger potential gains, with substantially more implementation work.
These are the original source-review findings and research proposals, not measured
speedups. All 21 cycles are now complete; see the
[experiment record](pairing-optimization-experiments.md) for decisions and the
[implementation references](pairing.md#optimization-sources) for retained code.

Reviewed `bn254-gt` at `23548d076999e01ed04de48ffee2b49d7eda4adf` and the local
Firedancer checkout at `20c3fa1ff2dab737ec075c3e3e302ba778fd98fe`. References to
Firedancer below mean this checkout and its benchmarked configuration, not every
Firedancer version or optional backend. The active Rust pairing implementation
is `src/pairing/`, rather than the untracked `src/curve/pairing.rs`.

The existing complete-call benchmark puts our latency between 0.40% below and
1.83% above Firedancer for nonempty seeded inputs across both byte orders. The
separate cancelling case has a larger gap. Calls include byte decoding, point
validation, subgroup checks, preparation, allocation where applicable, Miller
loops, final exponentiation, and Boolean encoding. Thus a field-operation count
cannot be interpreted directly as a complete-call speedup. The run was serialized
by benchctl but not CPU-pinned or isolated from unrelated server processes.

**Optimizations present in Firedancer that we can adopt**

1. **Replace multiplication by one-half with modular halving. High priority.**
   Our [homogeneous doubling](../src/pairing/miller.rs) multiplies two Fq2 values
   by the Montgomery representation of 1/2. That is four base-field Montgomery
   multiplications per doubling, or 256 per active pair across 64 doublings.
   Firedancer's
   [fp_halve](https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bn254/fd_bn254_field_inl.h#L225)
   computes `(a + (a is odd ? q : 0)) >> 1`. This also works directly on our
   canonical Montgomery residues. Add a base-field halving helper and apply it
   componentwise. The operation count is a source-level saving; benchmark the
   compiled result rather than treating it as a predicted percentage.

2. **Specialize Fq12 Frobenius maps and the G2 second Frobenius. High priority.**
   Our [Fq12 map](../src/backend/fq12.rs) composes Fq6 maps and another coefficient
   multiplication, expressing seven Fq2 constant multiplications. Firedancer
   [combines the constants](https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bn254/fd_bn254_field_inl.h#L810)
   into five. Its second Frobenius uses base-field constants, requiring ten Fq
   multiplications instead of generic complex arithmetic. Generate combined
   tables for the powers actually used, including a direct third-power map.
   Similarly, replace repeated G2 first-Frobenius applications with a direct
   second-power map where appropriate in subgroup checking and Miller correction.
   Check assembly for constant folding before attributing the full source-level
   difference to runtime work.

3. **Compute only the last correction line. High priority, small change.**
   Firedancer's
   [last mixed addition](https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bn254/fd_bn254_pairing.c#L210)
   disables the point update. Our `Homogeneous::add` also computes the new X, Y,
   and Z although this final point is unused. A line-only helper removes two Fq2
   squares and seven Fq2 multiplications from the source formula per active pair.
   LLVM may already eliminate some of this work, so inspect generated code.

4. **Put the factor of three on the G1 coordinate. Small, broadly applicable.**
   Our doubling line computes `3 * X²` in Fq2 before multiplying by `P.x`.
   Firedancer computes `3 * P.x` in Fq instead. This halves the componentwise
   additions needed for this factor. It is visible in
   [the doubling formula](https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bn254/fd_bn254_pairing.c#L9).
   Precomputing the scaled G1 coordinate once per pair improves this further;
   that additional step is not implemented in the inspected Firedancer code.

5. **Use a better fixed exponentiation chain. Medium priority.**
   For the positive BN parameter `x`, Firedancer's
   [pow_x](https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bn254/fd_bn254_final_exp.c#L65)
   uses 62 cyclotomic squares and 17 Fq12 multiplications. Our
   [chain](../src/pairing/final_exp.rs) needs 63 and 18 including its table setup.
   There are three such exponentiations in the hard part. However, our existing
   compressed squaring is an advantage: compare chains while retaining it and
   accounting for decompression costs and live temporaries. Firedancer's longer
   runs of consecutive squares could reduce the number of decompressions.
   A newer chain discussed below is an additional candidate.

6. **Add an explicit x86 ADX/BMI2 field kernel. Potentially substantial.**
   Firedancer's
   [Montgomery kernel](https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bigint/fd_uint256_mul.inc#L16)
   uses `mulx` and independent `adcx`/`adox` carry chains. Its add/subtract helpers
   also explicitly control carries and conditional reduction. Our
   [portable backend](../src/backend/portable.rs) expresses these operations in
   Rust using u128 arithmetic. Native compiler flags do not guarantee the same
   instruction scheduling. Compare emitted assembly and prototype a specialized
   backend, retaining the portable implementation. Do not assume that every Rust
   conditional currently emits a branch; LLVM can already select branchless code.

7. **Tune inlining and register pressure deliberately. Experimental.**
   Firedancer marks several substantial Fq2/Fq6 helpers `noinline`; our field
   tower encourages inlining. Measure instruction-cache misses, spills, and
   call overhead before choosing boundaries. Blanket inlining or blanket
   `noinline` is not a demonstrated improvement. This is particularly relevant
   when introducing large assembly or fused field routines.

8. **Stream byte inputs through bounded storage. Wrapper optimization.**
   Firedancer's
   [syscall adapter](https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bn254/fd_bn254.c#L293)
   uses fixed-size point arrays. Our [comparison adapter](../benches/common/pairing.rs)
   allocates a Vec of all decoded pairs. An equivalent checked streaming adapter
   can eliminate this allocation and reduce memory traffic. The Rust core
   multi-pairing implementation already uses bounded stack storage; this finding
   concerns the byte-input wrapper, and its likely contribution must be profiled.

**Optimizations absent from the inspected Firedancer implementation**

1. **Use the newer 60-square, 17-multiply BN-parameter chain.** Current
   [gnark code](https://raw.githubusercontent.com/Consensys/gnark-crypto/master/ecc/bn254/internal/fptower/e12_pairing.go)
   has a shorter chain than either implementation. I independently evaluated
   its exponent and counted the operations. Prototype it with our compressed
   square runs; the best chain depends on decompression and register costs too.

2. **Multiply two sparse lines together before updating the dense accumulator.**
   The [gnark sparse-field routines](https://raw.githubusercontent.com/Consensys/gnark-crypto/master/ecc/bn254/internal/fptower/e12_pairing.go)
   support this transformation. From their formulas, two ordinary line updates
   cost 26 Fq2 multiplications; a sparse line product followed by a five-coefficient
   update costs 6 + 17 = 23. Apply this to doubling/addition steps and correction
   lines. Combining lines from different pairs is another opportunity. These
   counts exclude additions and nonresidue multiplications, so they are not
   timing predictions.

3. **Initialize accumulators by assignment instead of multiplying by one.**
   Our first line still passes through `mul_by_034`, and our first completed
   batch is multiplied by an identity Fq12 accumulator. Assign these first values
   directly. [Gnark's Miller loop](https://raw.githubusercontent.com/Consensys/gnark-crypto/master/ecc/bn254/pairing.go)
   illustrates first-line initialization. Our loop already skips the initial
   accumulator square, so there is no additional square to remove there.

4. **Hoist invariant G1 scaling and G2 negation outside the loop.**
   Prepare `3*P.x`, `-P.x`, `-P.y`, and `-Q.y` once where the chosen formulas need
   them. Firedancer explicitly leaves G1 precomputation as a TODO. Our loop also
   rebuilds `-Q.y` on negative digits. Balance the arithmetic savings against
   enlarging each batch entry. The existing `to_montgomery()` point accessors
   merely copy stored coordinates; they are not repeated Montgomery conversions.

5. **Fuse sums of products with Montgomery reduction. High potential.**
   Both implementations already use lazy input sums in Fq2, but reduce individual
   products before many higher-tower combinations. Investigate kernels for
   expressions such as `a*b + c*d` and `a*b - c*d` using
   [Longa's generalized interleaved reduction](https://eprint.iacr.org/2022/367).
   This can reduce reduction work and intermediate storage in Fq2/Fq6/Fq12.
   It requires new internal bounds: Firedancer explicitly notes that simply
   making its Fq6 additions lazy would violate the Fq2 input range. Use private
   bounded representations and restore canonical residues at public boundaries.

6. **Fuse scalar assembly at the Fq2 or larger-operation level.**
   The inspected Firedancer base-field assembly reserves stack space and saves
   six registers on every multiplication. A dedicated Fq2 multiply/square kernel
   can share modulus loads, register saves, and intermediate values across its
   component products. This is distinct from changing the reduction algorithm:
   even the existing algebra may benefit from better register scheduling. The
   benefit depends on the actual caller/callee code and must be measured.

7. **Build an AVX-512 IFMA backend for Fq and the pairing field tower. Highest
   architectural upside, substantial work.** Our active scalar backend alias is
   [PortableBackend](../src/backend/mod.rs). The existing
   [IFMA arithmetic](../src/backend/avx512/math.rs) is specialized to Fr for
   Poseidon, not Fq for pairings. Native flags therefore did not activate vector
   pairing arithmetic in the baseline. Two approaches deserve evaluation:
   parallelize independent coefficients within a single pairing, and parallelize
   G2/line work across multiple pairs. Keep a scalar path for unsuitable sizes.
   A [2025 TCHES implementation](https://eprint.iacr.org/2025/1283) demonstrates
   IFMA vectorization of pairing extension fields, including single-pair latency
   improvements. Its BLS12-381 results on Intel are evidence for the technique,
   not a predicted BN254 speedup on our AMD server. Derive Fq constants, handle
   52-bit versus 64-bit Montgomery radices explicitly, and keep data packed across
   substantial portions of the computation.

8. **Implement dedicated base-field Montgomery squaring.** Both current scalar
   backends implement `square(a)` as `multiply(a,a)`. Four-limb integer squaring
   has ten distinct limb products rather than sixteen, although doubling cross
   terms and Montgomery reduction still cost work. Firedancer itself has a TODO
   for specialized squaring in `fd_uint256_mul.h`. Expect the benefit mainly where
   true base-field squares occur; our optimized Fq2 square already uses two
   base-field multiplications, so this does not automatically accelerate every
   extension-field square.

9. **Amortize subgroup-check table normalization across pairs.** Our
   [fixed-x scalar multiplication](../src/curve/g2.rs) converts `3Q` to affine,
   normally paying one Fq2 inversion per nonidentity input. Form these triples
   in projective coordinates for a batch and normalize them with one zero-aware
   batch inversion. Alternatively compare a chain/table representation that
   avoids this normalization. This must still work on arbitrary on-curve twist
   points because the subgroup check has not yet succeeded. Keep the existing
   fast subgroup-membership criterion.

10. **Return early when the easy final exponent produces one.** We test for one
    before final exponentiation, but not after its easy part. Add that second
    check, as in [gnark](https://raw.githubusercontent.com/Consensys/gnark-crypto/master/ecc/bn254/pairing.go).
    It skips the hard part for this subset of inputs. A final pairing product
    equal to one does not imply that this earlier intermediate is one, so it is
    not a universal shortcut for every successful verification.

11. **Combine repeated G2 arguments using bilinearity.** For equal Q, replace
    `e(P1,Q)*e(P2,Q)` with `e(P1+P2,Q)`, and reuse the successful Q subgroup check
    within the call. The analogous equal-P grouping may also help, but requires
    more expensive G2 additions. This can substantially reduce repeated-point
    workloads and expose cancellations. It is unlikely to help unique random
    inputs, and lookup/addition overhead needs a threshold. Decode and validate
    all original inputs, including identity pairs and invalid trailing inputs,
    before accepting a combined result.

12. **Offer prepared, subgroup-checked G2 inputs for reusable workloads.** A
    separate API can cache fixed-Q line coefficients and validation for repeated
    verification keys. This moves substantial per-call work into reusable setup.
    Preparation time and memory must be reported separately; cached inputs are
    a different benchmark contract from the current fresh-byte-input comparison.

13. **Tune the Miller batch size and layout.** Our batch limit is 32 active pairs;
    Firedancer's is 16. Neither establishes the best size for the EPYC server.
    Larger or adaptive batches can share more Fq12 squarings, while increasing
    stack use and cache pressure. Sweep batch boundaries and evaluate a layout
    suitable for SIMD. Our existing 32-entry stack-bound test expresses a design
    choice that would need deliberate revision, not an accidental overwrite.

**Existing advantages and constraints**

Our crate already has the fast Frobenius-based G2 subgroup test, signed Miller
digits, shared multi-pairing squaring, one final exponentiation for the complete
product, sparse line multiplication, Karatsuba Fq2 multiplication with lazy sums,
two-multiplication Fq2 squaring, Granger–Scott and compressed cyclotomic squaring,
and a specialized multiplier for `9+u`. These should not be presented as missing
optimizations. Base-field inversion already uses batched Bernstein–Yang divsteps;
the benchmarked Firedancer configuration instead uses exponentiation because
s2n-bignum is disabled. Enabling that optional backend is a separate baseline
comparison and could change the relative results.

Likewise, [residue-check methods for proving pairings](https://eprint.iacr.org/2024/640)
use auxiliary witnesses. Their circuit/proof-verification savings do not by
themselves establish a faster native drop-in implementation when witness
generation is included. Treat them as a separate API/protocol investigation.

Preserve exact Arkworks-normalized Gt outputs as well as Boolean pairing checks.
Alternative final exponents can preserve the latter while changing the former.
Preserve full input validation; shortcuts that assume subgroup membership before
checking it are not equivalent implementations.

I would first prototype halving, combined Frobenius maps, the last-line helper,
and accumulator initialization. Next compare the new exponent chain and sparse
line fusion. Profile decoding, G2 validation, Miller work, and final exponentiation
separately to choose between fused scalar arithmetic and IFMA as the larger
investment. Run correctness and timings through benchctl with the same complete
call contract, CPU affinity, compiler settings, and input families. Attribute
gains one change at a time before testing the combined implementation.

**Baseline provenance**

The benchmark artifacts predate this review; no new implementation or benchmark
run was made for the review.

- Measured benchctl UUID: `1875c1f4971a4eff904ace997a1b96ca`.
- Source fingerprint: `8d8d00894a82e81244f3b6eea7ee48947ec8b696d8c23838300c5256a0913da5`.
- Host: `solana-devserver`, AMD EPYC 9354P.
- Rust 1.98.0, `RUSTFLAGS="-C target-cpu=native"`; GCC 13.3,
  `-O3 -march=native -mtune=native`, native ADX/BMI2, s2n-bignum disabled.
- Command: `benchctl submit --json --label bn254-pairing-full --artifact pairing-comparison-metadata.json -- python3 scripts/benchmark-bn254-pairing.py run`.
- Fetched results: `/Users/samkim/.local/state/benchctl/results/1875c1f4971a4eff904ace997a1b96ca`.
- [Full measurements, confidence intervals, flags, and commands](../../../target/pairing-benchmark-analysis/1875c1f4971a4eff904ace997a1b96ca/summary.md).
