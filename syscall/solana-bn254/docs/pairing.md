# BN254 pairing conventions

The extension-field foundation, target group and checked pairing engine are
implemented. This document records their representation and compatibility
contracts.

## Field tower and ranges

Let q be the BN254 coordinate-field modulus and r the scalar-field modulus:

- Fq2 = Fq[u] / (u² + 1).
- Fq6 = Fq2[v] / (v³ − (9 + u)).
- Fq12 = Fq6[w] / (w² − v).

The flattened Fq2 coefficient order for Fq12 is
[1, v, v², w, vw, v²w]. Each Fq2 coefficient is c0 + c1*u.

Every stored Fq coefficient is a canonical Montgomery residue below q, with
radix R = 2²⁵⁶. Fq6/Fq12 constructors accept already validated coefficient
types. Arithmetic returns the same representation. The private Fq2
multiplication sums retain their existing bound below 2q. The nonresidue
multiplier uses separate bounded accumulators internally; neither helper
changes the public base-field preconditions.

Scalar Fq2 multiplication forms three 512-bit Karatsuba products and performs
only two Montgomery reductions. With q < 2²⁵⁴, the imaginary numerator is
below 2q² < qR; the real numerator is corrected by qR if negative. Each REDC
input is below qR, so one final subtraction gives a canonical coefficient.
This uses the lazy-reduction technique in
[Aranha et al., Section 3.1](https://eprint.iacr.org/2010/526), with local
BN254-specific bounds.

On Linux x86-64, compile-time ADX/BMI2 enables the Fq multiplication kernel
adapted from Firedancer. AVX-512 F/DQ/IFMA enables six parallel Fq2 products
inside Fq6 multiplication. The SIMD helper normalizes its private input sums
below 2q; scaling one operand by 16 reconciles five 52-bit CIOS steps with
the external radix R=2²⁵⁶. These helpers return canonical residues. Other
targets retain portable arithmetic; no runtime CPU dispatch is performed.

Multiplication by xi = 9+u uses (9a−b) + (a+9b)u. For canonical a,b,
the helper forms 9a+q−b and a+9b in five-limb integer accumulators, each
below 10q. It reduces each accumulator before returning canonical Fq2
coefficients in the same Montgomery representation. The private reducer
and its carry bounds are documented and independently tested in
[src/backend/fq6/nonresidue.rs](../src/backend/fq6/nonresidue.rs).
Fq6 multiplication reduces the polynomial with v³=xi. Its inverse uses
t0=a0²−xi*a1*a2, t1=xi*a2²−a0*a1, t2=a1²−a0*a2; multiplication
by t0+t1*v+t2*v² leaves only a0*t0+xi*(a2*t1+a1*t2).
Fq12 uses the quadratic norm a0²−v*a1². Zero has no field inverse.

Frobenius multipliers are derived with integer arithmetic by
[scripts/generate_extension_constants.py](../scripts/generate_extension_constants.py):
xi^((q^k−1)/3), xi^(2(q^k−1)/3), and xi^((q^k−1)/6).
The tests check these maps using generic exponentiation rather than another
copy of the tables.

## Target-group and pairing normalization

The target group, `gt::Gt`, is the multiplicative subgroup of Fq12 with order r.
Its private storage preserves subgroup membership. `Gt::from_fq12` accepts only
nonzero values whose r-th power is one, using generic field exponentiation
without reducing that exponent modulo r. There is no unchecked public
constructor. Field zero is not a target-group element; identity and Default
are field one. Generic field values, Miller-loop outputs, cyclotomic values
and target-group values have different invariants.

Conjugation of an arbitrary Fq12 element is its q⁶ power. It equals inversion
only when the relative norm is one. Cyclotomic formulas must not be applied
to arbitrary field elements.

Gt inversion uses conjugation: r divides q⁴−q²+1, and
(q²+1)(q⁴−q²+1)=q⁶+1, so every Gt element g satisfies g^(q⁶+1)=1.
Group multiplication and squaring preserve the order-r invariant.
`Gt::pow` accepts an ordinary unsigned 256-bit integer, including values at or
above r; its input is not a Montgomery Fr element. Dense exponents use a
three-bit sliding window when the schedule saves at least four multiplications,
covering the odd-power table cost of three multiplications and one square.
Short or sparse exponents retain binary exponentiation. All coefficients
remain canonical Montgomery residues with no representation changes.
The window schedule follows
[Handbook of Applied Cryptography, Algorithm 14.85](https://cacr.uwaterloo.ca/hac/about/chap14.pdf);
the threshold for selecting it is specific to this implementation.

[tests/gt.rs](../tests/gt.rs) checks exact coefficients against Arkworks for
construction and group operations, full-width scalar boundaries and dependent
chains. It also checks rejection of zero and nonmembers that have norm one or
belong to the larger cyclotomic subgroup.

Pairing values match the workspace's Arkworks 0.5 BN254 convention.
Let x=4965661367192848881, E=(q¹²−1)/r and
c=2x(6x²+3x+1). Arkworks' final-exponentiation chain computes the exponent
cE, with the hard part c(q⁴−q²+1)/r after the easy part.

The test pairing_contract::final_exponent_convention_matches_arkworks_exactly
proves the integer exponent identity and compares the new field's generic
exponentiation with Arkworks' optimized chain. The production final-exponent
unit tests additionally compare its result with generic integer exponentiation
and Arkworks for seeded arbitrary Fq12 inputs, including zero rejection. Since 0<c<r and r is prime,
this multiplier preserves identity checks, but it changes general target-group
values. Boolean pairing checks alone do not establish exact-value compatibility.

The hard chain is from Fuentes-Castañeda, Knapp and Rodríguez-Henríquez,
[Faster Hashing to G2, Section 4.1](https://cacr.uwaterloo.ca/techreports/2011/cacr2011-26.pdf).
Its concrete normalization matches the
[Arkworks 0.5 BN implementation](https://raw.githubusercontent.com/arkworks-rs/algebra/v0.5.0/ec/src/models/bn/mod.rs).

## Pairing engine and API

The public functions in `solana_bn254::pairing` are:

- `pairing(&g1::Affine, &g2::Affine) -> Option<Gt>`.
- `multi_pairing` over an iterator of borrowed `(G1, G2)` pairs, returning
  `Option<Gt>`.
- `pairing_product_is_one` over the same input, returning `Option<bool>`.

Every G2 input is subgroup-checked before skipping identities. Empty input
returns identity; an invalid G2 point returns None, including when paired with
G1 identity or placed after a cancelling prefix. These APIs accept typed points;
byte decoding and syscall version handling remain separate.

The Miller loop uses the signed expansion of 6x+2 and correction lines at
psi(Q) and -psi²(Q). The fixed schedule is verified at compile time. Tests
also check every scalar prefix and correction step modulo r: no point doubled
is identity or has order two, and no mixed addition adds equal or opposite
points. This establishes the preconditions of the incomplete line formulas
for every nonidentity point of prime order r.

Line updates use homogeneous coordinates (X/Z,Y/Z). They do not reuse the
Jacobian G2 implementation's point representation. For the D twist, line
coefficients produce `ell_y*P.y + ell_x*P.x*w + ell_0*v*w`, with sparse Fq2
positions 0,3,4. Independent tests compare updated points and line coefficients
against affine group arithmetic, including a nontrivial projective scale, and
compare sparse evaluation with a dense Fq12 product.

Multi-pairing borrows the immutable affine inputs and keeps at most 32 active
pairs in 6.5 KiB of point state on the stack (on 64-bit targets). Bounded
subgroup validation shares normalization of the fixed-chain 3Q precomputations
through one zero-aware Fq2 inverse, adding 8.75 KiB of declared buffers at this
batch size. Arithmetic temporaries require additional stack space. Every input
is checked on successful calls, including identity pairs, and Miller batches
still count active pairs. Input chunks are consumed before validation; on
failure, later chunks need not be consumed or checked. It performs shared
Miller squaring within each batch, multiplies all batch results and
runs one final exponentiation for the complete product. Input length is
unbounded by the API and tails are processed with their actual active count.
No heap allocation, prepared line table or runtime dependency is required.
Batch size 32 is a bounded workspace choice measured in the batching
investigation, not a measured optimum.

The easy exponent `(q⁶−1)(q²+1)` enters a private cyclotomic type. Only this
type exposes specialized cyclotomic squaring and conjugation-as-inverse.
The hard chain computes the documented Arkworks-normalized exponent. Its
sealed result lets Gt accept the proven order-r element without repeating
subgroup exponentiation. Arbitrary Fq12 still requires the checked public Gt
constructor. Field, Miller-loop, cyclotomic and final-exponent outputs have
separate internal types. Zero has no final-exponent output.

All stored line and final-exponent coefficients are canonical field elements
with R=2²⁵⁶. The nonresidue helper contains its private wide accumulators and
returns canonical coefficients before subsequent field operations. G2
curve/Frobenius constants and the Fq6 nonresidue helper are shared internally
with their independent tests.

The fixed BN-parameter exponentiation evaluates the 62-square, 17-multiply
addition chain from
[gnark-crypto v0.12.1](https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/internal/fptower/e12_pairing.go)
at the inverse of its input. Five initial squares use full cyclotomic values;
the remaining runs have lengths 6, 7, 8, 6, 8, 6, 10 and 6. Within each run,
compressed cyclotomic squaring retains five Fq2 coefficients and reconstructs
the sixth without division, including at identity and zero coefficients. This
is the five-coefficient variant in
[Karabina, Section 5.6](https://eprint.iacr.org/2010/542), rather than the
four-coefficient variant that requires division. Independent tests cover the
full cyclotomic subgroup, which is larger than Gt.

Individual uncompressed cyclotomic squares use the Granger-Scott formula from
[Faster Squaring in the Cyclotomic Subgroup of Sixth Degree Extensions](https://eprint.iacr.org/2009/565).
Homogeneous line formulas follow the
[Arkworks BN implementation](https://github.com/arkworks-rs/algebra/blob/v0.5.0/ec/src/models/bn/g2.rs).

## Optimization sources

The references below identify algorithms and concrete implementation precedents.
The private range proofs, feature guards, batching policy and measured decisions
belong to this implementation. The
[experiment record](pairing-optimization-experiments.md) records which candidates
were kept or discarded; it is not a claim that every research proposal was kept.

| Optimization | Reference and adaptation |
| --- | --- |
| CIOS Montgomery multiplication | [Koç, Acar and Kaliski, Section 5](https://www.microsoft.com/en-us/research/wp-content/uploads/1996/01/j37acmon.pdf). Used by the scalar and radix-2⁵² IFMA kernels. |
| ADX/BMI2 carry chains | [Firedancer `fd_uint256_mul.inc`](https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bigint/fd_uint256_mul.inc). Adapted to Rust register outputs; the assembly retains its Apache-2.0 notice. |
| Modular halving | [Firedancer `fd_bn254_fp_halve`](https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bn254/fd_bn254_field_inl.h#L225). Add q for odd residues before shifting. |
| Dedicated integer squaring | [Handbook of Applied Cryptography, Algorithm 14.16](https://cacr.uwaterloo.ca/hac/about/chap14.pdf). Ten distinct limb products, with a local column accumulator. |
| Miller line cleanup | [Firedancer pairing loop](https://github.com/firedancer-io/firedancer/blob/20c3fa1ff2dab737ec075c3e3e302ba778fd98fe/src/ballet/bn254/fd_bn254_pairing.c). Apply the factor of three to G1 and omit the final unused point update. |
| Sparse line fusion | [gnark-crypto `Mul034By034` and `MulBy01234`](https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/internal/fptower/e12_pairing.go). Combine two lines before updating the dense accumulator. |
| Batched subgroup-check normalization | [Arkworks' zero-aware Montgomery batch inversion](https://github.com/arkworks-rs/algebra/blob/v0.5.0/ff/src/fields/mod.rs). Locally applied to the fixed-chain 3Q precomputations. |

Initializing the first accumulator by assignment is an algebraic simplification
of multiplication by one. The IFMA lane arrangement and single-pair workspace
shortcut are local scheduling choices, not separate published algorithms.

## Input contract and fixtures

G1 points must be on the curve. G2 points must also belong to the prime-order
subgroup. The existing g2::Affine constructor only checks the curve equation;
a pairing entry point must enforce subgroup membership separately.

The compatibility fixtures use the current syscall's 192-byte pair layout.
The core pairing API does not expose syscall version dispatch.

- G1 LE: x, y; G1 BE: the same coordinates with bytes reversed per coordinate.
- G2 LE: x.c0, x.c1, y.c0, y.c1.
- G2 BE: x.c1, x.c0, y.c1, y.c0, with big-endian coefficients.
- An empty product is one.
- Decode and validate every pair, including pairs with an identity point.
- Preserve existing coordinate canonicality and flag handling.
- Invalid trailing input must not be hidden by an identity or cancelling prefix.

[tests/fixtures/pairing.rs](../tests/fixtures/pairing.rs) constructs 39
deterministic cases in both byte orders. These cover generator and cancelling
products, identities, repeated points, batch boundaries, noncanonical and
off-curve coordinates, flags, cofactor torsion, and invalid lengths.
The core tests exercise decoding/subgroup requirements and run all fixtures
through the new pairing-product API in both byte orders.
A local runner also checks their results against the unchanged
solana-bn254-syscall wrapper: V1 returns a 32-byte Boolean, V0 is rejected,
and lengths not divisible by 192 are rejected.

[tests/pairing.rs](../tests/pairing.rs) also compares exact pairing outputs
with Arkworks, checks bilinearity and non-degeneracy, compares multi-pairing
with products of singles through 65 pairs, and tests cancellation and invalid
inputs around batch boundaries. Raw Miller outputs are not required to agree
across different line or denominator normalizations.

No production syscall integration or comparison-harness dependency is added
by this implementation.
