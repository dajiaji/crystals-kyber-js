<h1 align="center">@webpqc/hqc</h1>

<div align="center">
<a href="https://jsr.io/@webpqc/hqc"><img src="https://jsr.io/badges/@webpqc/hqc" alt="JSR"/></a>
<img src="https://github.com/dajiaji/crystals-kyber-js/actions/workflows/ci_node.yml/badge.svg" alt="Node.js CI" />
<img src="https://github.com/dajiaji/crystals-kyber-js/actions/workflows/ci_deno.yml/badge.svg" alt="Deno CI" />
</div>

<div align="center">
An HQC (Hamming Quasi-Cyclic) implementation written in TypeScript.<br>
</div>
<p></p>

- ✅ HQC ([HQC specifications v5.1](https://pqc-hqc.org/resources.html))
  support: HQC-1, HQC-3 and HQC-5.
- ✅ Written in TypeScript.
- ✅ Deterministic key generation support.
- ✅ Constant-time validation for ciphertext.
- ✅ Follows the countermeasures of the reference implementation against timing
  attacks: the polynomial multiplication does not take advantage of the sparsity
  of the secret vectors, the supports of the fixed weight vectors are not used
  as memory indices, and the decoders run the same sequence of operations for
  any word.
- ✅ No dependencies on other libraries.
- ✅ Tree-shaking friendly.
- ✅ The same API style as [`@webpqc/mlkem`](../mlkem/).
- ✅ Passed all the tests published by the HQC team with the
  [reference implementation v5.1.0](https://gitlab.com/pqc-hqc/hqc):
  - the Known Answer Test values (100 vectors for each parameter set),
  - the examples with intermediate values,
  - the Reed-Solomon test vectors (800 vectors for each parameter set).

> [!WARNING]
> HQC was selected by NIST for standardization in March 2025, but the standard
> (FIPS 207) has not been finalized yet. This package implements the HQC
> specifications v5.1 (2026-11-09) of the HQC team, and its outputs will change
> if the standard differs from them. It is not compatible with the
> implementations of the earlier versions of HQC, such as the one of the fourth
> round of the NIST PQC standardization process.

> [!WARNING]
> This package is at an early stage. The API may change, and the implementation
> has not been audited.

## Usage

```ts
import { createHqc3 } from "@webpqc/hqc";

// Create a pre-initialized instance.
// createHqc1 and createHqc5 are also available.
const recipient = await createHqc3();

// A recipient generates a key pair.
const [pkR, skR] = recipient.generateKeyPair();
//// Deterministic key generation is also supported
// const seed = new Uint8Array(32);
// globalThis.crypto.getRandomValues(seed);
// const [pkR, skR] = recipient.deriveKeyPair(seed);

// A sender generates a ciphertext and a shared secret with pkR.
const sender = await createHqc3();
const [ct, ssS] = sender.encap(pkR);

// The recipient decapsulates the ciphertext and generates the same shared secret with skR.
const ssR = recipient.decap(ct, skR);

// ssS === ssR
```

## API

The factory functions `createHqc1()`, `createHqc3()` and `createHqc5()` return a
promise of an instance of `HqcInterface`, whose operations are synchronous:

| Method                | Description                                                        |
| --------------------- | ------------------------------------------------------------------ |
| `generateKeyPair()`   | Generates a key pair `[publicKey, privateKey]`.                    |
| `deriveKeyPair(seed)` | Derives a key pair `[publicKey, privateKey]` from a 32-octet seed. |
| `encap(pk, seed?)`    | Generates `[ciphertext, sharedSecret]` for a public key.           |
| `decap(ct, sk)`       | Generates the shared secret from a ciphertext and a private key.   |

The sizes are as follows, in octets:

| Parameter set | NIST security category | Public key | Private key | Ciphertext | Shared secret |
| ------------- | ---------------------- | ---------- | ----------- | ---------- | ------------- |
| HQC-1         | 1                      | 2241       | 32          | 4433       | 32            |
| HQC-3         | 3                      | 4514       | 32          | 8978       | 32            |
| HQC-5         | 5                      | 7237       | 32          | 14421      | 32            |

- The private key is in the compressed format, which is the default one of the
  specifications: it is the 32-octet seed which the key pair is derived from
  (`seed_kem`). `deriveKeyPair(seed)` therefore returns the seed as the private
  key, and `decap` recomputes the key pair from it every time.
- The optional `seed` of `encap` is `m || salt`, where `m` is a message of 16
  (HQC-1), 24 (HQC-3) or 32 (HQC-5) octets and `salt` is 16 octets. It makes the
  encapsulation deterministic, and is intended for the tests.
- `decap` returns a pseudorandom shared secret for an invalid ciphertext of the
  correct length (implicit rejection), instead of throwing an error.

The methods throw `HqcError` for an invalid argument: a seed, a key or a
ciphertext of an incorrect length, or a public key of which an unused bit is
set.

See [bench/bundle](../../bench/bundle/) for the bundle sizes.

## Performance

HQC is slower than ML-KEM, and so is this implementation: its cost is dominated
by the multiplications of polynomials of 17669 to 57637 coefficients, which are
done without using the sparsity of the secret operand in order not to leak it.
Run `deno task bench` in this directory to see the benchmark results. They are
around the following on a laptop (AMD Ryzen 9 6900HX, Deno 2.9):

| Parameter set | `generateKeyPair` | `encap` | `decap` |
| ------------- | ----------------- | ------- | ------- |
| HQC-1         | 0.9 ms            | 1.7 ms  | 3.4 ms  |
| HQC-3         | 2.6 ms            | 5.1 ms  | 10 ms   |
| HQC-5         | 4.7 ms            | 9.4 ms  | 18 ms   |

## Limitations

- The expanded format of the private key is not supported.
- JavaScript gives no guarantee about the execution time. The code avoids the
  branches, the table lookups, the divisions and the floating-point operations
  which depend on secret values, but the resistance to side-channel attacks
  cannot be ensured in this language.

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs.
