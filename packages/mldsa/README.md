<h1 align="center">mldsa</h1>

<div align="center">
<a href="https://jsr.io/@webpqc/mldsa"><img src="https://jsr.io/badges/@webpqc/mldsa" alt="JSR"/></a>
<img src="https://github.com/dajiaji/crystals-kyber-js/actions/workflows/ci_node.yml/badge.svg" alt="Node.js CI" />
<img src="https://github.com/dajiaji/crystals-kyber-js/actions/workflows/ci_deno.yml/badge.svg" alt="Deno CI" />
</div>

<div align="center">
An ML-DSA (NIST FIPS 204) implementation written in TypeScript.<br>
</div>
<p></p>

- ✅ ML-DSA ([NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final))
  support: ML-DSA-44, ML-DSA-65 and ML-DSA-87.
- ✅ Written in TypeScript.
- ✅ Hedged and deterministic signing, with a context string.
- ✅ Deterministic key generation support.
- ✅ No dependencies on other libraries.
- ✅ Tree-shaking friendly.
- ✅ The same API style as [`@webpqc/mlkem`](../mlkem/).
- ✅ Passed all the tests for the pure ML-DSA published by:
  - [usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files)
    (the ACVP test vectors by NIST)
  - [C2SP/wycheproof](https://github.com/C2SP/wycheproof/tree/main/testvectors_v1)
    (Project Wycheproof, started by Google)

> [!WARNING]
> This package is at an early stage. The API may change, and the implementation
> has not been audited.

> [!NOTE]
> In the future, this package aims to use the native ML-DSA defined by
> [Modern Algorithms in the Web Cryptography API](https://wicg.github.io/webcrypto-modern-algos/)
> when available, and fall back to the TypeScript implementation otherwise.

## Usage

```ts
import { createMlDsa65 } from "@webpqc/mldsa";

// Create a pre-initialized instance.
// createMlDsa44 and createMlDsa87 are also available.
const signer = await createMlDsa65();

// A signer generates a key pair.
const [pk, sk] = signer.generateKeyPair();
//// Deterministic key generation is also supported
// const seed = new Uint8Array(32);
// globalThis.crypto.getRandomValues(seed);
// const [pk, sk] = signer.deriveKeyPair(seed);

// The signer signs a message with sk.
const msg = new TextEncoder().encode("hello world");
const sig = signer.sign(sk, msg);

// A verifier verifies the signature with pk.
const verifier = await createMlDsa65();
const ok = verifier.verify(pk, sig, msg);
// ok === true
```

### Context string

A signature can be bound to a context string of at most 255 octets. The verifier
has to pass the same one.

```ts
import { createMlDsa65 } from "@webpqc/mldsa";

const ctx = await createMlDsa65();
const [pk, sk] = ctx.generateKeyPair();
const msg = new TextEncoder().encode("hello world");
const context = new TextEncoder().encode("my protocol v1");

const sig = ctx.sign(sk, msg, { context });
const ok = ctx.verify(pk, sig, msg, { context });
// ok === true
```

### Deterministic signing

`sign` is hedged by default: it mixes fresh randomness into each signature, as
FIPS 204 recommends. Passing a 32-octet `seed` (`rnd` in FIPS 204) makes it
reproducible, and 32 zero octets give the deterministic variant of FIPS 204.

```ts
import { createMlDsa65 } from "@webpqc/mldsa";

const ctx = await createMlDsa65();
const [_pk, sk] = ctx.generateKeyPair();
const msg = new TextEncoder().encode("hello world");

const sig = ctx.sign(sk, msg, { seed: new Uint8Array(32) });
```

## API

`createMlDsa44()`, `createMlDsa65()` and `createMlDsa87()` return a promise of
an `MlDsaInterface`, whose operations are synchronous:

| Method                        | Description                                                        |
| ----------------------------- | ------------------------------------------------------------------ |
| `generateKeyPair()`           | Generates a key pair `[publicKey, privateKey]`.                    |
| `deriveKeyPair(seed)`         | Derives a key pair `[publicKey, privateKey]` from a 32-octet seed. |
| `sign(sk, msg, opts?)`        | Signs a message and returns the signature.                         |
| `verify(pk, sig, msg, opts?)` | Verifies a signature and returns `true` if it is valid.            |

The private key is in the expanded form of FIPS 204 (`skEncode`).

`verify` returns `false` for an invalid signature, and also for a signature or a
public key of an incorrect length (FIPS 204, Section 3.6.2). The methods throw
`MlDsaError` for any other invalid argument: one which is not a `Uint8Array`, a
private key of an incorrect length or with out-of-range values, a context string
longer than 255 octets, or a seed of an incorrect length.

| Parameter set | Public key | Private key | Signature |
| ------------- | ---------- | ----------- | --------- |
| ML-DSA-44     | 1312       | 2560        | 2420      |
| ML-DSA-65     | 1952       | 4032        | 3309      |
| ML-DSA-87     | 2592       | 4896        | 4627      |

## Limitations

- HashML-DSA (the pre-hash variant of FIPS 204) is not supported.
- The external mu interface is not exposed.

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs.
