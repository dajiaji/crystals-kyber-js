# Test vectors

The test vectors in this directory are the official ones published by the HQC
team with the reference implementation, and are used as they are.

- Repository: https://gitlab.com/pqc-hqc/hqc
- Version: `v5.1.0` (commit `06567ccbad10580d78dd7863b15d23f41076d57f`,
  2026-10-26)
- Specifications: HQC specifications v5.1 (2026-11-09),
  https://pqc-hqc.org/doc/hqc_specifications_v5.1.pdf
- License: the reference implementation is released into the public domain.

| Directory       | Source in the repository              | Used by                     |
| --------------- | ------------------------------------- | --------------------------- |
| `kat/`          | `kats/ref/hqc-*/PQCkemKAT_32.rsp`     | `test/kat.test.ts`          |
| `intermediate/` | `kats/ref/hqc-*/intermediates_values` | `test/intermediate.test.ts` |
| `rs/`           | `kats/rs/hqc-*/rs.tv`                 | `test/reedSolomon.test.ts`  |

The files under `kats/x86_64/avx256/` of the repository, which are generated
with the optimized implementation, are identical to the ones under `kats/ref/`.

## `kat/`: Known Answer Test values

100 vectors for each of HQC-1, HQC-3 and HQC-5, generated with the KAT generator
of NIST (`PQCgenKAT_kem.c`).

| Field   | Meaning                                                   |
| ------- | --------------------------------------------------------- |
| `count` | Test number                                               |
| `seed`  | AES-CTR-DRBG seed                                         |
| `pk`    | Resulting encapsulation key                               |
| `sk`    | Resulting decapsulation key, i.e. the 32-octet `seed_kem` |
| `ct`    | Resulting KEM ciphertext                                  |
| `ss`    | Resulting KEM shared secret                               |

For each vector, the DRBG based on AES-256 in the counter mode (see
[SP800-90A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf))
is seeded with the `seed` value, without a personalization string. Then the
generator draws from it, with one call for each value:

1. `seed_kem` (32 octets) for the key generation,
2. `m` (16, 24 or 32 octets) for the encapsulation,
3. `salt` (16 octets) for the encapsulation.

`test/drng.ts` implements the DRBG.

## `intermediate/`: examples with intermediate values

One key generation, encapsulation and decapsulation for each parameter set, with
the values of every step (the `VERBOSE` mode of the reference implementation).
The DRBG above is seeded with the 48 octets `00 01 ... 2f`.

## `rs/`: Reed-Solomon test vectors

800 samples for each parameter set: 100 for each of 8 scenarios, from a clean
codeword to a fully corrupted one. A sample has a message, its codeword, a
corrupted codeword, and the syndromes, the error locator polynomial, the error
positions and the decoded message which the decoder computes from it.

The key generation, the encapsulation and the decapsulation of valid values
almost never make the Reed-Solomon decoder correct an error, so these vectors
are what tests it.

## How to update

```sh
git clone https://gitlab.com/pqc-hqc/hqc.git
cd hqc && git checkout <tag>
for l in 1 3 5; do
  cp kats/ref/hqc-$l/PQCkemKAT_32.rsp    <here>/kat/hqc-$l/
  cp kats/ref/hqc-$l/intermediates_values <here>/intermediate/hqc-$l/
  cp kats/rs/hqc-$l/rs.tv                <here>/rs/hqc-$l/
done
```
