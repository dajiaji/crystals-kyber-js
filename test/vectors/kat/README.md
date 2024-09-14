Vectors from: https://github.com/post-quantum-cryptography/KAT/blob/main/MLKEM

<hr>

## KAT for FIPS-203 (draft)

Compliant with FIPS-203 draft, published on August 24, 2023. Those vectors
include
[comments](https://csrc.nist.gov/Projects/post-quantum-cryptography/post-quantum-cryptography-standardization/example-files)
published by NIST on October 31, 2023.

## File format:

| Field   | Meaning                                              |
| ------- | ---------------------------------------------------- |
| `count` | Test number                                          |
| `z`     | Random 32-bytes `z` (Algorithm 15)                   |
| `d`     | Random 32-bytes `d` (Algorithm 12)                   |
| `msg`   | Random 32-bytes `m` (Algorithm 16)                   |
| `seed`  | AES-CTR-drbg seed                                    |
| `pk`    | Resulting public key                                 |
| `sk`    | Resulting secret key                                 |
| `ct`    | Resulting KEM ciphertext                             |
| `ss`    | Resulting KEM shared secret                          |
| `ct_n`  | Invalid KEM ciphertext                               |
| `ss_n`  | Shared secret resulting from decapsulation of `ct_n` |

## Differences with the FIPS-203

- No tests for key validation
- The order of the input i and j to the XOF at step 6 in Algorithm 12
  K-PKE.KeyGen() is switched.
- The order of the input i and j to the XOF at step 6 in Algorithm 13
  K-PKE.Encrypt() is switched.

## How it was generated

We use DRBG based on based on AES-CTR (see
[SP800-90A](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf))
for generating random bytes. For each KAT vector, the DRBG is seeded with the
`seed` value (personalisation string is not used). The test first generates a
secret and public key. Then it encapsulates and decapsulates the shared secret.

The pseudocode below may make it clearer

```
use aes_ctr_drbg::DrbgCtx; // aes_ctr_drbg = "0.0.2" crate

fn main() {
    // Initialize DRBG with the magic value
    let Ok(mut entropy) = hex::decode("60496cd0a12512800a79161189b055ac3996ad24e578d3c5fc57c1e60fa2eb4e550d08e51e9db7b67f1a616681d9182d") else {
        ... blah ...
    }
    let mut drbg: DrbgCtx = DrbgCtx::new();
    drbg.init(&entropy, Vec::new());
    for i in 0..100 {
        drbg.get_random(&mut entropy);
        kem::kem(i, &entropy);
    }
}

pub fn kem(count: usize, entropy: &[u8]) {
    let mut buf = Vec::new();
    let mut drbg: DrbgCtx = DrbgCtx::new();
    drbg.init(&entropy.clone(), Vec::new());

    println!("count = {}", count);

    // The code generates random strings in the following order: z,d,msg

    // z
    buf.resize(32, 0);
    drbg.get_random(&mut buf);
    println!("z = {}", hex::encode(&buf));

    // d
    drbg.get_random(&mut buf);
    println!("d = {}", hex::encode(&buf));

    // msg
    drbg.get_random(&mut buf);
    println!("msg = {}", hex::encode(&buf));

    // Re-init
    drbg.init(&entropy.clone(), Vec::new());

    // Generate keys
    kyber_keygen(&mut pk, &mut sk);

    // Encapsulate
    kyber_encaps(&pk, &mut ct, &mut ss);

    // Decapsulate
    kyber_decaps(&sk, &ct, &mut ss);

    println!("seed = {}", hex::encode(&entropy));
    println!("pk = {}", hex::encode(&pk));
    println!("sk = {}", hex::encode(&sk));
    println!("ct = {}", hex::encode(&ct));
    println!("ss = {}", hex::encode(&ss1));
```
