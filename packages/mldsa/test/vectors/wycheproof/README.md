Vectors from: https://github.com/C2SP/wycheproof/tree/main/testvectors_v1

These are the ML-DSA test vectors of Project Wycheproof, which was started by
Google and is now maintained by the C2SP community. The files are unmodified
copies at the commit `65ca494727a52944c204441c860b039e6786b99b`:

| File                            | Meaning                                         |
| ------------------------------- | ----------------------------------------------- |
| `mldsa_*_sign_seed_test.json`   | Signing with a private key given as a seed      |
| `mldsa_*_sign_noseed_test.json` | Signing with a private key in the expanded form |
| `mldsa_*_verify_test.json`      | Verification                                    |

See [doc/mldsa.md](https://github.com/C2SP/wycheproof/blob/main/doc/mldsa.md) of
Wycheproof for the details of the format.

The vectors are distributed under the Apache License 2.0. [LICENSE](./LICENSE)
is the copy of the license at the same commit.
