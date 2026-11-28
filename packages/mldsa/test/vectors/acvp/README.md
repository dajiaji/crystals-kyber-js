Vectors from:
https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files

These are the test vectors published by NIST for the Automated Cryptographic
Validation Protocol (ACVP). The files are unmodified copies of
`internalProjection.json`, which has both the prompts and the expected results,
at the commit `975de31eb83d87039ec88934fdc47d8c312b892d`:

| File                         | Source directory        |
| ---------------------------- | ----------------------- |
| `ML-DSA-keyGen-FIPS204.json` | `ML-DSA-keyGen-FIPS204` |
| `ML-DSA-sigGen-FIPS204.json` | `ML-DSA-sigGen-FIPS204` |
| `ML-DSA-sigVer-FIPS204.json` | `ML-DSA-sigVer-FIPS204` |

The test groups with `"preHash": "preHash"` are for HashML-DSA, which this
package does not implement, so the tests skip them.
