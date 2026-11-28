<p align="center">
  <img src="./assets/webpqc-logo.png" alt="webpqc logo" width="200" />
</p>

<h1 align="center">webpqc</h1>

<div align="center">
Post-quantum cryptography implementations written in TypeScript for various JavaScript runtimes.
</div>
<p></p>

This repository is a monorepo that has the following packages:

| package                            | registry                                                                                                                                                                                      | description                                                                                                                                                                                                                          |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [@webpqc/mlkem](./packages/mlkem/) | [![JSR](https://jsr.io/badges/@webpqc/mlkem)](https://jsr.io/@webpqc/mlkem) [![npm](https://img.shields.io/npm/v/@webpqc/mlkem?color=%23EE3214)](https://www.npmjs.com/package/@webpqc/mlkem) | An ML-KEM (NIST FIPS 203) implementation. Published as `@webpqc/mlkem` on JSR, and as `@webpqc/mlkem`, [mlkem](https://www.npmjs.com/package/mlkem) and [crystals-kyber-js](https://www.npmjs.com/package/crystals-kyber-js) on npm. |
| [@webpqc/mldsa](./packages/mldsa/) | [![JSR](https://jsr.io/badges/@webpqc/mldsa)](https://jsr.io/@webpqc/mldsa) [![npm](https://img.shields.io/npm/v/@webpqc/mldsa?color=%23EE3214)](https://www.npmjs.com/package/@webpqc/mldsa) | An ML-DSA (NIST FIPS 204) implementation. Published as `@webpqc/mldsa` on JSR and npm. At an early stage: the API may change.                                                                                                        |
| [@webpqc/hqc](./packages/hqc/)     | [![JSR](https://jsr.io/badges/@webpqc/hqc)](https://jsr.io/@webpqc/hqc) [![npm](https://img.shields.io/npm/v/@webpqc/hqc?color=%23EE3214)](https://www.npmjs.com/package/@webpqc/hqc)         | An HQC (HQC specifications v5.1) implementation. Published as `@webpqc/hqc` on JSR and npm. At an early stage: the API may change.                                                                                                   |

See the README of each package for installation and usage.

## Design Direction

The algorithms are currently implemented in TypeScript. In the future, this
project aims to use the native implementations defined by
[Modern Algorithms in the Web Cryptography API](https://wicg.github.io/webcrypto-modern-algos/)
when available, and fall back to the TypeScript ones otherwise.

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs.
