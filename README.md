<h1 align="center">mlkem / crystals-kyber-js</h1>

<div align="center">
<a href="https://jsr.io/@dajiaji/mlkem"><img src="https://jsr.io/badges/@dajiaji/mlkem" alt="JSR"/></a>
<a href="https://www.npmjs.com/package/mlkem"><img src="https://img.shields.io/npm/v/mlkem?color=%23EE3214" alt="NPM"/></a>
<img src="https://github.com/dajiaji/crystals-kyber-js/actions/workflows/ci_browsers.yml/badge.svg" alt="Browser CI" />
<img src="https://github.com/dajiaji/crystals-kyber-js/actions/workflows/ci_node.yml/badge.svg" alt="Node.js CI" />
<img src="https://github.com/dajiaji/crystals-kyber-js/actions/workflows/ci_deno.yml/badge.svg" alt="Deno CI" />
<img src="https://github.com/dajiaji/crystals-kyber-js/actions/workflows/ci_cloudflare.yml/badge.svg" alt="Cloudflare Workers CI" />
<img src="https://github.com/dajiaji/crystals-kyber-js/actions/workflows/ci_bun.yml/badge.svg" alt="bun CI" />
<a href="https://codecov.io/gh/dajiaji/crystals-kyber-js">
  <img src="https://codecov.io/gh/dajiaji/crystals-kyber-js/branch/main/graph/badge.svg?token=7I7JGKDDJ2" alt="codecov" />
</a>
</div>

<div align="center">
An ML-KEM (NIST FIPS 203) and CRYSTALS-KYBER implementation written in TypeScript.<br>
</div>
<p></p>

<div align="center">

[Documentation for main](https://dajiaji.github.io/crystals-kyber-js/docs/main/)

</div>

This module is based on
[ntontutoveanu/crystals-kyber-javascript](https://github.com/antontutoveanu/crystals-kyber-javascript),
but includes the following improvements:

- ✅ Written in TypeScript.
- ✅ Available on various JavaScript runtimes: Browsers, Node.js, Deno,
  Cloudflare Workers, etc.
- ✅ Deterministic key generation support.
- ✅ Constant-time validation for ciphertext.
- ✅ Better performance: 1.4 to 1.8 times faster than the original
  implementation.
- ✅ Tree-shaking friendly.
- ✅ Fix [KyberSlash](https://kyberslash.cr.yp.to/index.html) vulnerability.
- ✅ ML-KEM ([NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final))
  support.
- ✅ Passed all the tests published by:
  - [post-quantum-cryptography/KAT/MLKEM](https://github.com/post-quantum-cryptography/KAT/tree/main/MLKEM)
  - [C2SP/CCTV/ML-KEM](https://github.com/C2SP/CCTV/tree/main/ML-KEM)
  - [pq-crystals/kyber](https://github.com/C2SP/CCTV/tree/main/ML-KEM) (10000
    consecutive tests)

This repository has the following packages:

| package           | registry                                                                                                                  | description                                                                                                                                                                                                                          |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| crystals-kyber-js | [![npm](https://img.shields.io/npm/v/crystals-kyber-js?color=%23EE3214)](https://www.npmjs.com/package/crystals-kyber-js) | `v1.x` implements CRYSTALS-KYBER, and `v2.x-` implements ML-KEM (NIST FIPS 203). `crystals-kyber-js` may become deprecated in the near future. Instead, we recommend switching to the following `mlkem` or `@dajiaji/mlkem`.         |
| mlkem             | [![npm](https://img.shields.io/npm/v/mlkem?color=%23EE3214)](https://www.npmjs.com/package/mlkem)                         | Implements only ML-KEM (NIST FIPS 203). It is an alias for the above `crystals-kyber-js` starting from `v2` onwards. We recommend using this package going forward.                                                                  |
| @dajiaji/mlkem    | [![JSR](https://jsr.io/badges/@dajiaji/mlkem)](https://jsr.io/@dajiaji/mlkem)                                             | Implements only ML-KEM (NIST FIPS 203). It is an ML-KEM package for [jsr.io](https://jsr.io/). The above `mlkem` is an npm package of `@dajiaji/mlkem`, which has been converted using [@deno/dnt](https://github.com/denoland/dnt). |

For Node.js, you can install `mlkem` or `crystals-kyber-js` via npm, yarn or
pnpm:

```sh
# RECOMMENTED using `mlkem`
npm install mlkem
# `crystals-kyber-js` is still available for use, but it may become deprecated in the near future.
npm install crystals-kyber-js
```

Then, you can use it as follows:

```ts
import { MlKem768 } from "mlkem"; // or from "crystals-kyber-js"

async function doMlKem() {
  // A recipient generates a key pair.
  const recipient = new MlKem768(); // MlKem512 and MlKem1024 are also available.
  const [pkR, skR] = await recipient.generateKeyPair();
  //// Deterministic key generation is also supported
  // const seed = new Uint8Array(64);
  // globalThis.crypto.getRandomValues(seed); // node >= 19
  // const [pkR, skR] = await recipient.deriveKeyPair(seed);

  // A sender generates a ciphertext and a shared secret with pkR.
  const sender = new MlKem768();
  const [ct, ssS] = await sender.encap(pkR);

  // The recipient decapsulates the ciphertext and generates the same shared secret with skR.
  const ssR = await recipient.decap(ct, skR);

  // ssS === ssR
  return;
}

try {
  doMlKem();
} catch (err: unknown) {
  console.log("failed:", (err as Error).message);
}
```

## Index

- [Installation](#installation)
  - [Node.js](#nodejs)
  - [Deno](#deno)
  - [Cloudflare Workers](#cloudflare-workers)
  - [Bun](#bun)
  - [Web Browsers](#web-browsers)
- [Usage](#usage)
- [Contributing](#contributing)

## Installation

### Node.js

```sh
# Using npm:
npm install mlkem  # or crystals-kyber-js
yarn add mlkem  # or crystals-kyber-js
pnpm install mlkem  # or crystals-kyber-js
# Using jsr:
npx jsr add @dajiaji/mlkem
yarn dlx jsr add @dajiaji/mlkem
pnpm dlx jsr add @dajiaji/mlkem
```

### Deno

Starting from version 2.0.0, `@dajiaji/mlkem` is available from the
[jsr.io](https://jsr.io). From this version onwards, please use JSR import
instead of HTTPS import in Deno.

**JSR import (`>=2.0.0`):**

Add `@dajiaji/mlkem` package using the commands below:

```sh
deno add @dajiaji/mlkem
```

Then, you can use the module from code like this:

```ts
import { MlKem1024, MlKem512, MlKem768 } from "@dajiaji/mlkem";
```

**HTTPS import (deprecated):**

```ts
import {
  Kyber1024,
  Kyber512,
  Kyber768,
} from "https://deno.land/x/crystals_kyber@<SEMVER>/mod.ts";
```

### Cloudflare Workers

```sh
# Using npm:
npm install mlkem  # or crystals-kyber-js
yarn add mlkem  # or crystals-kyber-js
pnpm install mlkem  # or crystals-kyber-js
# Using jsr:
npx jsr add @dajiaji/mlkem
yarn dlx jsr add @dajiaji/mlkem
pnpm dlx jsr add @dajiaji/mlkem
```

```ts
import { MlKem1024, MlKem512, MlKem768 } from "@dajiaji/mlkem";
```

### Bun

```sh
# Using npm:
npm install mlkem  # or crystals-kyber-js
yarn add mlkem  # or crystals-kyber-js
pnpm install mlkem  # or crystals-kyber-js
# Using jsr:
bunx jsr add @dajiaji/bhttp
```

```ts
import { MlKem1024, MlKem512, MlKem768 } from "@dajiaji/mlkem";
```

### Web Browsers

Followings are how to use this module with typical CDNs. Other CDNs can be used
as well.

```html
<!-- use a specific version -->
<script type="module">
  // Using esm.sh:
  import {
    MlKem1024,
    MlKem512,
    MlKem768,
  } from "https://esm.sh/mlkem@<SEMVER>";
  // Using unpkg.com:
  // import { MlKem768 } from "https://unpkg.com/mlkem@SEMVER";
  // ...
</script>
```

## Usage

This section shows some typical usage examples.

### Node.js

```js
import { MlKem768 } from "mlkem";
// const { MlKem768 } = require("mlkem");

async function doMlKem() {
  const recipient = new MlKem768();
  const [pkR, skR] = await recipient.generateKeyPair();

  const sender = new MlKem768();
  const [ct, ssS] = await sender.encap(pkR);

  const ssR = await recipient.decap(ct, skR);

  // ssS === ssR
  return;
}

try {
  doMlKem();
} catch (err) {
  console.log("failed: ", err.message);
}
```

### Deno, Cloudflare Workers and Bun

```ts
import { MlKem512 } from "@dajiaji/mlkem";

async function doMlKem() {
  const recipient = new MlKem512();
  const [pkR, skR] = await recipient.generateKeyPair();

  const sender = new MlKem512();
  const [ct, ssS] = await sender.encap(pkR);

  const ssR = await recipient.decap(ct, skR);

  // ssS === ssR
  return;
}

try {
  doMlKem();
} catch (err: unknown) {
  console.log("failed:", (err as Error).message);
}
```

### Browsers

```html
<html>
  <head></head>
  <body>
    <script type="module">
      import { MlKem1024 } from "https://esm.sh/mlkem";

      globalThis.doMlKem = async () => {
        try {
          const recipient = new MlKem1024();
          const [pkR, skR] = await recipient.generateKeyPair();

          const sender = new MlKem1024();
          const [ct, ssS] = await sender.encap(pkR);

          const ssR = await recipient.decap(ct, skR);

          // ssS === ssR
          return;
        } catch (err) {
          alert("failed: ", err.message);
        }
      };
    </script>
    <button type="button" onclick="doMlKem()">do CRYSTALS-KYBER</button>
  </body>
</html>
```

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs.
