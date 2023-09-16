<h1 align="center">crystals-kyber-js</h1>

<div align="center">

[![deno doc](https://doc.deno.land/badge.svg)](https://doc.deno.land/https/deno.land/x/crystals_kyber/mod.ts)
![Browser CI](https://github.com/dajiaji/crystals-kyber-js/actions/workflows/ci_browsers.yml/badge.svg)
![Node.js CI](https://github.com/dajiaji/crystals-kyber-js/actions/workflows/ci_node.yml/badge.svg)
![Deno CI](https://github.com/dajiaji/crystals-kyber-js/actions/workflows/ci_deno.yml/badge.svg)
![Cloudflare Workers CI](https://github.com/dajiaji/crystals-kyber-js/actions/workflows/ci_cloudflare.yml/badge.svg)
![Bun CI](https://github.com/dajiaji/crystals-kyber-js/actions/workflows/ci_bun.yml/badge.svg)
[![codecov](https://codecov.io/gh/dajiaji/crystals-kyber-js/branch/main/graph/badge.svg?token=7I7JGKDDJ2)](https://codecov.io/gh/dajiaji/crystals-kyber-js)

</div>

<div align="center">
A CRYSTALS-KYBER implementation written in TypeScript for various JavaScript runtimes.<br>
</div>
<p></p>

<div align="center">

[Documentation for main](https://dajiaji.github.io/hpke-js/docs/main/)

</div>

This module is based on
<a href="https://github.com/antontutoveanu/crystals-kyber-javascript">ntontutoveanu/crystals-kyber-javascript</a>,
but includes the following improvements:<br>

- ✅ Available on various JavaScript runtimes: Browsers, Node.js, Deno,
  Cloudflare Workers, etc.<br>
- ✅ Written in TypeScript.<br>
- ✅ Deterministic key generation support.<br>
- ✅ Constant-time validation for ciphertext.<br>
- ✅ Better performance: 1.4 to 1.8 times faster than the original
  implementation.<br>
- ✅ Tree-shaking friendly.<br>

For Node.js, you can install `crystals-kyber-js` via npm/yarn:

```sh
npm install crystals-kyber-js
```

Then, you can use it as follows:

```js
import { Kyber768 } from "crystals-kyber-js";

async function doKyber() {
  // A recipient generates a key pair.
  const recipient = new Kyber768(); // Kyber512 and Kyber1024 are also available.
  const [pkR, skR] = await recipient.generateKeyPair();
  //// Deterministic key generation is also supported
  // const seed = new Uint8Array(64);
  // globalThis.crypto.getRandomValues(seed); // node >= 19
  // const [pkR, skR] = await recipient.deriveKeyPair(seed);

  // A sender generates a ciphertext and a shared secret with pkR.
  const sender = new Kyber768();
  const [ct, ssS] = await sender.encap(pkR);

  // The recipient decapsulates the ciphertext and generates the same shared secret with skR.
  const ssR = await recipient.decap(ct, skR);

  // ssS === ssR
  return;
}

try {
  doKyber();
} catch (err) {
  console.log("failed: ", err.message);
}
```

## Index

- [Installation](#installation)
  - [Node.js](#nodejs)
  - [Deno](#deno)
  - [Web Browsers](#web-browsers)
  - [Cloudflare Workers](#cloudflare-workers)
- [Usage](#usage)
- [Contributing](#contributing)

## Installation

### Node.js

Using npm:

```sh
npm install crystals-kyber-js
```

Using yarn:

```sh
yarn add crystals-kyber-js
```

### Deno

Using deno.land:

```js
// use a specific version
import { Kyber768 } from "https://deno.land/x/crystals_kyber@1.0.0/mod.ts";

// use the latest stable version
import { Kyber768 } from "https://deno.land/x/crystals_kyber/mod.ts";
```

### Web Browsers

Followings are how to use this module with typical CDNs. Other CDNs can be used
as well.

Using esm.sh:

```html
<!-- use a specific version -->
<script type="module">
  import { Kyber768 } from "https://esm.sh/crystals-kyber-js@1.0.0";
  // ...
</script>

<!-- use the latest stable version -->
<script type="module">
  import { Kyber768 } from "https://esm.sh/crystals-kyber-js";
  // ...
</script>
```

Using unpkg:

```html
<!-- use a specific version -->
<script type="module">
  import { Kyber768 } from "https://unpkg.com/crystals-kyber-js@1.0.0";
  // ...
</script>
```

### Cloudflare Workers

```sh
git clone git@github.com:dajiaji/crystals-kyber-js.git
cd crystals-kyber-js
npm install -g esbuild
deno task dnt
deno task minify > $YOUR_SRC_PATH/crystals-kyber.js
```

## Usage

This section shows some typical usage examples.

### Node.js

```js
import { Kyber768 } from "crystals-kyber-js";
// const { Kyber768 } = require("crystals-kyber-js");

async function doKyber() {
  const recipient = new Kyber768();
  const [pkR, skR] = await recipient.generateKeyPair();

  const sender = new Kyber768();
  const [ct, ssS] = await sender.encap(pkR);

  const ssR = await recipient.decap(ct, skR);

  // ssS === ssR
  return;
}

try {
  doKyber();
} catch (err) {
  console.log("failed: ", err.message);
}
```

### Deno

```js
import { Kyber512 } from "https://deno.land/x/crystals_kyber@1.0.0/mod.ts";

async function doKyber() {

  const recipient = new Kyber512();
  const [pkR, skR] = await recipient.generateKeyPair();

  const sender = new Kyber512();
  const [ct, ssS] = await sender.encap(pkR);

  const ssR = await recipient.decap(ct, skR);

  // ssS === ssR
  return;
}

try {
  doKyber();
} catch (_err: unknown) {
  console.log("failed.");
}
```

### Browsers

```html
<html>
  <head></head>
  <body>
    <script type="module">
      import { Kyber1024 } from "https://esm.sh/crystals-kyber@1.0.0";

      globalThis.doKyber = async () => {
        try {
          const recipient = new Kyber1024();
          const [pkR, skR] = await recipient.generateKeyPair();

          const sender = new Kyber1024();
          const [ct, ssS] = await sender.encap(pkR);

          const ssR = await recipient.decap(ct, skR);

          // ssS === ssR
          return;
        } catch (err) {
          alert("failed: ", err.message);
        }
      }
    </script>
    <button type="button" onclick="doKyber()">do CRYSTALS-KYBER</button>
  </body>
</html>
```

## Contributing

We welcome all kind of contributions, filing issues, suggesting new features or
sending PRs.
