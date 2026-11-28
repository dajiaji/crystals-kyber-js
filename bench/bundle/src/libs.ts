/**
 * Libraries under comparison, and the "typical application" entry point
 * source generated for each of them.
 *
 * Each application does one operation with one parameter set, and exports it
 * as an async function named after the role:
 *
 * - keygen: derive a key pair from a seed
 * - encap:  encapsulate to a public key          (ML-KEM)
 * - decap:  decapsulate with a private key       (ML-KEM)
 * - sign:   sign a message with a private key    (ML-DSA)
 * - verify: verify a signature with a public key (ML-DSA)
 */

import { ROLES } from "./suites.ts";
import type { Role, Suite } from "./suites.ts";

export { ROLES };
export type { Role };

export type LibId = "@webpqc" | "@noble/post-quantum";

export interface Lib {
  readonly id: LibId;
  /** Generates the ESM source of the application entry point. */
  entry(suite: Suite, role: Role): string;
  /** Packages the application depends on for the suite. */
  packages(suite: Suite): string[];
}

const webpqc: Lib = {
  id: "@webpqc",
  packages: (suite) => [suite.webpqc("keygen")[0]],
  entry(suite, role) {
    const [pkg, create] = suite.webpqc(role);
    const body: Record<Role, string> = {
      keygen: `export async function keygen(seed) {
  const ctx = await ${create}();
  const [pk, sk] = ctx.deriveKeyPair(seed);
  return { pk, sk };
}`,
      encap: `export async function encap(pk) {
  const ctx = await ${create}();
  const [ct, ss] = ctx.encap(pk);
  return { ct, ss };
}`,
      decap: `export async function decap(ct, sk) {
  const ctx = await ${create}();
  return ctx.decap(ct, sk);
}`,
      sign: `export async function sign(sk, msg) {
  const ctx = await ${create}();
  return ctx.sign(sk, msg);
}`,
      verify: `export async function verify(pk, sig, msg) {
  const ctx = await ${create}();
  return ctx.verify(pk, sig, msg);
}`,
    };
    return `import { ${create} } from "${pkg}";
${body[role]}
`;
  },
};

const noble: Lib = {
  id: "@noble/post-quantum",
  // The dependencies (@noble/hashes, @noble/curves) come along with it.
  packages: () => ["@noble/post-quantum"],
  entry(suite, role) {
    const [pkg, alg] = suite.noble;
    // Async, as the applications of the other side are.
    const body: Record<Role, string> = {
      keygen: `export async function keygen(seed) {
  const { publicKey, secretKey } = ${alg}.keygen(seed);
  return { pk: publicKey, sk: secretKey };
}`,
      encap: `export async function encap(pk) {
  const { cipherText, sharedSecret } = ${alg}.encapsulate(pk);
  return { ct: cipherText, ss: sharedSecret };
}`,
      decap: `export async function decap(ct, sk) {
  return ${alg}.decapsulate(ct, sk);
}`,
      sign: `export async function sign(sk, msg) {
  return ${alg}.sign(msg, sk);
}`,
      verify: `export async function verify(pk, sig, msg) {
  return ${alg}.verify(sig, msg, pk);
}`,
    };
    return `import { ${alg} } from "${pkg}";
${body[role]}
`;
  },
};

export const LIBS: readonly Lib[] = [webpqc, noble];
