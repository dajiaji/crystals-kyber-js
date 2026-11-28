import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { createMlDsa44, createMlDsa65, createMlDsa87 } from "../mod.ts";

const msg = new TextEncoder().encode("hello world");

const targets = [
  { name: "ML-DSA-44", create: createMlDsa44, noble: ml_dsa44 },
  { name: "ML-DSA-65", create: createMlDsa65, noble: ml_dsa65 },
  { name: "ML-DSA-87", create: createMlDsa87, noble: ml_dsa87 },
];

for (const { name, create, noble } of targets) {
  const ctx = await create();
  const seed = new Uint8Array(32);
  globalThis.crypto.getRandomValues(seed);
  const [pk, sk] = ctx.deriveKeyPair(seed);
  const sig = ctx.sign(sk, msg);

  Deno.bench(`${name} deriveKeyPair:mldsa`, { group: `${name} keygen` }, () => {
    ctx.deriveKeyPair(seed);
  });

  Deno.bench(`${name} keygen:noble`, { group: `${name} keygen` }, () => {
    noble.keygen(seed);
  });

  Deno.bench(`${name} sign:mldsa`, { group: `${name} sign` }, () => {
    ctx.sign(sk, msg);
  });

  Deno.bench(`${name} sign:noble`, { group: `${name} sign` }, () => {
    noble.sign(msg, sk);
  });

  Deno.bench(`${name} verify:mldsa`, { group: `${name} verify` }, () => {
    ctx.verify(pk, sig, msg);
  });

  Deno.bench(`${name} verify:noble`, { group: `${name} verify` }, () => {
    noble.verify(sig, msg, pk);
  });
}
