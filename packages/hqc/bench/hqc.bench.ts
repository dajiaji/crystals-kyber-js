import { createHqc1, createHqc3, createHqc5 } from "../mod.ts";

for (
  const [name, create] of [
    ["HQC-1", createHqc1],
    ["HQC-3", createHqc3],
    ["HQC-5", createHqc5],
  ] as const
) {
  Deno.bench(`deriveKeyPair:${name}`, { group: name }, async (b) => {
    const ctx = await create();
    const seed = new Uint8Array(32);
    globalThis.crypto.getRandomValues(seed);
    b.start();
    const [_pk, _sk] = ctx.deriveKeyPair(seed);
    b.end();
  });

  Deno.bench(`keygen:${name}`, { group: name }, async (b) => {
    const ctx = await create();
    b.start();
    const [_pk, _sk] = ctx.generateKeyPair();
    b.end();
  });

  Deno.bench(`encap:${name}`, { group: name }, async (b) => {
    const ctx = await create();
    const [pk, _sk] = ctx.generateKeyPair();
    b.start();
    const [_ct, _ss] = ctx.encap(pk);
    b.end();
  });

  Deno.bench(`decap:${name}`, { group: name }, async (b) => {
    const ctx = await create();
    const [pk, sk] = ctx.generateKeyPair();
    const [ct, _ss1] = ctx.encap(pk);
    b.start();
    const _ss2 = ctx.decap(ct, sk);
    b.end();
  });

  Deno.bench(`all (keygen/encap/decap):${name}`, { group: name }, async (b) => {
    const ctx = await create();
    b.start();
    const [pk, sk] = ctx.generateKeyPair();
    const [ct, _ss1] = ctx.encap(pk);
    const _ss2 = ctx.decap(ct, sk);
    b.end();
  });
}
