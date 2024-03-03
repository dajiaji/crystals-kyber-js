import * as kyber from "npm:crystals-kyber";
import { MlKem1024 } from "../mod.ts";

Deno.bench("deriveKeyPair", async (b) => {
  const ctx = new MlKem1024();
  const seed = new Uint8Array(64);
  globalThis.crypto.getRandomValues(seed);
  b.start();
  const [_pk, _sk] = await ctx.deriveKeyPair(seed);
  b.end();
});

Deno.bench("generateKeyPair", async (b) => {
  const ctx = new MlKem1024();
  b.start();
  const [_pk, _sk] = await ctx.generateKeyPair();
  b.end();
});

Deno.bench("crystals-kyber:KeyGen1024", () => {
  const [_pk, _sk] = kyber.KeyGen1024();
});

Deno.bench("encap", async (b) => {
  const ctx = new MlKem1024();
  const [pk, _sk] = await ctx.generateKeyPair();
  b.start();
  const [_ct, _ss] = await ctx.encap(pk);
  b.end();
});

Deno.bench("crystals-kyber:Encrypt1024", (b) => {
  const [pk, _sk] = kyber.KeyGen1024();
  b.start();
  const [_ct, _ss] = kyber.Encrypt1024(pk);
  b.end();
});

Deno.bench("decap", async (b) => {
  const ctx = new MlKem1024();
  const [pk, sk] = await ctx.generateKeyPair();
  const [ct, _ss1] = await ctx.encap(pk);
  b.start();
  const _ss2 = await ctx.decap(ct, sk);
  b.end();
});

Deno.bench("crystals-kyber:Decrypt1024", (b) => {
  const [pk, sk] = kyber.KeyGen1024();
  const [ct, _ss1] = kyber.Encrypt1024(pk);
  b.start();
  const _ss2 = kyber.Decrypt1024(ct, sk);
  b.end();
});

Deno.bench("all - generateKeyPair/encap/decap", async (b) => {
  const ctx = new MlKem1024();
  b.start();
  const [pk, sk] = await ctx.generateKeyPair();
  const [ct, _ss1] = await ctx.encap(pk);
  const _ss2 = await ctx.decap(ct, sk);
  b.end();
});

Deno.bench("crystals-kyber:all", () => {
  const [pk, sk] = kyber.KeyGen1024();
  const [ct, _ss1] = kyber.Encrypt1024(pk);
  const _ss2 = kyber.Decrypt1024(ct, sk);
});
