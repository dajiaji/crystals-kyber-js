import * as kyber from "crystals-kyber";
import { ml_kem512 } from "@noble/post-quantum/ml-kem.js";
import { MlKem512 } from "../mod.ts";

Deno.bench("deriveKeyPair", async (b) => {
  const ctx = new MlKem512();
  const seed = new Uint8Array(64);
  globalThis.crypto.getRandomValues(seed);
  b.start();
  const [_pk, _sk] = await ctx.deriveKeyPair(seed);
  b.end();
});

Deno.bench("generateKeyPair", async (b) => {
  const ctx = new MlKem512();
  b.start();
  const [_pk, _sk] = await ctx.generateKeyPair();
  b.end();
});

Deno.bench("crystals-kyber:KeyGen512", () => {
  const [_pk, _sk] = kyber.KeyGen512();
});

Deno.bench("encap", async (b) => {
  const ctx = new MlKem512();
  const [pk, _sk] = await ctx.generateKeyPair();
  b.start();
  const [_ct, _ss] = await ctx.encap(pk);
  b.end();
});

Deno.bench("crystals-kyber:Encrypt512", (b) => {
  const [pk, _sk] = kyber.KeyGen512();
  b.start();
  const [_ct, _ss] = kyber.Encrypt512(pk);
  b.end();
});

Deno.bench("decap", async (b) => {
  const ctx = new MlKem512();
  const [pk, sk] = await ctx.generateKeyPair();
  const [ct, _ss1] = await ctx.encap(pk);
  b.start();
  const _ss2 = await ctx.decap(ct, sk);
  b.end();
});

Deno.bench("crystals-kyber:Decrypt512", (b) => {
  const [pk, sk] = kyber.KeyGen512();
  const [ct, _ss1] = kyber.Encrypt512(pk);
  b.start();
  const _ss2 = kyber.Decrypt512(ct, sk);
  b.end();
});

Deno.bench("all - generateKeyPair/encap/decap", async (b) => {
  const ctx = new MlKem512();
  b.start();
  const [pk, sk] = await ctx.generateKeyPair();
  const [ct, _ss1] = await ctx.encap(pk);
  const _ss2 = await ctx.decap(ct, sk);
  b.end();
});

Deno.bench("crystals-kyber:all", () => {
  const [pk, sk] = kyber.KeyGen512();
  const [ct, _ss1] = kyber.Encrypt512(pk);
  const _ss2 = kyber.Decrypt512(ct, sk);
});

Deno.bench("noble:keygen", () => {
  const _keys = ml_kem512.keygen();
});

Deno.bench("noble:encapsulate", (b) => {
  const keys = ml_kem512.keygen();
  b.start();
  const _enc = ml_kem512.encapsulate(keys.publicKey);
  b.end();
});

Deno.bench("noble:decapsulate", (b) => {
  const keys = ml_kem512.keygen();
  const enc = ml_kem512.encapsulate(keys.publicKey);
  b.start();
  const _ss = ml_kem512.decapsulate(enc.cipherText, keys.secretKey);
  b.end();
});

Deno.bench("noble:all", () => {
  const keys = ml_kem512.keygen();
  const enc = ml_kem512.encapsulate(keys.publicKey);
  const _ss = ml_kem512.decapsulate(enc.cipherText, keys.secretKey);
});
