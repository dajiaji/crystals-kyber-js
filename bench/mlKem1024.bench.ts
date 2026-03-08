import * as kyber from "crystals-kyber";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { MlKem1024 } from "../mod.ts";

Deno.bench("deriveKeyPair:mlkem", async (b) => {
  const ctx = new MlKem1024();
  const seed = new Uint8Array(64);
  globalThis.crypto.getRandomValues(seed);
  b.start();
  const [_pk, _sk] = await ctx.deriveKeyPair(seed);
  b.end();
});

Deno.bench("keygen:mlkem", async (b) => {
  const ctx = new MlKem1024();
  b.start();
  const [_pk, _sk] = await ctx.generateKeyPair();
  b.end();
});

Deno.bench("keygen:crystals-kyber", () => {
  const [_pk, _sk] = kyber.KeyGen1024();
});

Deno.bench("keygen:noble", () => {
  const _keys = ml_kem1024.keygen();
});

Deno.bench("encap:mlkem", async (b) => {
  const ctx = new MlKem1024();
  const [pk, _sk] = await ctx.generateKeyPair();
  b.start();
  const [_ct, _ss] = await ctx.encap(pk);
  b.end();
});

Deno.bench("encap:crystals-kyber", (b) => {
  const [pk, _sk] = kyber.KeyGen1024();
  b.start();
  const [_ct, _ss] = kyber.Encrypt1024(pk);
  b.end();
});

Deno.bench("encap:noble", (b) => {
  const keys = ml_kem1024.keygen();
  b.start();
  const _enc = ml_kem1024.encapsulate(keys.publicKey);
  b.end();
});

Deno.bench("decap:mlkem", async (b) => {
  const ctx = new MlKem1024();
  const [pk, sk] = await ctx.generateKeyPair();
  const [ct, _ss1] = await ctx.encap(pk);
  b.start();
  const _ss2 = await ctx.decap(ct, sk);
  b.end();
});

Deno.bench("decap:crystals-kyber", (b) => {
  const [pk, sk] = kyber.KeyGen1024();
  const [ct, _ss1] = kyber.Encrypt1024(pk);
  b.start();
  const _ss2 = kyber.Decrypt1024(ct, sk);
  b.end();
});

Deno.bench("decap:noble", (b) => {
  const keys = ml_kem1024.keygen();
  const enc = ml_kem1024.encapsulate(keys.publicKey);
  b.start();
  const _ss = ml_kem1024.decapsulate(enc.cipherText, keys.secretKey);
  b.end();
});

Deno.bench("all (keygen/encap/decap):mlkem", async (b) => {
  const ctx = new MlKem1024();
  b.start();
  const [pk, sk] = await ctx.generateKeyPair();
  const [ct, _ss1] = await ctx.encap(pk);
  const _ss2 = await ctx.decap(ct, sk);
  b.end();
});

Deno.bench("all:crystals-kyber", () => {
  const [pk, sk] = kyber.KeyGen1024();
  const [ct, _ss1] = kyber.Encrypt1024(pk);
  const _ss2 = kyber.Decrypt1024(ct, sk);
});

Deno.bench("all:noble", () => {
  const keys = ml_kem1024.keygen();
  const enc = ml_kem1024.encapsulate(keys.publicKey);
  const _ss = ml_kem1024.decapsulate(enc.cipherText, keys.secretKey);
});
