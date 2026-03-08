import * as kyber from "crystals-kyber";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import mlkem from "mlkem-wasm";
import { MlKem768 } from "../mod.ts";

Deno.bench("deriveKeyPair:mlkem", async (b) => {
  const ctx = new MlKem768();
  const seed = new Uint8Array(64);
  globalThis.crypto.getRandomValues(seed);
  b.start();
  const [_pk, _sk] = await ctx.deriveKeyPair(seed);
  b.end();
});

Deno.bench("keygen:mlkem", async (b) => {
  const ctx = new MlKem768();
  b.start();
  const [_pk, _sk] = await ctx.generateKeyPair();
  b.end();
});

Deno.bench("keygen:crystals-kyber", () => {
  const [_pk, _sk] = kyber.KeyGen768();
});

Deno.bench("keygen:noble", () => {
  const _keys = ml_kem768.keygen();
});

Deno.bench("keygen:mlkem-wasm", async () => {
  const _keys = await mlkem.generateKey("ML-KEM-768", true, [
    "encapsulateBits",
    "decapsulateBits",
  ]);
});

Deno.bench("encap:mlkem", async (b) => {
  const ctx = new MlKem768();
  const [pk, _sk] = await ctx.generateKeyPair();
  b.start();
  const [_ct, _ss] = await ctx.encap(pk);
  b.end();
});

Deno.bench("encap:crystals-kyber", (b) => {
  const [pk, _sk] = kyber.KeyGen768();
  b.start();
  const [_ct, _ss] = kyber.Encrypt768(pk);
  b.end();
});

Deno.bench("encap:noble", (b) => {
  const keys = ml_kem768.keygen();
  b.start();
  const _enc = ml_kem768.encapsulate(keys.publicKey);
  b.end();
});

Deno.bench("encap:mlkem-wasm", async (b) => {
  const keys = await mlkem.generateKey("ML-KEM-768", true, [
    "encapsulateBits",
    "decapsulateBits",
  ]);
  b.start();
  const _enc = await mlkem.encapsulateBits("ML-KEM-768", keys.publicKey);
  b.end();
});

Deno.bench("decap:mlkem", async (b) => {
  const ctx = new MlKem768();
  const [pk, sk] = await ctx.generateKeyPair();
  const [ct, _ss1] = await ctx.encap(pk);
  b.start();
  const _ss2 = await ctx.decap(ct, sk);
  b.end();
});

Deno.bench("decap:crystals-kyber", (b) => {
  const [pk, sk] = kyber.KeyGen768();
  const [ct, _ss1] = kyber.Encrypt768(pk);
  b.start();
  const _ss2 = kyber.Decrypt768(ct, sk);
  b.end();
});

Deno.bench("decap:noble", (b) => {
  const keys = ml_kem768.keygen();
  const enc = ml_kem768.encapsulate(keys.publicKey);
  b.start();
  const _ss = ml_kem768.decapsulate(enc.cipherText, keys.secretKey);
  b.end();
});

Deno.bench("decap:mlkem-wasm", async (b) => {
  const keys = await mlkem.generateKey("ML-KEM-768", true, [
    "encapsulateBits",
    "decapsulateBits",
  ]);
  const enc = await mlkem.encapsulateBits("ML-KEM-768", keys.publicKey);
  b.start();
  const _ss = await mlkem.decapsulateBits(
    "ML-KEM-768",
    keys.privateKey,
    enc.ciphertext,
  );
  b.end();
});

Deno.bench("all (keygen/encap/decap):mlkem", async (b) => {
  const ctx = new MlKem768();
  b.start();
  const [pk, sk] = await ctx.generateKeyPair();
  const [ct, _ss1] = await ctx.encap(pk);
  const _ss2 = await ctx.decap(ct, sk);
  b.end();
});

Deno.bench("all:crystals-kyber", () => {
  const [pk, sk] = kyber.KeyGen768();
  const [ct, _ss1] = kyber.Encrypt768(pk);
  const _ss2 = kyber.Decrypt768(ct, sk);
});

Deno.bench("all:mlkem-wasm", async () => {
  const keys = await mlkem.generateKey("ML-KEM-768", true, [
    "encapsulateBits",
    "decapsulateBits",
  ]);
  const enc = await mlkem.encapsulateBits("ML-KEM-768", keys.publicKey);
  const _ss = await mlkem.decapsulateBits(
    "ML-KEM-768",
    keys.privateKey,
    enc.ciphertext,
  );
});

Deno.bench("all:noble", () => {
  const keys = ml_kem768.keygen();
  const enc = ml_kem768.encapsulate(keys.publicKey);
  const _ss = ml_kem768.decapsulate(enc.cipherText, keys.secretKey);
});
