import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import {
  createMlDsa44Signer,
  createMlDsa44Verifier,
  createMlDsa65Signer,
  createMlDsa65Verifier,
  createMlDsa87Signer,
  createMlDsa87Verifier,
} from "../mod.ts";

const msg = new TextEncoder().encode("hello world");

const targets = [
  {
    name: "ML-DSA-44",
    createSigner: createMlDsa44Signer,
    createVerifier: createMlDsa44Verifier,
    noble: ml_dsa44,
  },
  {
    name: "ML-DSA-65",
    createSigner: createMlDsa65Signer,
    createVerifier: createMlDsa65Verifier,
    noble: ml_dsa65,
  },
  {
    name: "ML-DSA-87",
    createSigner: createMlDsa87Signer,
    createVerifier: createMlDsa87Verifier,
    noble: ml_dsa87,
  },
];

for (const { name, createSigner, createVerifier, noble } of targets) {
  const signer = await createSigner();
  const verifier = await createVerifier();
  const seed = new Uint8Array(32);
  globalThis.crypto.getRandomValues(seed);
  const [pk, sk] = signer.deriveKeyPair(seed);
  const sig = signer.sign(sk, msg);

  Deno.bench(`${name} deriveKeyPair:mldsa`, { group: `${name} keygen` }, () => {
    signer.deriveKeyPair(seed);
  });

  Deno.bench(`${name} keygen:noble`, { group: `${name} keygen` }, () => {
    noble.keygen(seed);
  });

  Deno.bench(`${name} sign:mldsa`, { group: `${name} sign` }, () => {
    signer.sign(sk, msg);
  });

  Deno.bench(`${name} sign:noble`, { group: `${name} sign` }, () => {
    noble.sign(msg, sk);
  });

  Deno.bench(`${name} verify:mldsa`, { group: `${name} verify` }, () => {
    verifier.verify(pk, sig, msg);
  });

  Deno.bench(`${name} verify:noble`, { group: `${name} verify` }, () => {
    noble.verify(sig, msg, pk);
  });
}
