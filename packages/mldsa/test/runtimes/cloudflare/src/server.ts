// The package built by dnt, which dnt.ts copies next to this file.
import {
  createMlDsa44Signer,
  createMlDsa44Verifier,
  createMlDsa65Signer,
  createMlDsa65Verifier,
  createMlDsa87Signer,
  createMlDsa87Verifier,
  type MlDsaSignerInterface,
  type MlDsaVerifierInterface,
} from "./mldsa/mod.js";

function compare(x: Uint8Array, y: Uint8Array): boolean {
  if (x.length != y.length) {
    return false;
  }
  const v = new Uint8Array([0]);
  for (let i = 0; i < x.length; i++) {
    v[0] |= x[i] ^ y[i];
  }
  const z = new Uint8Array([0]);
  z[0] = ~(v[0] ^ z[0]);
  z[0] &= z[0] >> 4;
  z[0] &= z[0] >> 2;
  z[0] &= z[0] >> 1;
  return z[0] === 1 ? true : false;
}

const SUITES = {
  "/mldsa44": [createMlDsa44Signer, createMlDsa44Verifier],
  "/mldsa65": [createMlDsa65Signer, createMlDsa65Verifier],
  "/mldsa87": [createMlDsa87Signer, createMlDsa87Verifier],
} as Record<
  string,
  [
    () => Promise<MlDsaSignerInterface>,
    () => Promise<MlDsaVerifierInterface>,
  ] | undefined
>;

export async function testServer(request: Request): Promise<Response> {
  const url = new URL(request.url);

  const suite = SUITES[url.pathname];
  if (suite === undefined) {
    return new Response("ng: invalid path", { status: 404 });
  }
  const [createSigner, createVerifier] = suite;
  try {
    // generateKeyPair/sign/verify
    const signer = await createSigner();
    const [pk, sk] = signer.generateKeyPair();
    const msg = new TextEncoder().encode("hello world");
    const sig = signer.sign(sk, msg);
    const verifier = await createVerifier();
    if (!verifier.verify(pk, sig, msg)) {
      throw new Error("The signature was rejected.");
    }
    if (verifier.verify(pk, sig, new TextEncoder().encode("hello world!"))) {
      throw new Error("The signature was accepted for another message.");
    }

    // sign/verify with a context string
    const context = new TextEncoder().encode("context");
    const ctxSig = signer.sign(sk, msg, { context });
    if (!verifier.verify(pk, ctxSig, msg, { context })) {
      throw new Error("The signature with a context was rejected.");
    }
    if (verifier.verify(pk, ctxSig, msg)) {
      throw new Error("The signature was accepted without its context.");
    }

    // deriveKeyPair
    const seed = new Uint8Array(32);
    crypto.getRandomValues(seed);
    const [dPk, dSk] = signer.deriveKeyPair(seed);
    const [dPk2, dSk2] = signer.deriveKeyPair(seed);
    if (!compare(dPk, dPk2) || !compare(dSk, dSk2)) {
      throw new Error("The two derived keypairs mismatch.");
    }
  } catch (e: unknown) {
    return new Response("ng: " + (e as Error).message);
  }
  return new Response("ok");
}
