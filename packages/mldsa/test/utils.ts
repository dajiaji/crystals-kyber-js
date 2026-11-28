import type { MlDsaSignerInterface, MlDsaVerifierInterface } from "../mod.ts";
import { Keccak } from "../src/deps.ts";
import { MlDsaSigner } from "../src/mlDsaSigner.ts";
import { MlDsaVerifier } from "../src/mlDsaVerifier.ts";
import {
  ML_DSA_44,
  ML_DSA_65,
  ML_DSA_87,
  type MlDsaParams,
} from "../src/params.ts";

declare const Deno: undefined;
const isDeno = () => typeof Deno !== "undefined";

export function testVectorPath(): string {
  if (isDeno()) {
    return "./test/vectors";
  }
  return "../../../packages/mldsa/test/vectors";
}

export function hexToBytes(v: string): Uint8Array {
  if (v.length % 2 !== 0 || /[^\da-f]/i.test(v)) {
    throw new Error("Not hex string.");
  }
  const res = new Uint8Array(v.length / 2);
  for (let i = 0; i < res.length; i++) {
    res[i] = parseInt(v.substring(2 * i, 2 * i + 2), 16);
  }
  return res;
}

export function bytesToHex(v: Uint8Array): string {
  return [...v].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/**
 * A signer and a verifier of the same parameter set as one object, for the
 * tests which need both.
 */
export interface MlDsaPair
  extends MlDsaSignerInterface, MlDsaVerifierInterface {
  readonly signer: MlDsaSignerInterface;
  readonly verifier: MlDsaVerifierInterface;
}

function pairOf<
  S extends MlDsaSignerInterface,
  V extends MlDsaVerifierInterface,
>(signer: S, verifier: V): MlDsaPair & { signer: S; verifier: V } {
  return {
    signer,
    verifier,
    generateKeyPair: () => signer.generateKeyPair(),
    deriveKeyPair: (seed) => signer.deriveKeyPair(seed),
    sign: (sk, msg, opts) => signer.sign(sk, msg, opts),
    verify: (pk, sig, msg, opts) => verifier.verify(pk, sig, msg, opts),
  };
}

export async function createPair(
  createSigner: () => Promise<MlDsaSignerInterface>,
  createVerifier: () => Promise<MlDsaVerifierInterface>,
): Promise<MlDsaPair> {
  return pairOf(await createSigner(), await createVerifier());
}

/**
 * ML-DSA with the internal interfaces of FIPS 204 exposed, which the test
 * vectors for ML-DSA.Sign_internal / ML-DSA.Verify_internal need.
 */
export interface TestableMlDsa extends MlDsaPair {
  /** ML-DSA.Sign_internal for a formatted message M'. */
  signInternal(sk: Uint8Array, mPrime: Uint8Array, rnd: Uint8Array): Uint8Array;
  /** ML-DSA.Verify_internal for a formatted message M'. */
  verifyInternal(pk: Uint8Array, sig: Uint8Array, mPrime: Uint8Array): boolean;
  /** ML-DSA.Sign_internal with an externally computed mu. */
  signMu(sk: Uint8Array, mu: Uint8Array, rnd: Uint8Array): Uint8Array;
  /** ML-DSA.Verify_internal with an externally computed mu. */
  verifyMu(pk: Uint8Array, sig: Uint8Array, mu: Uint8Array): boolean;
}

class TestableSigner extends MlDsaSigner {
  signMu(sk: Uint8Array, mu: Uint8Array, rnd: Uint8Array): Uint8Array {
    return this._signMu(sk, mu, rnd);
  }
}

class TestableVerifier extends MlDsaVerifier {
  verifyMu(pk: Uint8Array, sig: Uint8Array, mu: Uint8Array): boolean {
    try {
      return this._verifyMu(pk, mu, sig);
    } finally {
      // _verifyMu leaves the cleanup to its caller, as verify() does it
      this._zeroHashes();
    }
  }
}

// H: SHAKE256 over the concatenation of `inputs`, with a 64-octet output.
function h64(...inputs: Uint8Array[]): Uint8Array {
  const h = new Keccak(136, 0x1f, 64, true);
  for (const input of inputs) h.updateUnsafe(input);
  return h.writeIntoUnsafe(new Uint8Array(64));
}

/** The parameter sets, by the name the test vectors use. */
export const PARAMETER_SETS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] as const;

export type ParameterSet = typeof PARAMETER_SETS[number];

const PARAMS: Record<string, MlDsaParams> = {
  "ML-DSA-44": ML_DSA_44,
  "ML-DSA-65": ML_DSA_65,
  "ML-DSA-87": ML_DSA_87,
};

// deno-lint-ignore require-await
export async function createTestableMlDsa(
  name: string,
): Promise<TestableMlDsa> {
  const params = PARAMS[name];
  if (params === undefined) {
    throw new Error(`unknown parameter set: ${name}`);
  }
  const signer = new TestableSigner(params, globalThis.crypto);
  const verifier = new TestableVerifier(params);
  return {
    ...pairOf(signer, verifier),
    // mu = H(tr || M', 64), where tr = H(pk, 64) is at the offset 64 of sk.
    signInternal: (sk, mPrime, rnd) =>
      signer.signMu(sk, h64(sk.subarray(64, 128), mPrime), rnd),
    verifyInternal: (pk, sig, mPrime) =>
      verifier.verifyMu(pk, sig, h64(h64(pk), mPrime)),
    signMu: (sk, mu, rnd) => signer.signMu(sk, mu, rnd),
    verifyMu: (pk, sig, mu) => verifier.verifyMu(pk, sig, mu),
  };
}
