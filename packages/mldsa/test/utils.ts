import type { MlDsaInterface } from "../mod.ts";
import { MlDsa44Impl } from "../src/mlDsa44.ts";
import { MlDsa65Impl } from "../src/mlDsa65.ts";
import { MlDsa87Impl } from "../src/mlDsa87.ts";

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
 * ML-DSA with the internal interfaces of FIPS 204 exposed, which the test
 * vectors for ML-DSA.Sign_internal / ML-DSA.Verify_internal need.
 */
export interface TestableMlDsa extends MlDsaInterface {
  /** ML-DSA.Sign_internal for a formatted message M'. */
  signInternal(sk: Uint8Array, mPrime: Uint8Array, rnd: Uint8Array): Uint8Array;
  /** ML-DSA.Verify_internal for a formatted message M'. */
  verifyInternal(pk: Uint8Array, sig: Uint8Array, mPrime: Uint8Array): boolean;
  /** ML-DSA.Sign_internal with an externally computed mu. */
  signMu(sk: Uint8Array, mu: Uint8Array, rnd: Uint8Array): Uint8Array;
  /** ML-DSA.Verify_internal with an externally computed mu. */
  verifyMu(pk: Uint8Array, sig: Uint8Array, mu: Uint8Array): boolean;
}

class TestableMlDsa44 extends MlDsa44Impl implements TestableMlDsa {
  signInternal(sk: Uint8Array, mPrime: Uint8Array, rnd: Uint8Array) {
    return this._signInternal(sk, mPrime, rnd);
  }
  verifyInternal(pk: Uint8Array, sig: Uint8Array, mPrime: Uint8Array) {
    return this._verifyInternal(pk, sig, mPrime);
  }
  signMu(sk: Uint8Array, mu: Uint8Array, rnd: Uint8Array) {
    return this._signMu(sk, mu, rnd);
  }
  verifyMu(pk: Uint8Array, sig: Uint8Array, mu: Uint8Array) {
    return this._verifyMu(pk, mu, sig);
  }
  async setup(): Promise<this> {
    await this._setup();
    return this;
  }
}

class TestableMlDsa65 extends MlDsa65Impl implements TestableMlDsa {
  signInternal(sk: Uint8Array, mPrime: Uint8Array, rnd: Uint8Array) {
    return this._signInternal(sk, mPrime, rnd);
  }
  verifyInternal(pk: Uint8Array, sig: Uint8Array, mPrime: Uint8Array) {
    return this._verifyInternal(pk, sig, mPrime);
  }
  signMu(sk: Uint8Array, mu: Uint8Array, rnd: Uint8Array) {
    return this._signMu(sk, mu, rnd);
  }
  verifyMu(pk: Uint8Array, sig: Uint8Array, mu: Uint8Array) {
    return this._verifyMu(pk, mu, sig);
  }
  async setup(): Promise<this> {
    await this._setup();
    return this;
  }
}

class TestableMlDsa87 extends MlDsa87Impl implements TestableMlDsa {
  signInternal(sk: Uint8Array, mPrime: Uint8Array, rnd: Uint8Array) {
    return this._signInternal(sk, mPrime, rnd);
  }
  verifyInternal(pk: Uint8Array, sig: Uint8Array, mPrime: Uint8Array) {
    return this._verifyInternal(pk, sig, mPrime);
  }
  signMu(sk: Uint8Array, mu: Uint8Array, rnd: Uint8Array) {
    return this._signMu(sk, mu, rnd);
  }
  verifyMu(pk: Uint8Array, sig: Uint8Array, mu: Uint8Array) {
    return this._verifyMu(pk, mu, sig);
  }
  async setup(): Promise<this> {
    await this._setup();
    return this;
  }
}

/** The parameter sets, by the name the test vectors use. */
export const PARAMETER_SETS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] as const;

export type ParameterSet = typeof PARAMETER_SETS[number];

export function createTestableMlDsa(name: string): Promise<TestableMlDsa> {
  switch (name) {
    case "ML-DSA-44":
      return new TestableMlDsa44().setup();
    case "ML-DSA-65":
      return new TestableMlDsa65().setup();
    case "ML-DSA-87":
      return new TestableMlDsa87().setup();
    default:
      throw new Error(`unknown parameter set: ${name}`);
  }
}
