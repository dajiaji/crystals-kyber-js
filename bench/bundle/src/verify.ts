/**
 * Runtime verification of the generated bundles.
 *
 * For each suite, every keygen bundle derives a key pair from the same seed,
 * and all of them must agree. Then every encap (sign) bundle encapsulates
 * (signs) and every decap (verify) bundle must recover the shared secret
 * (accept the signature), cross-library. This guarantees that the measured
 * bundles are functional and interoperable, not trivially tree-shaken away.
 */

import { pathToFileURL } from "node:url";

import { LIBS } from "./libs.ts";
import type { LibId, Role } from "./libs.ts";
import type { Suite } from "./suites.ts";

export type BundleFiles = Record<LibId, Partial<Record<Role, string>>>;

type KeygenFn = (
  seed: Uint8Array,
) => Promise<{ pk: Uint8Array; sk: Uint8Array }>;
type EncapFn = (pk: Uint8Array) => Promise<{ ct: Uint8Array; ss: Uint8Array }>;
type DecapFn = (ct: Uint8Array, sk: Uint8Array) => Promise<Uint8Array>;
type SignFn = (sk: Uint8Array, msg: Uint8Array) => Promise<Uint8Array>;
type VerifyFn = (
  pk: Uint8Array,
  sig: Uint8Array,
  msg: Uint8Array,
) => Promise<boolean>;

/** Seed sizes of ML-KEM.KeyGen_internal (d || z) and ML-DSA.KeyGen_internal. */
const SEED_SIZE = { kem: 64, dsa: 32 } as const;

async function importBundle<T>(
  files: BundleFiles,
  lib: LibId,
  role: Role,
): Promise<T> {
  const file = files[lib][role];
  if (file === undefined) {
    throw new Error(`no ${role} bundle for ${lib}`);
  }
  const mod = (await import(pathToFileURL(file).href)) as Record<
    string,
    unknown
  >;
  if (typeof mod[role] !== "function") {
    throw new Error(`${file} does not export ${role}()`);
  }
  return mod[role] as T;
}

const equal = (a: Uint8Array, b: Uint8Array): boolean =>
  Buffer.compare(a, b) === 0;

export async function verify(suite: Suite, files: BundleFiles): Promise<void> {
  const seed = crypto.getRandomValues(new Uint8Array(SEED_SIZE[suite.kind]));

  let keys: { pk: Uint8Array; sk: Uint8Array } | undefined;
  for (const lib of LIBS) {
    const keygen = await importBundle<KeygenFn>(files, lib.id, "keygen");
    const derived = await keygen(seed);
    if (keys === undefined) {
      keys = derived;
    } else if (!equal(keys.pk, derived.pk) || !equal(keys.sk, derived.sk)) {
      throw new Error(`${suite.id}: ${lib.id}: key pair mismatch`);
    }
  }
  const { pk, sk } = keys!;

  if (suite.kind === "kem") {
    for (const sender of LIBS) {
      const encap = await importBundle<EncapFn>(files, sender.id, "encap");
      const { ct, ss } = await encap(pk);
      for (const recipient of LIBS) {
        const decap = await importBundle<DecapFn>(
          files,
          recipient.id,
          "decap",
        );
        if (!equal(await decap(ct, sk), ss)) {
          throw new Error(
            `${suite.id}: ${sender.id} -> ${recipient.id}: shared secret mismatch`,
          );
        }
      }
    }
    return;
  }

  const msg = new TextEncoder().encode("hello bundle size bench");
  const other = new TextEncoder().encode("hello bundle size bench?");
  for (const signer of LIBS) {
    const sign = await importBundle<SignFn>(files, signer.id, "sign");
    const sig = await sign(sk, msg);
    for (const verifier of LIBS) {
      const verifySig = await importBundle<VerifyFn>(
        files,
        verifier.id,
        "verify",
      );
      const label = `${suite.id}: ${signer.id} -> ${verifier.id}`;
      if (await verifySig(pk, sig, msg) !== true) {
        throw new Error(`${label}: signature rejected`);
      }
      if (await verifySig(pk, sig, other) !== false) {
        throw new Error(`${label}: signature accepted for another message`);
      }
    }
  }
}
