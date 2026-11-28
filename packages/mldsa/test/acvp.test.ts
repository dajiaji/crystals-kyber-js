import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import {
  createTestableMlDsa,
  hexToBytes,
  type TestableMlDsa,
  testVectorPath,
} from "./utils.ts";

// The vectors published by NIST for the Automated Cryptographic Validation
// Protocol (ACVP). See ./vectors/acvp/README.md.

interface KeyGenTest {
  tcId: number;
  seed: string;
  pk: string;
  sk: string;
}

interface SigGenTest {
  tcId: number;
  message?: string;
  mu?: string;
  context?: string;
  rnd?: string;
  pk: string;
  sk: string;
  signature: string;
}

interface SigVerTest {
  tcId: number;
  testPassed: boolean;
  message?: string;
  mu?: string;
  context?: string;
  pk: string;
  signature: string;
  reason: string;
}

interface TestGroup<T> {
  tgId: number;
  parameterSet: string;
  deterministic?: boolean;
  signatureInterface?: "external" | "internal";
  preHash?: "pure" | "preHash" | "none";
  externalMu?: boolean;
  tests: T[];
}

async function loadGroups<T>(name: string): Promise<TestGroup<T>[]> {
  const data = await Deno.readTextFile(
    `${testVectorPath()}/acvp/${name}.json`,
  );
  return JSON.parse(data).testGroups;
}

const instances = new Map<string, Promise<TestableMlDsa>>();

function getInstance(parameterSet: string): Promise<TestableMlDsa> {
  let instance = instances.get(parameterSet);
  if (instance === undefined) {
    instance = createTestableMlDsa(parameterSet);
    instances.set(parameterSet, instance);
  }
  return instance;
}

describe("ACVP", () => {
  describe("ML-DSA-keyGen-FIPS204", () => {
    it("should derive the expected key pairs", async () => {
      const groups = await loadGroups<KeyGenTest>("ML-DSA-keyGen-FIPS204");
      let count = 0;
      for (const group of groups) {
        const ctx = await getInstance(group.parameterSet);
        for (const t of group.tests) {
          const [pk, sk] = ctx.deriveKeyPair(hexToBytes(t.seed));
          assertEquals(pk, hexToBytes(t.pk), `tcId ${t.tcId}: pk`);
          assertEquals(sk, hexToBytes(t.sk), `tcId ${t.tcId}: sk`);
          count++;
        }
      }
      console.log(`ACVP keyGen test vector count: ${count}`);
      assertEquals(count, 75);
    });
  });

  describe("ML-DSA-sigGen-FIPS204", () => {
    it("should generate the expected signatures", async () => {
      const groups = await loadGroups<SigGenTest>("ML-DSA-sigGen-FIPS204");
      let count = 0;
      let skipped = 0;
      for (const group of groups) {
        // HashML-DSA is not supported.
        if (group.preHash === "preHash") {
          skipped += group.tests.length;
          continue;
        }
        const ctx = await getInstance(group.parameterSet);
        for (const t of group.tests) {
          const label = `tgId ${group.tgId}, tcId ${t.tcId}`;
          const sk = hexToBytes(t.sk);
          const pk = hexToBytes(t.pk);
          const rnd = group.deterministic
            ? new Uint8Array(32)
            : hexToBytes(t.rnd as string);
          const expected = hexToBytes(t.signature);
          if (group.signatureInterface === "external") {
            const msg = hexToBytes(t.message as string);
            const context = hexToBytes(t.context as string);
            const sig = ctx.sign(sk, msg, { context, seed: rnd });
            assertEquals(sig, expected, label);
            assertEquals(ctx.verify(pk, sig, msg, { context }), true, label);
          } else if (group.externalMu) {
            const mu = hexToBytes(t.mu as string);
            const sig = ctx.signMu(sk, mu, rnd);
            assertEquals(sig, expected, label);
            assertEquals(ctx.verifyMu(pk, sig, mu), true, label);
          } else {
            const msg = hexToBytes(t.message as string);
            const sig = ctx.signInternal(sk, msg, rnd);
            assertEquals(sig, expected, label);
            assertEquals(ctx.verifyInternal(pk, sig, msg), true, label);
          }
          count++;
        }
      }
      console.log(
        `ACVP sigGen test vector count: ${count} (${skipped} HashML-DSA vectors skipped)`,
      );
      assertEquals(count, 270);
      assertEquals(skipped, 90);
    });
  });

  describe("ML-DSA-sigVer-FIPS204", () => {
    it("should accept or reject the signatures as expected", async () => {
      const groups = await loadGroups<SigVerTest>("ML-DSA-sigVer-FIPS204");
      let count = 0;
      let skipped = 0;
      let rejected = 0;
      for (const group of groups) {
        // HashML-DSA is not supported.
        if (group.preHash === "preHash") {
          skipped += group.tests.length;
          continue;
        }
        const ctx = await getInstance(group.parameterSet);
        for (const t of group.tests) {
          const label = `tgId ${group.tgId}, tcId ${t.tcId}: ${t.reason}`;
          const pk = hexToBytes(t.pk);
          const sig = hexToBytes(t.signature);
          let actual: boolean;
          if (group.signatureInterface === "external") {
            actual = ctx.verify(pk, sig, hexToBytes(t.message as string), {
              context: hexToBytes(t.context as string),
            });
          } else if (group.externalMu) {
            actual = ctx.verifyMu(pk, sig, hexToBytes(t.mu as string));
          } else {
            actual = ctx.verifyInternal(
              pk,
              sig,
              hexToBytes(t.message as string),
            );
          }
          assertEquals(actual, t.testPassed, label);
          if (!t.testPassed) rejected++;
          count++;
        }
      }
      console.log(
        `ACVP sigVer test vector count: ${count} (${rejected} to be rejected, ${skipped} HashML-DSA vectors skipped)`,
      );
      assertEquals(count, 135);
      assertEquals(skipped, 45);
    });
  });
});
