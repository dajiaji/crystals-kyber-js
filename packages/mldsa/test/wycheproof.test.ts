import { assertEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { MlDsaError } from "../mod.ts";
import {
  createTestableMlDsa,
  hexToBytes,
  PARAMETER_SETS,
  testVectorPath,
} from "./utils.ts";

// The vectors published by Project Wycheproof (C2SP/wycheproof), which
// was started by Google. See ./vectors/wycheproof/README.md.

interface SignTest {
  tcId: number;
  comment: string;
  msg?: string;
  ctx?: string;
  rnd?: string;
  mu?: string;
  sig: string;
  result: "valid" | "invalid";
  flags: string[];
}

interface SignGroup {
  privateSeed?: string;
  privateKey?: string;
  // null if the private key is malformed
  publicKey: string | null;
  tests: SignTest[];
}

interface VerifyTest {
  tcId: number;
  comment: string;
  msg: string;
  ctx?: string;
  sig: string;
  result: "valid" | "invalid";
  flags: string[];
}

interface VerifyGroup {
  publicKey: string;
  tests: VerifyTest[];
}

interface TestFile<G> {
  algorithm: string;
  numberOfTests: number;
  testGroups: G[];
}

async function load<G>(
  parameterSet: string,
  kind: string,
): Promise<TestFile<G>> {
  const size = parameterSet.substring("ML-DSA-".length);
  const data = await Deno.readTextFile(
    `${testVectorPath()}/wycheproof/mldsa_${size}_${kind}_test.json`,
  );
  const file: TestFile<G> = JSON.parse(data);
  assertEquals(file.algorithm, parameterSet);
  return file;
}

PARAMETER_SETS.forEach((parameterSet) =>
  describe(`Wycheproof ${parameterSet}`, () => {
    // Signs with a private key and compares to the expected signatures.
    async function runSignTests(
      kind: string,
      getPrivateKey: (
        group: SignGroup,
        deriveKeyPair: (seed: Uint8Array) => [Uint8Array, Uint8Array],
      ) => Uint8Array,
    ) {
      const ctx = await createTestableMlDsa(parameterSet);
      const file = await load<SignGroup>(parameterSet, kind);
      let count = 0;
      let invalid = 0;
      for (const group of file.testGroups) {
        for (const t of group.tests) {
          const label = `tcId ${t.tcId}: ${t.comment}`;
          const context = t.ctx === undefined ? undefined : hexToBytes(t.ctx);
          const rnd = t.rnd === undefined
            ? new Uint8Array(32)
            : hexToBytes(t.rnd);
          const expected = hexToBytes(t.sig);
          count++;
          if (t.result === "invalid") {
            invalid++;
            assertThrows(
              () => {
                const sk = getPrivateKey(group, (s) => ctx.deriveKeyPair(s));
                ctx.sign(sk, hexToBytes(t.msg as string), {
                  context,
                  seed: rnd,
                });
              },
              MlDsaError,
              undefined,
              label,
            );
            continue;
          }
          const sk = getPrivateKey(group, (s) => ctx.deriveKeyPair(s));
          const pk = hexToBytes(group.publicKey as string);
          if (t.msg !== undefined) {
            const msg = hexToBytes(t.msg);
            const sig = ctx.sign(sk, msg, { context, seed: rnd });
            assertEquals(sig, expected, label);
            assertEquals(ctx.verify(pk, sig, msg, { context }), true, label);
          }
          if (t.mu !== undefined) {
            const mu = hexToBytes(t.mu);
            const sig = ctx.signMu(sk, mu, rnd);
            assertEquals(sig, expected, label);
            assertEquals(ctx.verifyMu(pk, sig, mu), true, label);
          }
        }
      }
      console.log(
        `Wycheproof ${parameterSet} ${kind} test vector count: ${count} (${invalid} invalid)`,
      );
      assertEquals(count, file.numberOfTests);
    }

    it("should pass the sign_seed tests", async () => {
      await runSignTests("sign_seed", (group, deriveKeyPair) => {
        const [pk, sk] = deriveKeyPair(hexToBytes(group.privateSeed as string));
        assertEquals(pk, hexToBytes(group.publicKey as string));
        return sk;
      });
    });

    it("should pass the sign_noseed tests", async () => {
      await runSignTests(
        "sign_noseed",
        (group) => hexToBytes(group.privateKey as string),
      );
    });

    it("should pass the verify tests", async () => {
      const ctx = await createTestableMlDsa(parameterSet);
      const file = await load<VerifyGroup>(parameterSet, "verify");
      let count = 0;
      let invalid = 0;
      for (const group of file.testGroups) {
        const pk = hexToBytes(group.publicKey);
        for (const t of group.tests) {
          const label = `tcId ${t.tcId}: ${t.comment}`;
          const context = t.ctx === undefined ? undefined : hexToBytes(t.ctx);
          const sig = hexToBytes(t.sig);
          const msg = hexToBytes(t.msg);
          if (t.flags.includes("InvalidContext")) {
            // Only a context that is too long is reported as an error.
            assertEquals(t.result, "invalid", label);
            assertThrows(
              () => ctx.verify(pk, sig, msg, { context }),
              MlDsaError,
              "context must be at most 255 bytes in length",
              label,
            );
          } else {
            // Anything else, including a public key or a signature of an
            // incorrect length, has to give false without throwing.
            const actual = ctx.verify(pk, sig, msg, { context });
            assertEquals(actual, t.result === "valid", label);
          }
          if (t.result === "invalid") invalid++;
          count++;
        }
      }
      console.log(
        `Wycheproof ${parameterSet} verify test vector count: ${count} (${invalid} invalid)`,
      );
      assertEquals(count, file.numberOfTests);
    });
  })
);
