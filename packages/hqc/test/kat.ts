import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { NistDrbg, setRandom } from "./drng.ts";
import type { HqcTestParams } from "./params.ts";
import { concat, parseKAT, testVectorPath } from "./utils.ts";

/**
 * Defines the test of a parameter set with the official Known Answer Test
 * values of the HQC team: 100 vectors, generated with the KAT generator of
 * NIST. See ./vectors/README.md.
 *
 * The test of each parameter set is in a file of its own, so that they run
 * in parallel.
 */
export function describeKat(params: HqcTestParams): void {
  describe(`${params.name}: KAT vectors`, () => {
    it("should match expected values", async () => {
      const { seed, pk, sk, ct, ss } = parseKAT(
        await Deno.readTextFile(
          `${testVectorPath()}/kat/${params.dir}/PQCkemKAT_32.rsp`,
        ),
      );
      assertEquals(seed.length, 100);
      console.log(`${params.name} KAT test vector count: ${seed.length}`);

      const generator = new params.Impl();
      const ctx = await params.create();
      for (let i = 0; i < seed.length; i++) {
        // The way the vectors were generated: the random bit generator is
        // seeded with `seed`, then a key pair is generated, a shared secret
        // is encapsulated and it is decapsulated.
        const drbg = new NistDrbg(seed[i]);
        setRandom(generator, (buffer) => drbg.fill(buffer));

        const [pkActual, skActual] = generator.generateKeyPair();
        assertEquals(pkActual, pk[i]);
        assertEquals(skActual, sk[i]);

        const [ctActual, ssEncapActual] = generator.encap(pkActual);
        assertEquals(ctActual, ct[i]);
        assertEquals(ssEncapActual, ss[i]);

        const ssDecapActual = generator.decap(ct[i], sk[i]);
        assertEquals(ssDecapActual, ss[i]);

        // The same vector with the values given explicitly. The
        // decapsulation key is the 32-octet seed which the key pair is
        // derived from, and the encapsulation takes m || salt, which the
        // generator draws one by one after that seed.
        const drbg2 = new NistDrbg(seed[i]);
        const seedKem = new Uint8Array(32);
        const m = new Uint8Array(params.k1);
        const salt = new Uint8Array(16);
        drbg2.fill(seedKem);
        drbg2.fill(m);
        drbg2.fill(salt);
        assertEquals(seedKem, sk[i]);

        assertEquals(ctx.deriveKeyPair(seedKem), [pk[i], sk[i]]);
        assertEquals(ctx.encap(pk[i], concat(m, salt)), [ct[i], ss[i]]);
      }
    });
  });
}
