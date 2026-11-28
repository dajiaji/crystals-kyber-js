import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { HQC_PARAMS } from "./params.ts";

type Internals = {
  _bufCdw: Uint8Array;
  _codeEncode(v: Uint32Array, m: Uint8Array): void;
  _codeDecode(m: Uint8Array, v: Uint32Array): void;
};

// The concatenated code C: the shortened Reed-Solomon code as the external
// code and the duplicated Reed-Muller code as the internal code (HQC
// specifications v5.1, Section 3.5.1).
HQC_PARAMS.forEach((params) =>
  describe(`${params.name}: concatenated code`, () => {
    const words = (params.n + 31) >>> 5;
    // the size of a duplicated Reed-Muller codeword in bits and in words
    const n2 = 128 * params.multiplicity;
    const blockWords = n2 / 32;

    const randomInt = (max: number) => {
      const rnd = new Uint32Array(1);
      globalThis.crypto.getRandomValues(rnd);
      return rnd[0] % max;
    };

    it("should decode a codeword", () => {
      const ctx = new params.Impl() as unknown as Internals;
      const v = new Uint32Array(words);
      const m = new Uint8Array(params.k1);
      const decoded = new Uint8Array(params.k1);
      for (let i = 0; i < 10; i++) {
        globalThis.crypto.getRandomValues(m);
        ctx._codeEncode(v, m);
        // the codeword of the external code is systematic
        assertEquals(ctx._bufCdw.subarray(params.n1 - params.k1), m);
        ctx._codeDecode(decoded, v);
        assertEquals(decoded, m);
      }
    });

    // The internal code corrects less than 32 errors per copy in a block, and
    // the external code corrects t1 blocks which are decoded wrongly.
    it("should correct errors in every block and t1 blocks which are lost", () => {
      const ctx = new params.Impl() as unknown as Internals;
      const v = new Uint32Array(words);
      const m = new Uint8Array(params.k1);
      const decoded = new Uint8Array(params.k1);
      for (let round = 0; round < 10; round++) {
        globalThis.crypto.getRandomValues(m);
        ctx._codeEncode(v, m);

        const lost = new Set<number>();
        while (lost.size < params.t1) {
          lost.add(randomInt(params.n1));
        }
        for (let block = 0; block < params.n1; block++) {
          const head = block * blockWords;
          if (lost.has(block)) {
            globalThis.crypto.getRandomValues(
              v.subarray(head, head + blockWords),
            );
            continue;
          }
          const positions = new Set<number>();
          while (positions.size < 32 * params.multiplicity - 1) {
            positions.add(randomInt(n2));
          }
          for (const pos of positions) {
            v[head + (pos >>> 5)] ^= 1 << (pos & 31);
          }
        }
        ctx._codeDecode(decoded, v);
        assertEquals(decoded, m);
      }
    });
  })
);
