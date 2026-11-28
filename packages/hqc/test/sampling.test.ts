import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { shake256 } from "../src/sha3/sha3.ts";
import { reduce24 } from "../src/utils.ts";
import { HQC_PARAMS } from "./params.ts";

type Internals = {
  _maskN: number;
  _rejectionThreshold: number;
  _barrettMu: number;
  _poolXof: unknown;
  _xofInit(seed: Uint8Array, domain?: number): void;
  _sampleVect(v: Uint32Array): void;
  _sampleFixedWeightVect1(v: Uint32Array, weight: number): void;
  _sampleFixedWeightVect2(v: Uint32Array, weight: number): void;
};

// A function which returns the next octets of a stream.
type Stream = (len: number) => Uint8Array;

// SampleSupport1 as the specifications write it (HQC specifications v5.1,
// Section 3.3).
function sampleSupport1(
  next: Stream,
  weight: number,
  n: number,
  rejectionThreshold: number,
): number[] {
  const support: number[] = [];
  while (support.length < weight) {
    const bytes = next(3);
    let candidate = bytes[0] | (bytes[1] << 8) | (bytes[2] << 16);
    if (candidate >= rejectionThreshold) continue;
    candidate = candidate % n;
    if (!support.includes(candidate)) {
      support.push(candidate);
    }
  }
  return support;
}

// SampleSupport2 as the specifications write it.
function sampleSupport2(next: Stream, weight: number, n: number): number[] {
  const bytes = next(4 * weight);
  const support: number[] = [];
  for (let i = 0; i < weight; i++) {
    const rnd = BigInt(bytes[4 * i]) | (BigInt(bytes[4 * i + 1]) << 8n) |
      (BigInt(bytes[4 * i + 2]) << 16n) | (BigInt(bytes[4 * i + 3]) << 24n);
    support.push(i + Number((rnd * BigInt(n - i)) >> 32n));
  }
  for (let i = weight - 1; i >= 0; i--) {
    for (let j = i + 1; j < weight; j++) {
      if (support[i] === support[j]) {
        support[i] = i;
      }
    }
  }
  return support;
}

// ComputeVectorFromSupport, as 32-bit words.
function vectorFromSupport(support: number[], n: number): Uint32Array {
  const v = new Uint32Array((n + 31) >>> 5);
  for (const pos of support) {
    v[pos >>> 5] |= 1 << (pos & 31);
  }
  return v;
}

function weightOf(v: Uint32Array): number {
  let weight = 0;
  for (const word of v) {
    for (let x = word; x !== 0; x &= x - 1) weight++;
  }
  return weight;
}

HQC_PARAMS.forEach((params) =>
  describe(`${params.name}: sampling`, () => {
    const n = params.n;
    const words = (n + 31) >>> 5;
    const nBytes = (n + 7) >>> 3;
    const internals = () => new params.Impl() as unknown as Internals;
    // The octets of SHAKE256(seed), which the samplers read from.
    const xof = (seed: Uint8Array): Stream => {
      const h = shake256.create({}).update(seed);
      return (len) => h.xofInto(new Uint8Array(len));
    };
    // Makes the samplers of an instance read the given octets, then 0xff.
    const feed = (ctx: Internals, stream: Uint8Array) => {
      let pos = 0;
      ctx._poolXof = {
        writeIntoUnsafe(out: Uint8Array) {
          for (let i = 0; i < out.length; i++) {
            out[i] = pos < stream.length ? stream[pos] : 0xff;
            pos++;
          }
          return out;
        },
      };
    };
    const u24 = (values: number[]) =>
      new Uint8Array(
        values.flatMap((x) => [x & 0xff, (x >> 8) & 0xff, x >> 16]),
      );

    it("should have the parameters of the specifications", () => {
      const ctx = internals();
      assertEquals(ctx._maskN, params.maskN);
      assertEquals(ctx._rejectionThreshold, params.rejectionThreshold);
      assertEquals(ctx._barrettMu, Math.floor(2 ** 32 / n));
      // the largest multiple of n below 2^24
      assertEquals(ctx._rejectionThreshold % n, 0);
      assertEquals(ctx._rejectionThreshold + n > 2 ** 24, true);
    });

    it("should reduce every 24-bit value modulo n", () => {
      const mu = Math.floor(2 ** 32 / n);
      for (let x = 0; x < 2 ** 24; x++) {
        if (reduce24(x, n, mu) !== x % n) {
          assertEquals(reduce24(x, n, mu), x % n, `${x} mod ${n}`);
        }
      }
    });

    it("SampleVect", () => {
      const ctx = internals();
      const v = new Uint32Array(words);
      for (let i = 0; i < 20; i++) {
        const seed = new Uint8Array(32).fill(i);
        ctx._xofInit(seed);
        ctx._sampleVect(v);

        const bytes = xof(seed)(nBytes);
        bytes[nBytes - 1] &= params.maskN;
        const expected = new Uint32Array(words);
        bytes.forEach((b, j) => expected[j >>> 2] |= b << (8 * (j & 3)));
        assertEquals(v, expected);
      }
      // the unused bits are cleared
      feed(ctx, new Uint8Array(0));
      ctx._sampleVect(v);
      assertEquals(weightOf(v), n);
    });

    it("SampleFixedWeightVect$", () => {
      const ctx = internals();
      const v = new Uint32Array(words);
      for (let i = 0; i < 200; i++) {
        const seed = new Uint8Array(32).fill(i);
        ctx._xofInit(seed);
        // two vectors from the same stream, as the key generation does
        for (let j = 0; j < 2; j++) {
          ctx._sampleFixedWeightVect1(v, params.omega);
          assertEquals(weightOf(v), params.omega);
        }
        const next = xof(seed);
        sampleSupport1(next, params.omega, n, params.rejectionThreshold);
        const support = sampleSupport1(
          next,
          params.omega,
          n,
          params.rejectionThreshold,
        );
        assertEquals(v, vectorFromSupport(support, n));
      }
    });

    it("SampleFixedWeightVect$ with rejected and repeated candidates", () => {
      const ctx = internals();
      const v = new Uint32Array(words);
      const threshold = params.rejectionThreshold;
      const head = [
        0xffffff, // rejected
        threshold, // rejected: the smallest value which is
        threshold - 1, // n - 1
        7,
        7, // repeated
        n, // 0
        0, // repeated
        2 * n + 3, // 3
        threshold + 1, // rejected
        n - 1, // repeated
      ];
      // then enough distinct positions to complete the support
      const tail = Array.from({ length: params.omega }, (_, i) => 100 + i);
      const stream = u24([...head, ...tail]);
      feed(ctx, stream);
      ctx._sampleFixedWeightVect1(v, params.omega);

      let pos = 0;
      const support = sampleSupport1(
        (len) => stream.subarray(pos, pos += len),
        params.omega,
        n,
        threshold,
      );
      assertEquals(support.slice(0, 5), [n - 1, 7, 0, 3, 100]);
      assertEquals(v, vectorFromSupport(support, n));
      assertEquals(weightOf(v), params.omega);
    });

    it("SampleFixedWeightVect", () => {
      const ctx = internals();
      const v = new Uint32Array(words);
      for (let i = 0; i < 200; i++) {
        const seed = new Uint8Array(32).fill(i);
        ctx._xofInit(seed);
        const next = xof(seed);
        // three vectors from the same stream, as the encryption does
        for (const weight of [params.omegaR, params.omegaE, params.omegaR]) {
          ctx._sampleFixedWeightVect2(v, weight);
          assertEquals(weightOf(v), weight);
          assertEquals(
            v,
            vectorFromSupport(sampleSupport2(next, weight, n), n),
          );
        }
      }
    });

    it("SampleFixedWeightVect with repeated positions", () => {
      const ctx = internals();
      const v = new Uint32Array(words);
      const weight = params.omegaR;

      // Every random value is 0: the position i is i.
      feed(ctx, new Uint8Array(4 * weight));
      ctx._sampleFixedWeightVect2(v, weight);
      assertEquals(
        v,
        vectorFromSupport(Array.from({ length: weight }, (_, i) => i), n),
      );

      // Every random value is 2^32 - 1: every position is n - 1, so all of
      // them but the last one are replaced with their indices.
      feed(ctx, new Uint8Array(0));
      ctx._sampleFixedWeightVect2(v, weight);
      assertEquals(
        v,
        vectorFromSupport(
          [...Array.from({ length: weight - 1 }, (_, i) => i), n - 1],
          n,
        ),
      );
      assertEquals(weightOf(v), weight);
    });
  })
);
