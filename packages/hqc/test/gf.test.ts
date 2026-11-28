import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { gfInverse, gfMul } from "../src/gf256.ts";
import { Gf2x } from "../src/gf2x.ts";
import { clmul16 } from "../src/utils.ts";
import { HQC_PARAMS } from "./params.ts";

// The carry-less multiplication by its definition.
function clmulNaive(x: number, y: number): number {
  let r = 0;
  for (let i = 0; i < 16; i++) {
    if (((y >>> i) & 1) === 1) {
      r ^= x << i;
    }
  }
  return r >>> 0;
}

describe("clmul16", () => {
  it("should multiply without carries", () => {
    const edges = [0, 1, 2, 3, 0x8000, 0xffff, 0x9249, 0x2492, 0x4924, 0x5555];
    for (const x of edges) {
      for (const y of edges) {
        assertEquals(clmul16(x, y) >>> 0, clmulNaive(x, y));
      }
    }
    // every 16-bit value with a few multipliers
    for (let x = 0; x < 0x10000; x++) {
      for (const y of [0xffff, 0xb6db, 0x1b, 0x8001]) {
        if ((clmul16(x, y) >>> 0) !== clmulNaive(x, y)) {
          assertEquals(clmul16(x, y) >>> 0, clmulNaive(x, y));
        }
        if ((clmul16(y, x) >>> 0) !== clmulNaive(y, x)) {
          assertEquals(clmul16(y, x) >>> 0, clmulNaive(y, x));
        }
      }
    }
    const rnd = new Uint16Array(2 * 100000);
    for (let i = 0; i < rnd.length; i += 0x8000) {
      globalThis.crypto.getRandomValues(rnd.subarray(i, i + 0x8000));
    }
    for (let i = 0; i < rnd.length; i += 2) {
      if (
        (clmul16(rnd[i], rnd[i + 1]) >>> 0) !== clmulNaive(rnd[i], rnd[i + 1])
      ) {
        assertEquals(
          clmul16(rnd[i], rnd[i + 1]) >>> 0,
          clmulNaive(rnd[i], rnd[i + 1]),
        );
      }
    }
  });
});

describe("GF(2^8)", () => {
  // The multiplication by its definition: modulo X^8 + X^4 + X^3 + X + 1.
  function gfMulNaive(a: number, b: number): number {
    let r = 0;
    for (let i = 0; i < 8; i++) {
      if (((b >> i) & 1) === 1) r ^= a << i;
    }
    for (let i = 14; i >= 8; i--) {
      if (((r >> i) & 1) === 1) r ^= 0x11b << (i - 8);
    }
    return r;
  }

  it("should multiply every pair of elements", () => {
    for (let a = 0; a < 256; a++) {
      for (let b = 0; b < 256; b++) {
        if (gfMul(a, b) !== gfMulNaive(a, b)) {
          assertEquals(gfMul(a, b), gfMulNaive(a, b), `${a} * ${b}`);
        }
      }
    }
  });

  it("should be the field of AES", () => {
    // FIPS 197, Section 4.2: {57} * {83} = {c1}
    assertEquals(gfMul(0x57, 0x83), 0xc1);
    // FIPS 197, Section 4.2.1: {57} * {13} = {fe}
    assertEquals(gfMul(0x57, 0x13), 0xfe);
    // FIPS 197, Section 5.1.1: the inverse of {53} is {ca}
    assertEquals(gfInverse(0x53), 0xca);
  });

  it("should invert every element", () => {
    assertEquals(gfInverse(0), 0);
    for (let a = 1; a < 256; a++) {
      assertEquals(gfMul(a, gfInverse(a)), 1);
    }
  });

  it("should have alpha = 0x03 as a primitive element", () => {
    const seen = new Set<number>();
    let p = 1;
    for (let i = 0; i < 255; i++) {
      seen.add(p);
      p = gfMul(p, 0x03);
    }
    assertEquals(seen.size, 255);
    assertEquals(p, 1);
    // the head of gf_exp of the reference implementation v5.1.0
    p = 1;
    const head = [];
    for (let i = 0; i < 12; i++) {
      head.push(p);
      p = gfMul(p, 0x03);
    }
    assertEquals(head, [1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150]);
  });
});

HQC_PARAMS.forEach((params) =>
  describe(`${params.name}: multiplication in F_2[X] / (X^n - 1)`, () => {
    const n = params.n;
    const words = (n + 31) >>> 5;
    const lastMask = (1 << (n & 31)) - 1;

    // The schoolbook multiplication, with a rotation of b for each bit of a.
    function mulNaive(a: Uint32Array, b: Uint32Array): Uint32Array {
      const p = new Uint32Array(2 * words);
      for (let i = 0; i < words; i++) {
        for (let bit = 0; bit < 32; bit++) {
          if (((a[i] >>> bit) & 1) === 0) continue;
          for (let j = 0; j < words; j++) {
            p[i + j] ^= b[j] << bit;
            if (bit !== 0) p[i + j + 1] ^= b[j] >>> (32 - bit);
          }
        }
      }
      // X^n = 1
      const o = new Uint32Array(words);
      for (let pos = 0; pos < 64 * words; pos++) {
        if (((p[pos >>> 5] >>> (pos & 31)) & 1) === 1) {
          const q = pos % n;
          o[q >>> 5] ^= 1 << (q & 31);
        }
      }
      return o;
    }

    function random(): Uint32Array {
      const v = new Uint32Array(words);
      globalThis.crypto.getRandomValues(v);
      v[words - 1] &= lastMask;
      return v;
    }

    function monomial(degree: number): Uint32Array {
      const v = new Uint32Array(words);
      v[degree >>> 5] = 1 << (degree & 31);
      return v;
    }

    it("should multiply dense polynomials", () => {
      const gf2x = new Gf2x(n);
      const o = new Uint32Array(words);
      for (let i = 0; i < 2; i++) {
        const a = random();
        const b = random();
        const expected = mulNaive(a, b);
        gf2x.mul(o, a, b);
        assertEquals(o, expected);
        // and it is commutative
        gf2x.mul(o, b, a);
        assertEquals(o, expected);
      }
    });

    it("should multiply the polynomials of which all the coefficients are 1", () => {
      const gf2x = new Gf2x(n);
      const ones = new Uint32Array(words).fill(0xffffffff);
      ones[words - 1] = lastMask;
      const o = new Uint32Array(words);
      gf2x.mul(o, ones, ones);
      // (1 + X + ... + X^(n - 1))^2 has n times each coefficient, and n is odd
      assertEquals(o, ones);
    });

    it("should rotate a polynomial when it is multiplied by a monomial", () => {
      const gf2x = new Gf2x(n);
      const a = random();
      const o = new Uint32Array(words);
      // 1 is the identity
      gf2x.mul(o, a, monomial(0));
      assertEquals(o, a);
      for (const degree of [1, 31, 32, n - 33, n - 1]) {
        gf2x.mul(o, a, monomial(degree));
        const expected = new Uint32Array(words);
        for (let pos = 0; pos < n; pos++) {
          if (((a[pos >>> 5] >>> (pos & 31)) & 1) === 1) {
            const q = (pos + degree) % n;
            expected[q >>> 5] |= 1 << (q & 31);
          }
        }
        assertEquals(o, expected);
      }
      // X^(n - 1) * X = X^n = 1
      gf2x.mul(o, monomial(n - 1), monomial(1));
      assertEquals(o, monomial(0));
    });

    it("should be distributive", () => {
      const gf2x = new Gf2x(n);
      const a = random();
      const b = random();
      const c = random();
      const ab = new Uint32Array(words);
      const ac = new Uint32Array(words);
      const sum = new Uint32Array(words);
      gf2x.mul(ab, a, b);
      gf2x.mul(ac, a, c);
      gf2x.mul(sum, a, b.map((x, i) => x ^ c[i]));
      assertEquals(sum, ab.map((x, i) => x ^ ac[i]));
    });

    it("should allow the output to be an operand", () => {
      const gf2x = new Gf2x(n);
      const a = random();
      const b = random();
      const expected = new Uint32Array(words);
      gf2x.mul(expected, a, b);
      const a2 = a.slice();
      gf2x.mul(a2, a2, b);
      assertEquals(a2, expected);
      const b2 = b.slice();
      gf2x.mul(b2, a, b2);
      assertEquals(b2, expected);
    });

    it("should wipe its working memory", () => {
      const gf2x = new Gf2x(n);
      const internals = gf2x as unknown as {
        _prod: Uint32Array;
        _scratch: Uint32Array;
      };
      gf2x.mul(new Uint32Array(words), random(), random());
      assertEquals(internals._prod.some((x) => x !== 0), true);
      assertEquals(internals._scratch.some((x) => x !== 0), true);
      gf2x.clear();
      assertEquals(internals._prod.every((x) => x === 0), true);
      assertEquals(internals._scratch.every((x) => x === 0), true);
    });
  })
);
