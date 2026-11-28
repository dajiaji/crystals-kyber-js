import { assertEquals, assertNotEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { Buffer } from "node:buffer";

import { HqcError } from "../mod.ts";
import { sha3_256, shake256 } from "../src/deps.ts";
import { setRandom } from "./drng.ts";
import { HQC_PARAMS, type HqcTestParams } from "./params.ts";
import { concat } from "./utils.ts";

// The shared secret which the decapsulation returns for a ciphertext it
// rejects, computed from the definitions (HQC specifications v5.1, Section
// 3.7): J(H(ek) || sigma || c), where sigma follows seed_pke in the output of
// XOF(seed_kem || k / 8).
function rejectionKey(
  params: HqcTestParams,
  pk: Uint8Array,
  sk: Uint8Array,
  ct: Uint8Array,
): Uint8Array {
  const sigma = shake256.create({ dkLen: 32 + params.k1 }).update(sk).update(
    new Uint8Array([params.k1]),
  ).digest().subarray(32);
  const hEk = sha3_256(concat(pk, new Uint8Array([0x01])));
  return sha3_256(concat(hEk, sigma, ct, new Uint8Array([0x03])));
}

HQC_PARAMS.forEach((params) =>
  describe(params.name, () => {
    describe("A sample code in README.", () => {
      it("should work normally", async () => {
        const recipient = await params.create();
        const [pkR, skR] = recipient.generateKeyPair();

        const sender = await params.create();
        const [ct, ssS] = sender.encap(pkR);

        const ssR = recipient.decap(ct, skR);

        assertEquals(ssS, ssR);
      });

      it("should work normally with deriveKeyPair", async () => {
        const recipient = await params.create();
        const seed = new Uint8Array(32);
        globalThis.crypto.getRandomValues(seed);
        const [pkR, skR] = recipient.deriveKeyPair(seed);
        const [pkR2, skR2] = recipient.deriveKeyPair(seed);
        assertEquals(pkR, pkR2);
        assertEquals(skR, skR2);

        const sender = await params.create();
        const [ct, ssS] = sender.encap(pkR);

        const ssR = recipient.decap(ct, skR);

        assertEquals(ssS, ssR);
      });
    });

    describe("sizes", () => {
      it("should be the ones of the specifications", async () => {
        const ctx = await params.create();
        const [pk, sk] = ctx.generateKeyPair();
        const [ct, ss] = ctx.encap(pk);
        assertEquals(pk.length, params.pkSize);
        assertEquals(sk.length, params.skSize);
        assertEquals(ct.length, params.ctSize);
        assertEquals(ss.length, params.ssSize);
        assertEquals(ctx.decap(ct, sk).length, params.ssSize);
      });

      it("should use the decapsulation key in the compressed format", async () => {
        const ctx = await params.create();
        const seed = new Uint8Array(32).map((_, i) => i + 1);
        const [_pk, sk] = ctx.deriveKeyPair(seed);
        assertEquals(sk, seed);
      });
    });

    describe("randomness", () => {
      it("should draw the seed of a key pair, then m and salt one by one", async () => {
        const ctx = await params.create();
        const lengths: number[] = [];
        setRandom(ctx, (buffer) => {
          lengths.push(buffer.length);
          globalThis.crypto.getRandomValues(buffer);
        });
        const [pk, sk] = ctx.generateKeyPair();
        assertEquals(lengths, [32]);
        const [ct, ss] = ctx.encap(pk);
        assertEquals(lengths, [32, params.k1, 16]);
        assertEquals(ctx.decap(ct, sk), ss);
        assertEquals(lengths, [32, params.k1, 16]);
      });

      it("should generate different keys and ciphertexts each time", async () => {
        const ctx = await params.create();
        const [pk1, sk1] = ctx.generateKeyPair();
        const [pk2, sk2] = ctx.generateKeyPair();
        assertNotEquals(pk1, pk2);
        assertNotEquals(sk1, sk2);
        const [ct1, ss1] = ctx.encap(pk1);
        const [ct2, ss2] = ctx.encap(pk1);
        assertNotEquals(ct1, ct2);
        assertNotEquals(ss1, ss2);
      });

      it("should wrap an error of the random number generator", async () => {
        const ctx = await params.create();
        const [pk] = ctx.generateKeyPair();
        setRandom(ctx, () => {
          throw new Error("no entropy");
        });
        assertThrows(() => ctx.generateKeyPair(), HqcError, "no entropy");
        assertThrows(() => ctx.encap(pk), HqcError, "no entropy");
      });
    });

    describe("implicit rejection", () => {
      it("should return J(H(ek) || sigma || c) for an invalid ciphertext", async () => {
        const ctx = await params.create();
        const [pk, sk] = ctx.generateKeyPair();
        const [ct, ss] = ctx.encap(pk);
        const uSize = params.pkSize - 32;
        // a bit of u, of the last used octet of u, of v, and of the salt
        for (
          const i of [
            0,
            uSize - 2,
            uSize,
            ct.length - 17,
            ct.length - 16,
            ct.length - 1,
          ]
        ) {
          const bad = ct.slice();
          bad[i] ^= 0x01;
          const actual = ctx.decap(bad, sk);
          assertNotEquals(actual, ss);
          assertEquals(actual, rejectionKey(params, pk, sk, bad));
        }
        // the genuine ciphertext is still accepted
        assertEquals(ctx.decap(ct, sk), ss);
      });

      it("should reject a ciphertext of which an unused bit of u is set", async () => {
        const ctx = await params.create();
        const [pk, sk] = ctx.generateKeyPair();
        const [ct, ss] = ctx.encap(pk);
        const last = params.pkSize - 32 - 1;
        assertEquals(ct[last] & ~params.maskN, 0);
        for (let bit = 0; bit < 8; bit++) {
          if (((params.maskN >> bit) & 1) === 1) continue;
          const bad = ct.slice();
          bad[last] |= 1 << bit;
          const actual = ctx.decap(bad, sk);
          assertNotEquals(actual, ss);
          assertEquals(actual, rejectionKey(params, pk, sk, bad));
        }
      });

      it("should return a pseudorandom value for a random ciphertext", async () => {
        const ctx = await params.create();
        const [pk, sk] = ctx.generateKeyPair();
        const bad = new Uint8Array(params.ctSize);
        globalThis.crypto.getRandomValues(bad);
        assertEquals(ctx.decap(bad, sk), rejectionKey(params, pk, sk, bad));
      });

      it("should return a different shared secret with another decapsulation key", async () => {
        const ctx = await params.create();
        const [pk, sk] = ctx.generateKeyPair();
        const [_pk2, sk2] = ctx.generateKeyPair();
        const [ct, ss] = ctx.encap(pk);
        assertEquals(ctx.decap(ct, sk), ss);
        assertNotEquals(ctx.decap(ct, sk2), ss);
      });
    });

    describe("input validation", () => {
      it("rejects a deriveKeyPair seed that is not 32 bytes", async () => {
        const ctx = await params.create();
        for (const len of [0, 31, 33, 64]) {
          assertThrows(
            () => ctx.deriveKeyPair(new Uint8Array(len)),
            HqcError,
            "seed must be 32 bytes in length",
          );
        }
      });

      it("rejects an encapsulation key of the wrong length", async () => {
        const ctx = await params.create();
        const [pk] = ctx.generateKeyPair();
        const longer = new Uint8Array(pk.length + 1);
        longer.set(pk);
        for (
          const bad of [
            pk.subarray(0, pk.length - 1),
            longer,
            new Uint8Array(0),
          ]
        ) {
          assertThrows(
            () => ctx.encap(bad),
            HqcError,
            "invalid encapsulation key",
          );
        }
      });

      // The vector s of an encapsulation key has n bits, so the bits of its
      // last octet above mask_n are not used.
      it("rejects an encapsulation key of which an unused bit is set", async () => {
        const ctx = await params.create();
        const [pk] = ctx.generateKeyPair();
        assertEquals(pk[pk.length - 1] & ~params.maskN, 0);
        for (let bit = 0; bit < 8; bit++) {
          const bad = pk.slice();
          bad[pk.length - 1] |= 1 << bit;
          if (((params.maskN >> bit) & 1) === 1) {
            // a used bit: the key is merely another key
            ctx.encap(bad);
            continue;
          }
          assertThrows(
            () => ctx.encap(bad),
            HqcError,
            "invalid encapsulation key",
          );
        }
      });

      it("rejects an encap seed of the wrong length", async () => {
        const ctx = await params.create();
        const [pk] = ctx.generateKeyPair();
        const size = params.k1 + 16;
        for (const len of [0, params.k1, size - 1, size + 1]) {
          assertThrows(
            () => ctx.encap(pk, new Uint8Array(len)),
            HqcError,
            `seed must be ${size} bytes in length`,
          );
        }
      });

      it("rejects a ciphertext of the wrong length", async () => {
        const ctx = await params.create();
        const [pk, sk] = ctx.generateKeyPair();
        const [ct] = ctx.encap(pk);
        const longer = new Uint8Array(ct.length + 1);
        longer.set(ct);
        for (const bad of [ct.subarray(0, ct.length - 1), longer]) {
          assertThrows(() => ctx.decap(bad, sk), HqcError, "Invalid ct size");
        }
      });

      it("rejects a decapsulation key of the wrong length", async () => {
        const ctx = await params.create();
        const [pk, sk] = ctx.generateKeyPair();
        const [ct] = ctx.encap(pk);
        const longer = new Uint8Array(sk.length + 1);
        longer.set(sk);
        for (const bad of [sk.subarray(0, sk.length - 1), longer]) {
          assertThrows(
            () => ctx.decap(ct, bad),
            HqcError,
            "Invalid decapsulation key",
          );
        }
      });

      it("accepts inputs which are views into a larger buffer", async () => {
        const ctx = await params.create();
        const [pk, sk] = ctx.generateKeyPair();
        const seed = new Uint8Array(params.k1 + 16).map((_, i) => i);
        const [ct, ss] = ctx.encap(pk, seed);

        const pad = (a: Uint8Array) => {
          const buf = new Uint8Array(a.length + 7).fill(0xa5);
          buf.set(a, 3);
          return buf.subarray(3, 3 + a.length);
        };
        assertEquals(ctx.deriveKeyPair(pad(sk)), [pk, sk]);
        assertEquals(ctx.encap(pad(pk), pad(seed)), [ct, ss]);
        assertEquals(ctx.decap(pad(ct), pad(sk)), ss);
      });
    });

    describe("caller-supplied seeds", () => {
      it("does not mutate a seed passed to encap", async () => {
        const ctx = await params.create();
        const [pk] = ctx.generateKeyPair();

        const seed = new Uint8Array(params.k1 + 16);
        for (let i = 0; i < seed.length; i++) seed[i] = i + 1;
        const original = seed.slice();

        const [ct1, ss1] = ctx.encap(pk, seed);
        assertEquals(seed, original);

        // and it still behaves deterministically on a second call
        const [ct2, ss2] = ctx.encap(pk, seed);
        assertEquals(ct2, ct1);
        assertEquals(ss2, ss1);
      });

      it("puts the salt of the seed at the end of the ciphertext", async () => {
        const ctx = await params.create();
        const [pk] = ctx.generateKeyPair();
        const seed = new Uint8Array(params.k1 + 16).map((_, i) => 0xf0 ^ i);
        const [ct] = ctx.encap(pk, seed);
        assertEquals(ct.subarray(ct.length - 16), seed.subarray(params.k1));
      });

      it("does not mutate a seed passed to deriveKeyPair", async () => {
        const ctx = await params.create();
        const seed = new Uint8Array(32);
        for (let i = 0; i < seed.length; i++) seed[i] = i;
        const original = seed.slice();

        const [pk1, sk1] = ctx.deriveKeyPair(seed);
        assertEquals(seed, original);

        const [pk2, sk2] = ctx.deriveKeyPair(seed);
        assertEquals(pk2, pk1);
        assertEquals(sk2, sk1);

        // the returned key is a copy of the seed, not the seed itself
        sk1.fill(0);
        assertEquals(seed, original);
      });

      // Buffer of Node.js is a Uint8Array of which slice() returns a view.
      it("returns a key which does not share the memory of a Buffer seed", async () => {
        const buffer = (a: Uint8Array) =>
          Buffer.from(a) as unknown as Uint8Array;
        const ctx = await params.create();
        const seed = buffer(new Uint8Array(32).map((_, i) => 0x30 + i));
        const expected = new Uint8Array(seed);

        const [pk, sk] = ctx.deriveKeyPair(seed);
        assertEquals(sk, expected);
        assertEquals(Buffer.isBuffer(sk), false);
        seed.fill(0);
        assertEquals(sk, expected);
        assertEquals(ctx.deriveKeyPair(sk)[0], pk);

        // Buffers are accepted for the other inputs too
        const encapSeed = new Uint8Array(params.k1 + 16).map((_, i) => i);
        const [ct, ss] = ctx.encap(pk, encapSeed);
        assertEquals(ctx.encap(buffer(pk), buffer(encapSeed)), [ct, ss]);
        assertEquals(ctx.decap(buffer(ct), buffer(sk)), ss);
      });

      it("does not mutate the keys and the ciphertext", async () => {
        const ctx = await params.create();
        const [pk, sk] = ctx.generateKeyPair();
        const pkOriginal = pk.slice();
        const skOriginal = sk.slice();
        const [ct, ss] = ctx.encap(pk);
        const ctOriginal = ct.slice();
        assertEquals(ctx.decap(ct, sk), ss);
        assertEquals(pk, pkOriginal);
        assertEquals(sk, skOriginal);
        assertEquals(ct, ctOriginal);
      });
    });
  })
);

describe("parameter sets", () => {
  it("should derive unrelated keys from the same seed", async () => {
    const seed = new Uint8Array(32).map((_, i) => 3 * i + 1);
    const keys = [];
    for (const params of HQC_PARAMS) {
      const ctx = await params.create();
      const [pk] = ctx.deriveKeyPair(seed);
      // seed_pke.ek, which the vector h is expanded from
      keys.push(pk.subarray(0, 32));
    }
    assertNotEquals(keys[0], keys[1]);
    assertNotEquals(keys[0], keys[2]);
    assertNotEquals(keys[1], keys[2]);
  });
});

// The working memory of an instance is wiped after every operation, so that
// no secret is left in it. These tests look into every buffer which an
// instance holds, and record the ones which are allocated meanwhile.
describe("secret zeroization", () => {
  type Buf = Uint8Array | Uint32Array | Int16Array;

  // The tables of the Reed-Solomon code, which are public constants.
  const PUBLIC_TABLES = new Set(["_generator", "_alphaIjPow", "_evalAlphaPow"]);

  // The names of the buffers held by the object, directly or not, which are
  // not all zeros.
  function dirtyBuffers(
    obj: object,
    path = "",
    seen = new Set<object>(),
  ): string[] {
    const dirty: string[] = [];
    seen.add(obj);
    for (const [key, value] of Object.entries(obj)) {
      if (ArrayBuffer.isView(value)) {
        if (!PUBLIC_TABLES.has(key) && (value as Buf).some((x) => x !== 0)) {
          dirty.push(path + key);
        }
      } else if (
        value !== null && typeof value === "object" && !seen.has(value)
      ) {
        dirty.push(...dirtyBuffers(value, `${path}${key}.`, seen));
      }
    }
    return dirty;
  }

  function recordAllocations(fn: () => void): Buf[] {
    const allocated: Buf[] = [];
    // deno-lint-ignore no-explicit-any
    const g = globalThis as any;
    const originals = [g.Uint8Array, g.Uint32Array, g.Int16Array];
    // deno-lint-ignore no-explicit-any
    const recording = (ctor: any) =>
      new Proxy(ctor, {
        construct(target, args, newTarget) {
          const buf = Reflect.construct(target, args, newTarget);
          allocated.push(buf);
          return buf;
        },
      });
    g.Uint8Array = recording(originals[0]);
    g.Uint32Array = recording(originals[1]);
    g.Int16Array = recording(originals[2]);
    try {
      fn();
    } finally {
      [g.Uint8Array, g.Uint32Array, g.Int16Array] = originals;
    }
    return allocated;
  }

  for (const params of HQC_PARAMS) {
    describe(params.name, () => {
      const seed = new Uint8Array(32).map((_, i) => i + 1);
      const encapSeed = new Uint8Array(params.k1 + 16).map((_, i) => 0xa5 ^ i);

      it("holds buffers which the test can see", () => {
        // a guard for the tests below: the pool is found and is not empty
        const ctx = new params.Impl();
        const pool = ctx as unknown as { _vecY: Uint32Array };
        pool._vecY[0] = 1;
        assertEquals(dirtyBuffers(ctx), ["_vecY"]);
      });

      it("wipes the pool after each operation", () => {
        const ctx = new params.Impl();
        setRandom(ctx, (buffer) => globalThis.crypto.getRandomValues(buffer));
        assertEquals(dirtyBuffers(ctx), []);

        const [pk, sk] = ctx.generateKeyPair();
        assertEquals(dirtyBuffers(ctx), []);

        ctx.deriveKeyPair(seed);
        assertEquals(dirtyBuffers(ctx), []);

        const [ct] = ctx.encap(pk);
        assertEquals(dirtyBuffers(ctx), []);

        ctx.encap(pk, encapSeed);
        assertEquals(dirtyBuffers(ctx), []);

        ctx.decap(ct, sk);
        assertEquals(dirtyBuffers(ctx), []);

        // a ciphertext which is rejected
        ct[0] ^= 1;
        ctx.decap(ct, sk);
        assertEquals(dirtyBuffers(ctx), []);
      });

      it("wipes the pool when an operation fails", () => {
        const ctx = new params.Impl();
        setRandom(ctx, (buffer) => globalThis.crypto.getRandomValues(buffer));
        const [pk] = ctx.generateKeyPair();
        const [ct] = ctx.encap(pk);
        assertThrows(() => ctx.encap(pk, new Uint8Array(1)), HqcError);
        assertEquals(dirtyBuffers(ctx), []);
        assertThrows(() => ctx.decap(ct, new Uint8Array(1)), HqcError);
        assertEquals(dirtyBuffers(ctx), []);
        setRandom(ctx, (buffer) => {
          // fails at the second draw, after m has been drawn
          if (buffer.length === 16) throw new Error("no entropy");
          globalThis.crypto.getRandomValues(buffer);
        });
        assertThrows(() => ctx.encap(pk), HqcError, "no entropy");
        assertEquals(dirtyBuffers(ctx), []);
      });

      it("keeps no copy of the seed after generateKeyPair", () => {
        const ctx = new params.Impl();
        setRandom(ctx, (buffer) => globalThis.crypto.getRandomValues(buffer));
        let keys: Uint8Array[] = [];
        const allocated = recordAllocations(() => {
          keys = ctx.generateKeyPair();
        });
        // the seed is drawn into a buffer of its own, which is then wiped
        assertEquals(allocated.length > 0, true);
        const left = allocated.filter((b) =>
          !keys.includes(b as Uint8Array) && b.some((x) => x !== 0)
        );
        assertEquals(left.length, 0);
      });

      it("keeps no copy of the seed after deriveKeyPair", () => {
        const ctx = new params.Impl();
        let keys: Uint8Array[] = [];
        const allocated = recordAllocations(() => {
          keys = ctx.deriveKeyPair(seed);
        });
        const left = allocated.filter((b) =>
          !keys.includes(b as Uint8Array) && b.some((x) => x !== 0)
        );
        assertEquals(left.length, 0);
      });

      for (const noSeed of [undefined, null]) {
        it(`wipes the message and the salt it generated when the seed is ${noSeed}`, () => {
          const ctx = new params.Impl();
          setRandom(ctx, (buffer) => globalThis.crypto.getRandomValues(buffer));
          const [pk] = ctx.generateKeyPair();
          let out: Uint8Array[] = [];
          const allocated = recordAllocations(() => {
            out = ctx.encap(pk, noSeed as undefined);
          });
          // m || salt is the only buffer of that size which encap allocates
          const seeds = allocated.filter((b) =>
            b instanceof Uint8Array && b.length === params.k1 + 16
          );
          assertEquals(seeds.length, 1);
          assertEquals(seeds[0], new Uint8Array(params.k1 + 16));
          const left = allocated.filter((b) =>
            !out.includes(b as Uint8Array) && b.some((x) => x !== 0)
          );
          assertEquals(left.length, 0);
        });
      }

      it("keeps no intermediate value after decap", () => {
        const ctx = new params.Impl();
        const [pk, sk] = ctx.deriveKeyPair(seed);
        const [ct] = ctx.encap(pk, encapSeed);
        let ss: Uint8Array = new Uint8Array(0);
        const allocated = recordAllocations(() => {
          ss = ctx.decap(ct, sk);
        });
        const left = allocated.filter((b) =>
          b !== ss && b.some((x) => x !== 0)
        );
        assertEquals(left.length, 0);
      });
    });
  }
});
