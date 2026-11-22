import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import * as fs from "node:fs";
import * as readline from "node:readline";
import { shake128 } from "../src/deps.ts";

import { MlKem1024, MlKem512, MlKem768, MlKemError } from "../mod.ts";
import { bytesToHex, hexToBytes, parseKAT, testVectorPath } from "./utils.ts";
import { getDeterministicMlKemClass } from "./drng.ts";

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const ret = new Uint8Array(a.length + b.length);
  ret.set(a, 0);
  ret.set(b, a.length);
  return ret;
}

[MlKem512, MlKem768, MlKem1024].forEach((MlKemClass) =>
  describe(MlKemClass.name, () => {
    const size = MlKemClass.name.substring(5);
    const DeterministicMlKemClass = getDeterministicMlKemClass(MlKemClass);

    describe("A sample code in README.", () => {
      it("should work normally", async () => {
        const recipient = new MlKemClass();
        const [pkR, skR] = await recipient.generateKeyPair();

        const sender = new MlKemClass();
        const [ct, ssS] = await sender.encap(pkR);

        const ssR = await recipient.decap(ct, skR);

        assertEquals(ssS, ssR);
      });

      it("should work normally with deriveKeyPair", async () => {
        const recipient = new MlKemClass();
        const seed = new Uint8Array(64);
        globalThis.crypto.getRandomValues(seed);
        const [pkR, skR] = await recipient.deriveKeyPair(seed);
        const [pkR2, skR2] = await recipient.deriveKeyPair(seed);
        assertEquals(pkR, pkR2);
        assertEquals(skR, skR2);

        const sender = new MlKemClass();
        const [ct, ssS] = await sender.encap(pkR);

        const ssR = await recipient.decap(ct, skR);

        assertEquals(ssS, ssR);
      });
    });

    describe("KAT vectors", () => {
      it("should match expected values", async () => {
        const kyber = new MlKemClass();
        const katData = await Deno.readTextFile(
          `${testVectorPath()}/kat/kat_MLKEM_${size}.rsp`,
        );
        const { z, d, ct, sk, ss, msg, pk, ct_n, ss_n } = parseKAT(katData);
        console.log(`KAT test vector count: ${sk.length}`);

        for (let i = 0; i < sk.length; i++) {
          const [pkActual, skActual] = await kyber.deriveKeyPair(
            concat(d[i], z[i]),
          );
          assertEquals(pkActual, pk[i]);
          assertEquals(skActual, sk[i]);

          const ssDecapActual = await kyber.decap(ct[i], sk[i]);
          assertEquals(ssDecapActual, ss[i]);

          const [ctActual, ssEncapActual] = await kyber.encap(pk[i], msg[i]);
          assertEquals(ctActual, ct[i]);
          assertEquals(ssEncapActual, ss[i]);

          // ct_n is an invalid ciphertext; decapsulating it must return the
          // implicit rejection secret J(z || ct_n) rather than throwing.
          const ssRejectActual = await kyber.decap(ct_n[i], sk[i]);
          assertEquals(ssRejectActual, ss_n[i]);
        }
      });
    });

    describe("CCTV/ML-KEM/modulus", () => {
      it("Invalid encapsulation keys", async () => {
        const sender = new MlKemClass();
        const rl = readline.createInterface({
          input: fs.createReadStream(
            `${testVectorPath()}/modulus/ML-KEM-${size}.txt`,
          ),
          crlfDelay: Infinity,
        });
        try {
          let count = 0;
          for await (const line of rl) {
            const invalidPk = hexToBytes(line);
            await assertRejects(
              () => sender.encap(invalidPk),
              MlKemError,
              "invalid encapsulation key",
            );
            count++;
          }
          console.log(`CCTV/ML-KEM/modulus test vector count: ${count}`);
        } catch (e) {
          console.error(e);
        } finally {
          rl.close();
        }
      });
    });

    describe("CCTV/ML-KEM/strcmp", () => {
      it("strcmp vectors that fail strcmp() is used in decap.", async () => {
        const kyber = new MlKemClass();
        const testData = await Deno.readTextFile(
          `${testVectorPath()}/strcmp/ML-KEM-${size}.txt`,
        );
        const { c: [ct], dk: [sk], K: [ss] } = parseKAT(testData);
        const res = await kyber.decap(ct, sk);
        assertEquals(res, ss);
        console.log("CCTV/ML-KEM/strcmp test vector count: 1");
      });
    });

    describe("CCTV/ML-KEM/unluckysample", () => {
      it("Unlucky NTT sampling vectors that require an unusually large number of XOF reads", async () => {
        const kyber = new MlKemClass();
        const testData = await Deno.readTextFile(
          `${testVectorPath()}/unluckysample/ML-KEM-${size}.txt`,
        );
        const { c: [ct], dk: [sk], K: [ss] } = parseKAT(testData);
        const res = await kyber.decap(ct, sk);
        assertEquals(res, ss);
        console.log("CCTV/ML-KEM/unluckysample test vector count: 1");
      });
    });

    describe("pq-crystals/kyber", () => {
      it("Accumulated vectors", async () => { // See https://github.com/C2SP/CCTV/blob/main/ML-KEM/README.md#accumulated-pq-crystals-vectors
        const deterministicMlKem = new DeterministicMlKemClass();
        const shakeInstance = shake128.create({ dkLen: 32 });
        /**
         * For each test, the following values are drawn from the RNG in order:
         *
         * d for K-PKE.KeyGen
         * z for ML-KEM.KeyGen
         * m for ML-KEM.Encaps
         * ct as an invalid ciphertext input to ML-KEM.Decaps
         * Then, the following values are written to a running SHAKE-128 instance in order:
         *
         * ek from ML-KEM.KeyGen
         * dk from ML-KEM.KeyGen
         * ct from ML-KEM.Encaps
         * k from ML-KEM.Encaps (which should be checked to match the output of ML-KEM.Decaps when provided with the correct ct)
         * k from ML-KEM.Decaps when provided with the random ct
         * The resulting hashes for 10 000 consecutive tests are:
         */
        const count = 100;
        const expectedHashes: { [key: string]: string } = {
          "MlKem512":
            "449120c6e320ef3e9fbfa2316e5f2d2e1e6dd37d8ff5d086d5d2db7d42aff0a1",
          "MlKem768":
            "8d65b902f28edc683cebee2872962fd165a4d197c9e24ec74caa4470270df0b7",
          "MlKem1024":
            "c3ffe9ebecfa479c142656cbfbc6417efa05b77e994fe538eef4daed166363df",
        };
        // const count = 10000;
        // const expectedHashes: { [key: string]: string } = {
        //   "MlKem512":
        //     "705dcffc87f4e67e35a09dcaa31772e86f3341bd3ccf1e78a5fef99ae6a35a13",
        //   "MlKem768":
        //     "f959d18d3d1180121433bf0e05f11e7908cf9d03edc150b2b07cb90bef5bc1c1",
        //   "MlKem1024":
        //     "e3bf82b013307b2e9d47dde791ff6dfc82e694e6382404abdb948b908b75bad5",
        // };
        // const count = 1000000;
        // const expectedHashes: { [key: string]: string } = {
        //   "MlKem512":
        //     "21dd330d4355f2ae2876b9fa2b9de62ecaf76aca1d598de8db2b467d36e36a6a",
        //   "MlKem768":
        //     "3b108396a277f2952ff3243a985c9709bcb95788c39b7b36a2c4e19d1a41e51e",
        //   "MlKem1024":
        //     "6377c4f0ecfdb32e63f7b58227960828784fe0b3e0e5e5e9f77be300f003512a",
        // };
        console.log("pq-crystals/kyber test vector count:", count);

        for (let i = 0; i < count; i++) {
          const [ek, dk] = await deterministicMlKem.generateKeyPair();
          const [ct, k] = await deterministicMlKem.encap(ek);
          const kActual = await deterministicMlKem.decap(ct, dk);
          assertEquals(kActual, k);
          // sample random, invalid ct
          // @ts-ignore private accessor
          const ctRandom = deterministicMlKem._api!.getRandomValues(
            new Uint8Array(ct.length),
          );
          const kRandom = await deterministicMlKem.decap(ctRandom, dk);
          // hash results
          shakeInstance.update(ek)
            .update(dk)
            .update(ct)
            .update(k)
            .update(kRandom);
        }
        const actualHash = shakeInstance.digest();
        assertEquals(bytesToHex(actualHash), expectedHashes[MlKemClass.name]);
      });
    });
  })
);

describe("input validation", () => {
  for (const MlKemClass of [MlKem512, MlKem768, MlKem1024]) {
    describe(MlKemClass.name, () => {
      it("rejects a deriveKeyPair seed that is not 64 bytes", async () => {
        const kyber = new MlKemClass();
        for (const len of [0, 63, 65, 128]) {
          await assertRejects(
            () => kyber.deriveKeyPair(new Uint8Array(len)),
            MlKemError,
            "seed must be 64 bytes in length",
          );
        }
      });

      it("rejects an encapsulation key of the wrong length", async () => {
        const kyber = new MlKemClass();
        const [pk] = await kyber.generateKeyPair();
        for (const bad of [pk.subarray(0, pk.length - 1), new Uint8Array(0)]) {
          await assertRejects(
            () => kyber.encap(bad),
            MlKemError,
            "invalid encapsulation key",
          );
        }
        // a longer key is rejected too
        const longer = new Uint8Array(pk.length + 1);
        longer.set(pk);
        await assertRejects(
          () => kyber.encap(longer),
          MlKemError,
          "invalid encapsulation key",
        );
      });

      it("rejects an encap seed that is not 32 bytes", async () => {
        const kyber = new MlKemClass();
        const [pk] = await kyber.generateKeyPair();
        for (const len of [31, 33]) {
          await assertRejects(
            () => kyber.encap(pk, new Uint8Array(len)),
            MlKemError,
            "seed must be 32 bytes in length",
          );
        }
      });

      it("rejects a ciphertext of the wrong length", async () => {
        const kyber = new MlKemClass();
        const [pk, sk] = await kyber.generateKeyPair();
        const [ct] = await kyber.encap(pk);
        const longer = new Uint8Array(ct.length + 1);
        longer.set(ct);
        for (const bad of [ct.subarray(0, ct.length - 1), longer]) {
          await assertRejects(
            () => kyber.decap(bad, sk),
            MlKemError,
            "Invalid ct size",
          );
        }
      });

      it("rejects a decapsulation key of the wrong length", async () => {
        const kyber = new MlKemClass();
        const [pk, sk] = await kyber.generateKeyPair();
        const [ct] = await kyber.encap(pk);
        const longer = new Uint8Array(sk.length + 1);
        longer.set(sk);
        for (const bad of [sk.subarray(0, sk.length - 1), longer]) {
          await assertRejects(
            () => kyber.decap(ct, bad),
            MlKemError,
            "Invalid decapsulation key",
          );
        }
      });

      // FIPS 203 section 7.3 hash check. The decapsulation key is
      // dk_pke (384k) || ek (384k + 32) || H(ek) (32) || z (32).
      it("rejects a decapsulation key whose stored hash is corrupted", async () => {
        const kyber = new MlKemClass();
        const [pk, sk] = await kyber.generateKeyPair();
        const [ct] = await kyber.encap(pk);
        const hOffset = sk.length - 64;
        for (const i of [hOffset, hOffset + 31]) {
          const bad = sk.slice();
          bad[i] ^= 0x01;
          await assertRejects(
            () => kyber.decap(ct, bad),
            MlKemError,
            "Invalid decapsulation key",
          );
        }
      });

      it("rejects a decapsulation key whose embedded encapsulation key is corrupted", async () => {
        const kyber = new MlKemClass();
        const [pk, sk] = await kyber.generateKeyPair();
        const [ct] = await kyber.encap(pk);
        const ekOffset = sk.length - 64 - pk.length;
        for (const i of [ekOffset, sk.length - 65]) {
          const bad = sk.slice();
          bad[i] ^= 0x01;
          await assertRejects(
            () => kyber.decap(ct, bad),
            MlKemError,
            "Invalid decapsulation key",
          );
        }
      });

      it("accepts a decapsulation key whose z is altered (implicit rejection value only)", async () => {
        const kyber = new MlKemClass();
        const [pk, sk] = await kyber.generateKeyPair();
        const [ct, ss] = await kyber.encap(pk);
        const altered = sk.slice();
        altered[sk.length - 1] ^= 0x01;
        assertEquals(await kyber.decap(ct, altered), ss);
      });
    });
  }
});

// The XOF refill path of SampleNTT (FIPS 203 Algorithm 7) is unreachable with
// real SHAKE128 output (about 2^-105 per polynomial), so these tests replace
// the instance's XOF with one whose stream starts with rejected bytes.
describe("SampleNTT XOF refill", () => {
  const Q = 3329;
  const N = 256;

  // `rejected` bytes of 0xff (every 12-bit candidate is 0xfff >= Q), followed
  // by the genuine SHAKE128 output for the seed.
  function fakeStream(seed: Uint8Array, rejected: number): Uint8Array {
    const s = new Uint8Array(rejected + 1344).fill(0xff);
    s.set(shake128(seed, { dkLen: 1344 }), rejected);
    return s;
  }

  // A direct transcription of SampleNTT over a contiguous stream.
  function sampleNtt(stream: Uint8Array): Int16Array {
    const out = new Int16Array(N);
    for (let n = 0, pos = 0; n < N; pos += 3) {
      const d1 = (stream[pos] | (stream[pos + 1] << 8)) & 0xfff;
      const d2 = ((stream[pos + 1] >> 4) | (stream[pos + 2] << 4)) & 0xfff;
      if (d1 < Q) out[n++] = d1;
      if (d2 < Q && n < N) out[n++] = d2;
    }
    return out;
  }

  type Internals = {
    _k: number;
    _poolXof: unknown;
    _sampleMatrix(
      seed: Uint8Array,
      transposed: boolean,
    ): Array<Array<Int16Array>>;
  };

  // 504: the first three blocks yield nothing, so the tail of the first
  //      squeeze and two further blocks are needed.
  // 600: the tail of the first squeeze is only partly usable.
  // Both make the pre-fix code, which re-read bytes 504..672, produce a
  // different matrix.
  [504, 600].forEach((rejected) =>
    [MlKem512, MlKem768, MlKem1024].forEach((MlKemClass) =>
      it(`${MlKemClass.name} continues the stream after ${rejected} rejected bytes`, () => {
        const kem = new MlKemClass() as unknown as Internals;
        let stream: Uint8Array = new Uint8Array(0);
        let pos = 0;
        let refills = 0;
        kem._poolXof = {
          reset() {},
          updateUnsafe(seed: Uint8Array) {
            stream = fakeStream(seed, rejected);
            pos = 0;
            return this;
          },
          writeIntoUnsafe(out: Uint8Array) {
            if (pos >= 672) refills++;
            out.set(stream.subarray(pos, pos + out.length));
            pos += out.length;
            return out;
          },
        };

        const rho = new Uint8Array(32).map((_, i) => i);
        [false, true].forEach((transposed) => {
          const a = kem._sampleMatrix(rho, transposed);
          for (let i = 0; i < kem._k; i++) {
            for (let j = 0; j < kem._k; j++) {
              const seed = new Uint8Array(34);
              seed.set(rho);
              seed[32] = transposed ? i : j;
              seed[33] = transposed ? j : i;
              assertEquals(a[i][j], sampleNtt(fakeStream(seed, rejected)));
            }
          }
        });
        assertEquals(refills > 0, true);
      })
    )
  );
});

describe("caller-supplied seeds", () => {
  for (const MlKemClass of [MlKem512, MlKem768, MlKem1024]) {
    it(`${MlKemClass.name} does not mutate a seed passed to encap`, async () => {
      const kyber = new MlKemClass();
      const [pk] = await kyber.generateKeyPair();

      const seed = new Uint8Array(32);
      for (let i = 0; i < seed.length; i++) seed[i] = i + 1;
      const original = seed.slice();

      const [ct1, ss1] = await kyber.encap(pk, seed);
      assertEquals(seed, original);

      // and it still behaves deterministically on a second call
      const [ct2, ss2] = await kyber.encap(pk, seed);
      assertEquals(ct2, ct1);
      assertEquals(ss2, ss1);
    });

    it(`${MlKemClass.name} does not mutate a seed passed to deriveKeyPair`, async () => {
      const kyber = new MlKemClass();
      const seed = new Uint8Array(64);
      for (let i = 0; i < seed.length; i++) seed[i] = i;
      const original = seed.slice();

      const [pk1, sk1] = await kyber.deriveKeyPair(seed);
      assertEquals(seed, original);

      const [pk2, sk2] = await kyber.deriveKeyPair(seed);
      assertEquals(pk2, pk1);
      assertEquals(sk2, sk1);
    });
  }
});

// Secrets that live outside the buffer pool have to be wiped one by one.
// These tests record every typed array allocated during an operation and
// check that none of them still holds a secret once the operation is over.
describe("secret zeroization", () => {
  type Buf = Uint8Array | Int16Array;

  async function recordAllocations(fn: () => Promise<void>): Promise<Buf[]> {
    const allocated: Buf[] = [];
    // deno-lint-ignore no-explicit-any
    const g = globalThis as any;
    const originals = [g.Uint8Array, g.Int16Array];
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
    g.Int16Array = recording(originals[1]);
    try {
      await fn();
    } finally {
      [g.Uint8Array, g.Int16Array] = originals;
    }
    return allocated;
  }

  function sameContent(a: Buf, b: Buf): boolean {
    return a.length === b.length && a.every((x, i) => x === b[i]);
  }

  // The message as `polyFromMsg` spreads it: bit i becomes coefficient i,
  // set to (Q + 1) / 2 when the bit is 1.
  function messagePoly(msg: Uint8Array): Int16Array {
    const r = new Int16Array(256);
    for (let i = 0; i < 256; i++) {
      r[i] = ((msg[i >> 3] >> (i & 7)) & 1) * 1665;
    }
    return r;
  }

  for (const MlKemClass of [MlKem512, MlKem768, MlKem1024]) {
    describe(MlKemClass.name, () => {
      const seed = new Uint8Array(64).map((_, i) => i + 1);
      const msg = new Uint8Array(32).map((_, i) => 0xa5 ^ i);

      it("keeps no second copy of the secret vector after deriveKeyPair", async () => {
        const kyber = new MlKemClass();
        let pk: Uint8Array = new Uint8Array(0);
        let sk: Uint8Array = new Uint8Array(0);
        const allocated = await recordAllocations(async () => {
          [pk, sk] = await kyber.deriveKeyPair(seed);
        });
        const secretVector = sk.subarray(0, sk.length - pk.length - 64);
        const copies = allocated.filter((b) =>
          b !== sk && b instanceof Uint8Array && sameContent(b, secretVector)
        );
        assertEquals(copies.length, 0);
      });

      it("keeps no message polynomial after encap", async () => {
        const kyber = new MlKemClass();
        const [pk] = await kyber.deriveKeyPair(seed);
        const allocated = await recordAllocations(async () => {
          await kyber.encap(pk, msg);
        });
        const expected = messagePoly(msg);
        const copies = allocated.filter((b) =>
          b instanceof Int16Array && sameContent(b, expected)
        );
        assertEquals(copies.length, 0);
      });

      it("keeps no message polynomial after decap", async () => {
        const kyber = new MlKemClass();
        const [pk, sk] = await kyber.deriveKeyPair(seed);
        const [ct] = await kyber.encap(pk, msg);
        const allocated = await recordAllocations(async () => {
          await kyber.decap(ct, sk);
        });
        const expected = messagePoly(msg);
        const copies = allocated.filter((b) =>
          b instanceof Int16Array && sameContent(b, expected)
        );
        assertEquals(copies.length, 0);
      });

      for (const noSeed of [undefined, null]) {
        it(`wipes the message it generated when the seed is ${noSeed}`, async () => {
          const kyber = new MlKemClass();
          const [pk] = await kyber.deriveKeyPair(seed);
          const allocated = await recordAllocations(async () => {
            await kyber.encap(pk, noSeed as undefined);
          });
          // the generated message is the only 32-byte buffer encap allocates
          const messages = allocated.filter((b) =>
            b instanceof Uint8Array && b.length === 32
          );
          assertEquals(messages.length, 1);
          assertEquals(messages[0], new Uint8Array(32));
        });
      }
    });
  }
});
