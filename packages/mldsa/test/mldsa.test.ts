import { assertEquals, assertNotEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import * as vm from "node:vm";

import { Keccak } from "../src/deps.ts";
import {
  createMlDsa44,
  createMlDsa65,
  createMlDsa87,
  MlDsaError,
} from "../mod.ts";

const PARAMS = [
  { name: "MlDsa44", create: createMlDsa44, pk: 1312, sk: 2560, sig: 2420 },
  { name: "MlDsa65", create: createMlDsa65, pk: 1952, sk: 4032, sig: 3309 },
  { name: "MlDsa87", create: createMlDsa87, pk: 2592, sk: 4896, sig: 4627 },
];

const msg = new TextEncoder().encode("hello world");

PARAMS.forEach((p) =>
  describe(p.name, () => {
    describe("A sample code in README.", () => {
      it("should work normally", async () => {
        const signer = await p.create();
        const [pk, sk] = signer.generateKeyPair();
        assertEquals(pk.length, p.pk);
        assertEquals(sk.length, p.sk);

        const sig = signer.sign(sk, msg);
        assertEquals(sig.length, p.sig);

        const verifier = await p.create();
        assertEquals(verifier.verify(pk, sig, msg), true);
      });

      it("should work normally with deriveKeyPair", async () => {
        const signer = await p.create();
        const seed = new Uint8Array(32);
        globalThis.crypto.getRandomValues(seed);
        const [pk, sk] = signer.deriveKeyPair(seed);
        const [pk2, sk2] = signer.deriveKeyPair(seed);
        assertEquals(pk, pk2);
        assertEquals(sk, sk2);

        const sig = signer.sign(sk, msg);
        assertEquals(signer.verify(pk, sig, msg), true);
      });
    });

    describe("generateKeyPair", () => {
      it("should generate a different key pair each time", async () => {
        const ctx = await p.create();
        const [pk1, sk1] = ctx.generateKeyPair();
        const [pk2, sk2] = ctx.generateKeyPair();
        assertNotEquals(pk1, pk2);
        assertNotEquals(sk1, sk2);
      });
    });

    describe("deriveKeyPair", () => {
      it("should throw MlDsaError if the seed is not 32 octets", async () => {
        const ctx = await p.create();
        for (const size of [0, 31, 33, 64]) {
          assertThrows(
            () => ctx.deriveKeyPair(new Uint8Array(size)),
            MlDsaError,
            "seed must be 32 bytes in length",
          );
        }
      });

      it("should not modify the seed", async () => {
        const ctx = await p.create();
        const seed = new Uint8Array(32).fill(0x2a);
        ctx.deriveKeyPair(seed);
        assertEquals(seed, new Uint8Array(32).fill(0x2a));
      });
    });

    describe("sign", () => {
      it("should be hedged by default", async () => {
        const ctx = await p.create();
        const [pk, sk] = ctx.generateKeyPair();
        const sig1 = ctx.sign(sk, msg);
        const sig2 = ctx.sign(sk, msg);
        assertNotEquals(sig1, sig2);
        assertEquals(ctx.verify(pk, sig1, msg), true);
        assertEquals(ctx.verify(pk, sig2, msg), true);
      });

      it("should be deterministic with a seed", async () => {
        const ctx = await p.create();
        const [pk, sk] = ctx.generateKeyPair();
        const seed = new Uint8Array(32);
        const sig1 = ctx.sign(sk, msg, { seed });
        const sig2 = ctx.sign(sk, msg, { seed });
        assertEquals(sig1, sig2);
        assertEquals(ctx.verify(pk, sig1, msg), true);
        // a supplied seed belongs to the caller and is left as it is
        assertEquals(seed, new Uint8Array(32));

        const sig3 = ctx.sign(sk, msg, { seed: new Uint8Array(32).fill(1) });
        assertNotEquals(sig1, sig3);
        assertEquals(ctx.verify(pk, sig3, msg), true);
      });

      it("should sign an empty message", async () => {
        const ctx = await p.create();
        const [pk, sk] = ctx.generateKeyPair();
        const empty = new Uint8Array(0);
        const sig = ctx.sign(sk, empty);
        assertEquals(ctx.verify(pk, sig, empty), true);
        assertEquals(ctx.verify(pk, sig, msg), false);
      });

      it("should bind the signature to the context", async () => {
        const ctx = await p.create();
        const [pk, sk] = ctx.generateKeyPair();
        const context = new Uint8Array(255).fill(0x41);
        const sig = ctx.sign(sk, msg, { context });
        assertEquals(ctx.verify(pk, sig, msg, { context }), true);
        assertEquals(ctx.verify(pk, sig, msg), false);
        assertEquals(
          ctx.verify(pk, sig, msg, { context: context.subarray(1) }),
          false,
        );
        // the empty context is the default
        const sig2 = ctx.sign(sk, msg, { context: new Uint8Array(0) });
        assertEquals(ctx.verify(pk, sig2, msg), true);
      });

      it("should throw MlDsaError if the context is too long", async () => {
        const ctx = await p.create();
        const [_pk, sk] = ctx.generateKeyPair();
        assertThrows(
          () => ctx.sign(sk, msg, { context: new Uint8Array(256) }),
          MlDsaError,
          "context must be at most 255 bytes in length",
        );
      });

      it("should throw MlDsaError if the seed is not 32 octets", async () => {
        const ctx = await p.create();
        const [_pk, sk] = ctx.generateKeyPair();
        for (const size of [0, 31, 33]) {
          assertThrows(
            () => ctx.sign(sk, msg, { seed: new Uint8Array(size) }),
            MlDsaError,
            "seed must be 32 bytes in length",
          );
        }
      });

      it("should throw MlDsaError if the private key is invalid", async () => {
        const ctx = await p.create();
        const [pk, sk] = ctx.generateKeyPair();
        for (const invalid of [new Uint8Array(0), sk.subarray(1), pk]) {
          assertThrows(
            () => ctx.sign(invalid, msg),
            MlDsaError,
            "invalid private key",
          );
        }
        // s1 with out-of-range coefficients
        const broken = sk.slice();
        broken.fill(0xFF, 128, 160);
        assertThrows(
          () => ctx.sign(broken, msg),
          MlDsaError,
          "invalid private key",
        );
      });
    });

    describe("verify", () => {
      it("should reject a modified message, signature or key", async () => {
        const ctx = await p.create();
        const [pk, sk] = ctx.generateKeyPair();
        const [pk2, _sk2] = ctx.generateKeyPair();
        const sig = ctx.sign(sk, msg);
        assertEquals(ctx.verify(pk, sig, msg), true);

        assertEquals(ctx.verify(pk2, sig, msg), false);
        assertEquals(ctx.verify(pk, sig, msg.subarray(1)), false);
        // c~, z and the hints
        for (const pos of [0, 100, sig.length - 1]) {
          const modified = sig.slice();
          modified[pos] ^= 0x01;
          assertEquals(ctx.verify(pk, modified, msg), false);
        }
      });

      it("should reject a signature of an incorrect length", async () => {
        const ctx = await p.create();
        const [pk, sk] = ctx.generateKeyPair();
        const sig = ctx.sign(sk, msg);
        const longer = new Uint8Array(sig.length + 1);
        longer.set(sig);
        assertEquals(ctx.verify(pk, new Uint8Array(0), msg), false);
        assertEquals(ctx.verify(pk, sig.subarray(1), msg), false);
        assertEquals(ctx.verify(pk, longer, msg), false);
      });

      it("should reject a public key of an incorrect length", async () => {
        const ctx = await p.create();
        const [pk, sk] = ctx.generateKeyPair();
        const sig = ctx.sign(sk, msg);
        for (const invalid of [new Uint8Array(0), pk.subarray(1), sk]) {
          assertEquals(ctx.verify(invalid, sig, msg), false);
        }
      });

      it("should verify again after an early rejection", async () => {
        const ctx = await p.create();
        const [pk, sk] = ctx.generateKeyPair();
        const sig = ctx.sign(sk, msg);
        // malformed hints: rejected while decoding the signature
        const malformed = sig.slice();
        malformed.fill(0xFF, sig.length - 8);
        assertEquals(ctx.verify(pk, malformed, msg), false);
        assertEquals(ctx.verify(pk, sig, msg), true);
      });

      it("should throw MlDsaError if the context is too long", async () => {
        const ctx = await p.create();
        const [pk, sk] = ctx.generateKeyPair();
        const sig = ctx.sign(sk, msg);
        assertThrows(
          () => ctx.verify(pk, sig, msg, { context: new Uint8Array(256) }),
          MlDsaError,
          "context must be at most 255 bytes in length",
        );
      });
    });
  })
);

describe("interoperability between parameter sets", () => {
  it("should not accept keys of another parameter set", async () => {
    const ctx44 = await createMlDsa44();
    const ctx65 = await createMlDsa65();
    const [pk, sk] = ctx44.generateKeyPair();
    const sig = ctx44.sign(sk, msg);
    assertThrows(() => ctx65.sign(sk, msg), MlDsaError);
    assertEquals(ctx65.verify(pk, sig, msg), false);
  });
});

// deno-lint-ignore no-explicit-any
const asAny = (v: unknown): any => v;

describe("arguments which are not Uint8Array", () => {
  // An ArrayBuffer has `byteLength` but no elements, so it must not be
  // accepted and silently handled as an empty input.
  const invalids = [
    new ArrayBuffer(32),
    new Uint16Array(16),
    new DataView(new ArrayBuffer(32)),
    Array.from(new Uint8Array(32)),
    "00".repeat(32),
    null,
  ];

  it("should be rejected by deriveKeyPair", async () => {
    const ctx = await createMlDsa44();
    for (const invalid of invalids) {
      assertThrows(
        () => ctx.deriveKeyPair(asAny(invalid)),
        MlDsaError,
        "seed must be a Uint8Array",
      );
    }
  });

  it("should be rejected by sign", async () => {
    const ctx = await createMlDsa44();
    const [_pk, sk] = ctx.generateKeyPair();
    for (const invalid of invalids) {
      assertThrows(
        () => ctx.sign(asAny(invalid), msg),
        MlDsaError,
        "sk must be a Uint8Array",
      );
      assertThrows(
        () => ctx.sign(sk, asAny(invalid)),
        MlDsaError,
        "msg must be a Uint8Array",
      );
      assertThrows(
        () => ctx.sign(sk, msg, { context: asAny(invalid) }),
        MlDsaError,
        "context must be a Uint8Array",
      );
      assertThrows(
        () => ctx.sign(sk, msg, { seed: asAny(invalid) }),
        MlDsaError,
        "seed must be a Uint8Array",
      );
    }
    assertThrows(
      () => ctx.sign(sk, asAny(sk.buffer)),
      MlDsaError,
      "msg must be a Uint8Array",
    );
  });

  it("should be rejected by verify", async () => {
    const ctx = await createMlDsa44();
    const [pk, sk] = ctx.generateKeyPair();
    const sig = ctx.sign(sk, msg);
    for (const invalid of invalids) {
      assertThrows(
        () => ctx.verify(asAny(invalid), sig, msg),
        MlDsaError,
        "pk must be a Uint8Array",
      );
      assertThrows(
        () => ctx.verify(pk, asAny(invalid), msg),
        MlDsaError,
        "sig must be a Uint8Array",
      );
      assertThrows(
        () => ctx.verify(pk, sig, asAny(invalid)),
        MlDsaError,
        "msg must be a Uint8Array",
      );
      assertThrows(
        () => ctx.verify(pk, sig, msg, { context: asAny(invalid) }),
        MlDsaError,
        "context must be a Uint8Array",
      );
    }
    // The same octets as the key, the signature and the message, as
    // ArrayBuffer.
    assertThrows(
      () => ctx.verify(asAny(pk.buffer), sig, msg),
      MlDsaError,
      "pk must be a Uint8Array",
    );
    assertThrows(
      () => ctx.verify(pk, sig, asAny(msg.buffer)),
      MlDsaError,
      "msg must be a Uint8Array",
    );
  });

  it("should accept a subclass of Uint8Array", async () => {
    class Bytes extends Uint8Array {}
    const ctx = await createMlDsa44();
    const seed = new Bytes(32).fill(7);
    const [pk, sk] = ctx.deriveKeyPair(seed);
    const [pk2, _sk2] = ctx.deriveKeyPair(new Uint8Array(32).fill(7));
    assertEquals(pk, pk2);
    const sig = ctx.sign(sk, Bytes.from(msg));
    assertEquals(ctx.verify(pk, sig, msg), true);
  });

  it("should accept a Uint8Array created in another realm", async () => {
    const ctx = await createMlDsa44();
    const [pk, sk] = ctx.deriveKeyPair(new Uint8Array(32).fill(7));
    const sig = ctx.sign(sk, msg, { seed: new Uint8Array(32) });
    for (
      const code of [
        "new Uint8Array(32).fill(7)",
        "class Bytes extends Uint8Array {}; new Bytes(32).fill(7)",
      ]
    ) {
      const seed: Uint8Array = vm.runInNewContext(code);
      assertEquals(seed instanceof Uint8Array, false);
      const [pk2, sk2] = ctx.deriveKeyPair(seed);
      assertEquals(pk2, pk);
      assertEquals(sk2, sk);
    }
    const foreign = (v: Uint8Array): Uint8Array =>
      vm.runInNewContext(
        `class Bytes extends Uint8Array {}; Bytes.from([${v.join(",")}])`,
      );
    assertEquals(
      ctx.sign(foreign(sk), foreign(msg), {
        seed: foreign(new Uint8Array(32)),
      }),
      sig,
    );
    assertEquals(ctx.verify(foreign(pk), foreign(sig), foreign(msg)), true);
  });

  it("should reject an object which pretends to be a Uint8Array", async () => {
    const ctx = await createMlDsa44();
    const fakes = [
      { constructor: { name: "Uint8Array" }, length: 32, byteLength: 32 },
      { [Symbol.toStringTag]: "Uint8Array", length: 32, byteLength: 32 },
      new Proxy(new Uint8Array(32), {}),
      vm.runInNewContext("new ArrayBuffer(32)"),
      vm.runInNewContext("new Uint16Array(16)"),
    ];
    for (const fake of fakes) {
      assertThrows(
        () => ctx.deriveKeyPair(asAny(fake)),
        MlDsaError,
        "seed must be a Uint8Array",
      );
    }
  });
});

describe("zeroization of the hash states", () => {
  // deno-lint-ignore no-explicit-any
  const internals = (v: unknown): any => v;
  const isZero = (v: ArrayLike<number>) =>
    Array.prototype.every.call(v, (x: number) => x === 0);

  it("Keccak.reset should clear the state and the scratch buffer", () => {
    const h = new Keccak(136, 0x1f, 32, true);
    h.updateUnsafe(msg).writeIntoUnsafe(new Uint8Array(32));
    assertEquals(isZero(internals(h).state), false);
    assertEquals(isZero(internals(h)._B), false);
    h.reset();
    assertEquals(isZero(internals(h).state), true);
    assertEquals(isZero(internals(h)._B), true);
  });

  function assertHashesCleared(ctx: unknown) {
    for (const name of ["_shake128", "_shake256"]) {
      const h = internals(ctx)[name];
      assertEquals(isZero(h.state), true, `${name}.state`);
      assertEquals(isZero(h._B), true, `${name}._B`);
    }
    assertEquals(isZero(internals(ctx)._block128), true);
    assertEquals(isZero(internals(ctx)._block256), true);
  }

  PARAMS.forEach((p) =>
    it(`${p.name} should leave nothing behind in the hashes`, async () => {
      const ctx = await p.create();
      const [pk, sk] = ctx.generateKeyPair();
      assertHashesCleared(ctx);
      const sig = ctx.sign(sk, msg);
      assertHashesCleared(ctx);
      assertEquals(ctx.verify(pk, sig, msg), true);
      assertHashesCleared(ctx);

      // rejected by the norm check of z, while decoding the signature
      const badZ = sig.slice();
      badZ.fill(0, 64, 128);
      assertEquals(ctx.verify(pk, badZ, msg), false);
      assertHashesCleared(ctx);
      // rejected by the decoding of the hints
      const badHints = sig.slice();
      badHints.fill(0xFF, sig.length - 8);
      assertEquals(ctx.verify(pk, badHints, msg), false);
      assertHashesCleared(ctx);
      // rejected by the comparison of c~
      assertEquals(ctx.verify(pk, sig, msg.subarray(1)), false);
      assertHashesCleared(ctx);
      // rejected by the private key validation
      const badSk = sk.slice();
      badSk.fill(0xFF, 128, 160);
      assertThrows(() => ctx.sign(badSk, msg), MlDsaError);
      assertHashesCleared(ctx);
    })
  );
});
