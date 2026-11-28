import { assertEquals, assertRejects, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { HqcError } from "../mod.ts";
import {
  bytesToWords,
  constantTimeCompare,
  wordsToBytes,
} from "../src/utils.ts";
import { NistDrbg } from "./drng.ts";
import { HQC_PARAMS } from "./params.ts";
import { bytesToHex } from "./utils.ts";

describe("constantTimeCompare", () => {
  it("should return 1 only for the same arrays", () => {
    const a = new Uint8Array([1, 2, 3, 0xff]);
    assertEquals(constantTimeCompare(a, a.slice()), 1);
    assertEquals(constantTimeCompare(new Uint8Array(0), new Uint8Array(0)), 1);
    for (let i = 0; i < a.length; i++) {
      for (let bit = 0; bit < 8; bit++) {
        const b = a.slice();
        b[i] ^= 1 << bit;
        assertEquals(constantTimeCompare(a, b), 0);
      }
    }
    assertEquals(constantTimeCompare(a, a.subarray(0, 3)), 0);
    assertEquals(constantTimeCompare(a.subarray(0, 3), a), 0);
  });
});

describe("bytesToWords / wordsToBytes", () => {
  it("should convert octets in little-endian order", () => {
    const words = new Uint32Array(2).fill(0xffffffff);
    bytesToWords(words, new Uint8Array([0x01, 0x02, 0x03, 0x04, 0x05]), 0, 5);
    assertEquals(words, new Uint32Array([0x04030201, 0x00000005]));

    const bytes = new Uint8Array(8);
    wordsToBytes(bytes, 1, new Uint32Array([0x84838281, 0x88878685]), 6);
    assertEquals(
      bytes,
      new Uint8Array([0x00, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x00]),
    );
  });

  it("should convert octets of any length and from any offset", () => {
    const src = new Uint8Array(40).map((_, i) => 0x80 + i);
    for (let len = 0; len <= 16; len++) {
      for (const off of [0, 1, 7]) {
        const words = new Uint32Array(5).fill(0xffffffff);
        bytesToWords(words, src, off, len);
        const out = new Uint8Array(20).fill(0xee);
        wordsToBytes(out, 0, words, 20);
        // the octets, then zeros up to the end of the words
        const expected = new Uint8Array(20);
        expected.set(src.subarray(off, off + len));
        assertEquals(out, expected);
      }
    }
  });
});

describe("HqcError", () => {
  it("should take its message from an error or a string", () => {
    assertEquals(new HqcError(new Error("failed")).message, "failed");
    assertEquals(new HqcError("failed").message, "failed");
    assertEquals(new HqcError(undefined).message, "");
    assertEquals(new HqcError({ message: "failed" }).message, "");
    assertEquals(new HqcError("failed").name, "HqcError");
    assertEquals(new HqcError("failed") instanceof Error, true);
  });
});

describe("factory functions", () => {
  it("should fail if the Web Crypto API is not available", async () => {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto")!;
    Object.defineProperty(globalThis, "crypto", {
      value: undefined,
      configurable: true,
    });
    try {
      for (const params of HQC_PARAMS) {
        await assertRejects(
          () => params.create(),
          Error,
          "Web Crypto API is not available",
        );
      }
    } finally {
      Object.defineProperty(globalThis, "crypto", descriptor);
    }
    // and they work again
    for (const params of HQC_PARAMS) {
      const ctx = await params.create();
      assertEquals(ctx.generateKeyPair()[0].length, params.pkSize);
    }
  });

  it("should bind the Web Crypto API once", async () => {
    for (const params of HQC_PARAMS) {
      const ctx = new params.Impl() as unknown as {
        _api: Crypto | undefined;
        _setup(): Promise<void>;
      };
      assertEquals(ctx._api, undefined);
      await ctx._setup();
      assertEquals(ctx._api, globalThis.crypto);
      const api = {} as Crypto;
      ctx._api = api;
      await ctx._setup();
      assertEquals(ctx._api === api, true);
    }
  });
});

// The test of the random bit generator which the KAT tests rely on.
describe("NistDrbg", () => {
  // The first seeds of the request files of the NIST KAT generator
  // (PQCkemKAT_*.req), which are drawn from the generator seeded with the
  // 48 octets 00 01 ... 2f.
  it("should generate the seeds of the KAT request files", () => {
    const drbg = new NistDrbg(new Uint8Array(48).map((_, i) => i));
    const seed = new Uint8Array(48);
    drbg.fill(seed);
    assertEquals(
      bytesToHex(seed).toUpperCase(),
      "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
    );
    drbg.fill(seed);
    assertEquals(
      bytesToHex(seed).toUpperCase(),
      "D81C4D8D734FCBFBEADE3D3F8A039FAA2A2C9957E835AD55B22E75BF57BB556AC81ADDE6AEEB4A5A875C3BFCADFA958F",
    );
  });

  it("should reject an entropy input of the wrong length", () => {
    for (const len of [0, 32, 47, 49]) {
      assertThrows(
        () => new NistDrbg(new Uint8Array(len)),
        Error,
        "entropy must be 48 bytes in length",
      );
    }
  });
});
