import { assertEquals, assertNotEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { sha3_256, shake256 } from "../src/deps.ts";
import { wordsToBytes } from "../src/utils.ts";
import { NistDrbg, setRandom } from "./drng.ts";
import { HQC_PARAMS } from "./params.ts";
import {
  concat,
  hexToBytes,
  parseIntermediates,
  testVectorPath,
} from "./utils.ts";

// The internals of an instance which the intermediate values are checked
// against.
type Internals = {
  _vecX: Uint32Array;
  _vecY: Uint32Array;
  _vecH: Uint32Array;
  _vecS: Uint32Array;
  _vecR1: Uint32Array;
  _vecR2: Uint32Array;
  _vecE: Uint32Array;
  _vecU: Uint32Array;
  _vecV: Uint32Array;
  _vecT: Uint32Array;
  _bufEk: Uint8Array;
  _bufCdw: Uint8Array;
  _i(seed: Uint8Array): Uint8Array;
  _h(ek: Uint8Array): Uint8Array;
  _g(hEk: Uint8Array, m: Uint8Array, salt: Uint8Array): Uint8Array;
  _j(hEk: Uint8Array, sigma: Uint8Array, ct: Uint8Array): Uint8Array;
  _pkeKeygen(seedPke: Uint8Array): void;
  _pkeEncrypt(
    out: Uint8Array,
    ek: Uint8Array,
    m: Uint8Array,
    theta: Uint8Array,
  ): void;
  _pkeDecrypt(m: Uint8Array, ct: Uint8Array): void;
  _codeEncode(v: Uint32Array, m: Uint8Array): void;
};

// The official examples with intermediate values of the HQC team: one key
// generation, encapsulation and decapsulation for each parameter set, with
// the values of every step. See ./vectors/README.md.
HQC_PARAMS.forEach((params) =>
  describe(`${params.name}: intermediate values`, () => {
    const nBytes = params.pkSize - 32;
    const n1n2Bytes = params.ctSize - nBytes - 16;

    const load = async () => {
      const sections = parseIntermediates(
        await Deno.readTextFile(
          `${testVectorPath()}/intermediate/${params.dir}/intermediates_values`,
        ),
      );
      const hex = (section: string, label: string, index = 0) =>
        hexToBytes(sections[section][label][index]);
      return { sections, hex };
    };
    const internals = () => new params.Impl() as unknown as Internals;
    // The first `len` octets of a vector.
    const bytes = (v: Uint32Array, len: number) => {
      const out = new Uint8Array(len);
      wordsToBytes(out, 0, v, len);
      return out;
    };

    it("should have the values of every step", async () => {
      const { sections } = await load();
      assertEquals(Object.keys(sections), ["KEYGEN", "ENCAPS", "DECAPS"]);
      // the vectors are printed in full
      assertEquals(sections["KEYGEN"]["y"][0].length, 2 * nBytes);
      assertEquals(sections["ENCAPS"]["v"][0].length, 2 * n1n2Bytes);
    });

    it("should match the whole example with the random bit generator of the KAT generator", async () => {
      const { hex } = await load();
      // The example is generated with the entropy input 00 01 ... 2f.
      const drbg = new NistDrbg(new Uint8Array(48).map((_, i) => i));
      const ctx = setRandom(
        new params.Impl(),
        (buffer) => drbg.fill(buffer),
      );
      const [pk, sk] = ctx.generateKeyPair();
      assertEquals(sk, hex("KEYGEN", "seed_kem"));
      assertEquals(pk, hex("KEYGEN", "ek_pke"));
      assertEquals(pk, hex("ENCAPS", "ek_kem"));

      const [ct, ss] = ctx.encap(pk);
      assertEquals(ct, hex("ENCAPS", "c_kem"));
      assertEquals(ss, hex("ENCAPS", "K"));

      assertEquals(ctx.decap(ct, sk), hex("DECAPS", "K_prime"));
    });

    it("HQC-KEM.Keygen", async () => {
      const { hex } = await load();
      const seedKem = hex("KEYGEN", "seed_kem");
      // seed_pke = XOF(seed_kem || k / 8)
      assertEquals(
        shake256.create({ dkLen: 32 }).update(seedKem).update(
          new Uint8Array([params.k1]),
        ).digest(),
        hex("KEYGEN", "seed_pke"),
      );
      const ctx = await params.create();
      assertEquals(ctx.deriveKeyPair(seedKem), [
        hex("KEYGEN", "ek_pke"),
        seedKem,
      ]);
    });

    it("HQC-PKE.Keygen", async () => {
      const { hex } = await load();
      const ctx = internals();
      const seedPke = hex("KEYGEN", "seed_pke");

      // (seed_pke.dk, seed_pke.ek) = I(seed_pke)
      assertEquals(
        ctx._i(seedPke),
        concat(hex("KEYGEN", "seed_dk"), hex("KEYGEN", "seed_ek")),
      );
      assertEquals(hex("KEYGEN", "seed_dk"), hex("KEYGEN", "dk_pke"));

      ctx._pkeKeygen(seedPke);
      assertEquals(bytes(ctx._vecY, nBytes), hex("KEYGEN", "y"));
      assertEquals(bytes(ctx._vecX, nBytes), hex("KEYGEN", "x"));
      assertEquals(bytes(ctx._vecH, nBytes), hex("KEYGEN", "h"));
      assertEquals(bytes(ctx._vecS, nBytes), hex("KEYGEN", "s"));
      assertEquals(ctx._bufEk, hex("KEYGEN", "ek_pke"));
    });

    it("C.Encode", async () => {
      const { hex } = await load();
      const ctx = internals();
      ctx._codeEncode(ctx._vecV, hex("ENCAPS", "m"));
      assertEquals(ctx._bufCdw, hex("ENCAPS", "Reed-Solomon code word"));
      assertEquals(
        bytes(ctx._vecV, n1n2Bytes),
        hex("ENCAPS", "Concatenated code word"),
      );
    });

    it("HQC-PKE.Encrypt", async () => {
      const { hex } = await load();
      const ctx = internals();
      const ek = hex("ENCAPS", "ek_kem");
      const m = hex("ENCAPS", "m");
      const salt = hex("ENCAPS", "salt");

      // (K, theta) = G(H(ek) || m || salt)
      const hEk = ctx._h(ek).slice();
      assertEquals(hEk, hex("ENCAPS", "H(ek_kem)"));
      const kTheta = ctx._g(hEk, m, salt).slice();
      assertEquals(
        kTheta,
        concat(hex("ENCAPS", "K"), hex("ENCAPS", "theta")),
      );

      const out = new Uint8Array(params.ctSize);
      ctx._pkeEncrypt(out, ek, m, kTheta.subarray(32));
      assertEquals(bytes(ctx._vecH, nBytes), hex("ENCAPS", "h"));
      assertEquals(bytes(ctx._vecS, nBytes), hex("ENCAPS", "s"));
      assertEquals(bytes(ctx._vecR1, nBytes), hex("ENCAPS", "r1"));
      assertEquals(bytes(ctx._vecR2, nBytes), hex("ENCAPS", "r2"));
      assertEquals(bytes(ctx._vecE, nBytes), hex("ENCAPS", "e"));
      assertEquals(bytes(ctx._vecU, nBytes), hex("ENCAPS", "u"));
      assertEquals(bytes(ctx._vecV, n1n2Bytes), hex("ENCAPS", "v"));

      // v = C.Encode(m) + Truncate(s.r2 + e)
      const v = hex("ENCAPS", "v");
      const codeword = hex("ENCAPS", "Concatenated code word");
      assertEquals(
        v.map((x, i) => x ^ codeword[i]),
        hex("ENCAPS", "Truncate(s.r2 + e)"),
      );

      // c_kem = (u, v, salt)
      out.set(salt, nBytes + n1n2Bytes);
      assertEquals(out, hex("ENCAPS", "c_kem"));
    });

    it("HQC-PKE.Decrypt", async () => {
      const { hex } = await load();
      const ctx = internals();
      const ct = hex("DECAPS", "c_kem");
      assertEquals(
        ct,
        concat(
          hex("DECAPS", "u"),
          hex("DECAPS", "v"),
          ct.subarray(ct.length - 16),
        ),
      );

      // the decryption key
      ctx._pkeKeygen(hex("DECAPS", "seed_pke"));
      assertEquals(bytes(ctx._vecY, nBytes), hex("DECAPS", "y"));
      assertEquals(bytes(ctx._vecY, nBytes), hex("DECAPS", "y", 1));

      const m = new Uint8Array(params.k1);
      ctx._pkeDecrypt(m, ct);
      assertEquals(bytes(ctx._vecT, n1n2Bytes), hex("DECAPS", "Truncate(u.y)"));
      assertEquals(
        bytes(ctx._vecV, n1n2Bytes),
        hex("DECAPS", "v - Truncate(u.y)"),
      );
      assertEquals(
        ctx._bufCdw,
        hex(
          "DECAPS",
          "Reed-Muller decoding result (the input for the Reed-Solomon decoding algorithm)",
        ),
      );
      assertEquals(m, hex("DECAPS", "m_prime"));
    });

    it("HQC-KEM.Decaps", async () => {
      const { hex } = await load();
      const seedKem = hex("DECAPS", "seed_kem");
      const ek = hex("DECAPS", "ek_pke");
      const ct = hex("DECAPS", "c_kem");

      // (seed_pke, sigma) = XOF(seed_kem || k / 8)
      const sigma = hex("DECAPS", "sigma");
      assertEquals(
        shake256.create({ dkLen: 32 + params.k1 }).update(seedKem).update(
          new Uint8Array([params.k1]),
        ).digest(),
        concat(hex("DECAPS", "seed_pke"), sigma),
      );

      const internal = internals();
      const hEk = internal._h(ek).slice();
      assertEquals(hEk, hex("DECAPS", "H(ek_pke)"));
      assertEquals(
        internal._g(hEk, hex("DECAPS", "m_prime"), ct.subarray(ct.length - 16)),
        concat(
          hex("DECAPS", "K_prime_candidate"),
          hex("DECAPS", "theta_prime"),
        ),
      );
      // the re-encryption gives the ciphertext
      assertEquals(
        concat(
          hex("DECAPS", "c_prime.u"),
          hex("DECAPS", "c_prime.v"),
          hex("DECAPS", "salt_prime"),
        ),
        ct,
      );

      // K_bar = J(H(ek) || sigma || c_kem)
      const kBar = hex("DECAPS", "K_bar");
      assertEquals(internal._j(hEk, sigma, ct), kBar);
      assertEquals(
        sha3_256(concat(hEk, sigma, ct, new Uint8Array([0x03]))),
        kBar,
      );

      const ctx = await params.create();
      const kPrime = hex("DECAPS", "K_prime");
      assertEquals(ctx.decap(ct, seedKem), kPrime);
      assertEquals(kPrime, hex("DECAPS", "K_prime_candidate"));
      assertNotEquals(kPrime, kBar);

      // K_bar is what the decapsulation returns for an invalid ciphertext:
      // here the one with another salt, for which K_bar is recomputed.
      const bad = ct.slice();
      bad[bad.length - 1] ^= 0x80;
      assertEquals(
        ctx.decap(bad, seedKem),
        sha3_256(concat(hEk, sigma, bad, new Uint8Array([0x03]))),
      );
    });
  })
);
