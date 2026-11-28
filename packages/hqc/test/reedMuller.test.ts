import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { ReedMuller } from "../src/reedMuller.ts";
import { wordsToBytes } from "../src/utils.ts";
import { HQC_PARAMS } from "./params.ts";

// rm_generator_matrix: the generator matrix of RM(1, 7) as 8 rows of 16
// octets (HQC specifications v5.1, Section 3.5.3).
const RM_GENERATOR_MATRIX: Uint8Array[] = [
  new Uint8Array(16).fill(0xff),
  new Uint8Array(16).map((_, i) => (i & 8) ? 0xff : 0x00),
  new Uint8Array(16).map((_, i) => (i & 4) ? 0xff : 0x00),
  new Uint8Array(16).map((_, i) => (i & 2) ? 0xff : 0x00),
  new Uint8Array(16).map((_, i) => (i & 1) ? 0xff : 0x00),
  new Uint8Array(16).fill(0x0f),
  new Uint8Array(16).fill(0x33),
  new Uint8Array(16).fill(0x55),
];

// RM.Encode by its definition: the sum of the rows of rm_generator_matrix
// which the bits of the message select, the bit 7 - i for the row i.
function rmEncode(message: number): Uint8Array {
  const codeword = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    if (((message >> (7 - i)) & 1) === 1) {
      for (let j = 0; j < 16; j++) {
        codeword[j] ^= RM_GENERATOR_MATRIX[i][j];
      }
    }
  }
  return codeword;
}

// dRM.Decode.ExpandAndSum and dRM.Decode.Hadamard as the specifications
// write them, for a duplicated word of 16 * multiplicity octets.
function hadamard(duplicatedWord: Uint8Array): number[] {
  const multiplicity = duplicatedWord.length / 16;
  let bitSums: number[] = new Array(128).fill(0);
  for (let i = 0; i < multiplicity; i++) {
    for (let j = 0; j < 16; j++) {
      for (let k = 0; k < 8; k++) {
        bitSums[8 * j + k] += (duplicatedWord[16 * i + j] >> (7 - k)) & 1;
      }
    }
  }
  let coeffs: number[] = new Array(128).fill(0);
  for (let i = 0; i < 7; i++) {
    for (let j = 0; j < 64; j++) {
      const a = bitSums[2 * j];
      const b = bitSums[2 * j + 1];
      coeffs[j] = a + b;
      coeffs[j + 64] = a - b;
    }
    if (i !== 6) {
      [coeffs, bitSums] = [bitSums, coeffs];
    }
  }
  coeffs[0] -= 64 * multiplicity;
  return coeffs;
}

// dRM.Decode.FindPeaks as the specifications write it.
function findPeaks(coeffs: number[]): number {
  let decodedByte = 0;
  let peakMagnitude = 0;
  for (let i = 0; i < 128; i++) {
    const currentMagnitude = Math.abs(coeffs[i]);
    if (currentMagnitude > peakMagnitude) {
      peakMagnitude = currentMagnitude;
      decodedByte = i;
    }
  }
  if (coeffs[decodedByte] > 0) {
    decodedByte |= 0x80;
  }
  return decodedByte;
}

[...new Set(HQC_PARAMS.map((p) => p.multiplicity))].forEach((multiplicity) =>
  describe(`Reed-Muller code duplicated ${multiplicity} times`, () => {
    // the length of a duplicated codeword in octets (n2) and in words
    const n2 = 16 * multiplicity;
    const words = 4 * multiplicity;
    const all = new Uint8Array(256).map((_, i) => i);

    const toBytes = (cdw: Uint32Array) => {
      const out = new Uint8Array(4 * cdw.length);
      wordsToBytes(out, 0, cdw, out.length);
      return out;
    };

    it("should have the rows of the generator matrix as codewords", () => {
      const rm = new ReedMuller(multiplicity);
      const cdw = new Uint32Array(words);
      for (let i = 0; i < 8; i++) {
        rm.encode(cdw, new Uint8Array([1 << (7 - i)]), 1);
        assertEquals(toBytes(cdw).subarray(0, 16), RM_GENERATOR_MATRIX[i]);
      }
    });

    it("should encode every octet to the duplicated codeword of RM(1, 7)", () => {
      const rm = new ReedMuller(multiplicity);
      const cdw = new Uint32Array(256 * words);
      rm.encode(cdw, all, 256);
      const bytes = toBytes(cdw);
      for (let m = 0; m < 256; m++) {
        const expected = rmEncode(m);
        for (let copy = 0; copy < multiplicity; copy++) {
          const offset = m * n2 + 16 * copy;
          assertEquals(bytes.subarray(offset, offset + 16), expected);
        }
      }
    });

    it("should decode every codeword", () => {
      const rm = new ReedMuller(multiplicity);
      const cdw = new Uint32Array(256 * words);
      const decoded = new Uint8Array(256);
      rm.encode(cdw, all, 256);
      rm.decode(decoded, cdw, 256);
      assertEquals(decoded, all);
    });

    // The minimum distance of the duplicated code is 64 * multiplicity, and
    // the decoder returns the nearest codeword.
    it("should correct less than 32 errors per copy", () => {
      const rm = new ReedMuller(multiplicity);
      const cdw = new Uint32Array(256 * words);
      const decoded = new Uint8Array(256);
      const rnd = new Uint16Array(1);
      rm.encode(cdw, all, 256);
      const maxErrors = 32 * multiplicity - 1;
      for (let m = 0; m < 256; m++) {
        // from no error for the octet 0 to the maximum for the last ones
        const weight = Math.min(maxErrors, Math.ceil(m * maxErrors / 200));
        const positions = new Set<number>();
        while (positions.size < weight) {
          globalThis.crypto.getRandomValues(rnd);
          positions.add(rnd[0] % (128 * multiplicity));
        }
        for (const pos of positions) {
          cdw[m * words + (pos >>> 5)] ^= 1 << (pos & 31);
        }
      }
      rm.decode(decoded, cdw, 256);
      assertEquals(decoded, all);
    });

    it("should correct a copy which is lost", () => {
      const rm = new ReedMuller(multiplicity);
      const cdw = new Uint32Array(256 * words);
      const decoded = new Uint8Array(256);
      rm.encode(cdw, all, 256);
      for (let m = 0; m < 256; m++) {
        // erase the copy (m mod multiplicity)
        cdw.fill(
          0,
          m * words + 4 * (m % multiplicity),
          m * words + 4 * (m % multiplicity) + 4,
        );
      }
      rm.decode(decoded, cdw, 256);
      assertEquals(decoded, all);
    });

    // The decoder is a best effort for any word. If the peak is not unique,
    // the smallest position is returned (HQC specifications v5.1, Section
    // 3.5.3).
    it("should decode any word as the specifications define", () => {
      const rm = new ReedMuller(multiplicity);
      const count = 2000;
      const cdw = new Uint32Array(count * words);
      for (let i = 0; i < cdw.length; i += 0x4000) {
        globalThis.crypto.getRandomValues(cdw.subarray(i, i + 0x4000));
      }
      // The first words are in the middle of two codewords: the codeword of
      // the octet m, of which the half of the bits which differ from the
      // codeword of 0x00 are cleared.
      const codewords = new Uint32Array(256 * words);
      rm.encode(codewords, all, 256);
      let ties = 0;
      for (let m = 0; m < 256; m++) {
        for (let w = 0; w < words; w++) {
          cdw[m * words + w] = codewords[m * words + w] &
            ((w & 1) === 0 ? 0x33333333 : 0x0f0f0f0f);
        }
      }
      const decoded = new Uint8Array(count);
      rm.decode(decoded, cdw, count);
      const bytes = toBytes(cdw);
      for (let i = 0; i < count; i++) {
        const coeffs = hadamard(bytes.subarray(i * n2, (i + 1) * n2));
        const peak = Math.max(...coeffs.map((x) => Math.abs(x)));
        if (coeffs.filter((x) => Math.abs(x) === peak).length > 1) ties++;
        assertEquals(decoded[i], findPeaks(coeffs), `word ${i}`);
      }
      // the rule for a peak which is not unique is exercised
      assertEquals(ties > 100, true, `${ties} ties`);
    });

    it("should wipe its working memory", () => {
      const rm = new ReedMuller(multiplicity);
      const internals = rm as unknown as {
        _bitSums: Int16Array;
        _hadamardCoeffs: Int16Array;
      };
      rm.decode(new Uint8Array(1), new Uint32Array(words).fill(0x12345678), 1);
      assertEquals(internals._bitSums.some((x) => x !== 0), true);
      assertEquals(internals._hadamardCoeffs.some((x) => x !== 0), true);
      rm.clear();
      assertEquals(internals._bitSums, new Int16Array(128));
      assertEquals(internals._hadamardCoeffs, new Int16Array(128));
    });
  })
);
