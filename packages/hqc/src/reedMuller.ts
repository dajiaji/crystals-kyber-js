/**
 * The duplicated Reed-Muller code of HQC (Section 3.5.3 of the HQC
 * specifications v5.1), which is the internal code of the concatenated code:
 * an octet is encoded to a codeword of RM(1, 7), which is repeated.
 *
 * The decoder runs the same sequence of operations whatever the word is.
 */
import { RM_N3 } from "./consts.ts";

// The number of 32-bit words of a codeword of RM(1, 7).
const RM_WORDS = RM_N3 / 32;

/**
 * The duplicated Reed-Muller code [128 * multiplicity, 8] with its working
 * memory.
 *
 * A word is an array of 32-bit words, of which the octet i is the bits
 * [8 * (i mod 4), 8 * (i mod 4) + 8) of the word floor(i / 4).
 */
export class ReedMuller {
  private _multiplicity: number;
  private _bitSums = new Int16Array(RM_N3);
  private _hadamardCoeffs = new Int16Array(RM_N3);

  constructor(multiplicity: number) {
    this._multiplicity = multiplicity;
  }

  /**
   * dRM.Encode: encodes each of the n1 octets of a message to a duplicated
   * codeword.
   */
  encode(cdw: Uint32Array, msg: Uint8Array, n1: number): void {
    const mult = this._multiplicity;
    for (let i = 0, p = 0; i < n1; i++) {
      // RM.Encode: the message times rm_generator_matrix
      const b = msg[i];
      let w = -((b >> 7) & 1);
      w ^= -(b & 1) & 0x55555555;
      w ^= -((b >> 1) & 1) & 0x33333333;
      w ^= -((b >> 2) & 1) & 0x0f0f0f0f;
      w ^= -((b >> 3) & 1) & 0xff00ff00;
      w ^= -((b >> 4) & 1) & 0xffff0000;
      const w0 = w;
      w ^= -((b >> 5) & 1);
      const w1 = w;
      w ^= -((b >> 6) & 1);
      const w3 = w;
      w ^= -((b >> 5) & 1);
      const w2 = w;
      for (let j = 0; j < mult; j++, p += RM_WORDS) {
        cdw[p] = w0;
        cdw[p + 1] = w1;
        cdw[p + 2] = w2;
        cdw[p + 3] = w3;
      }
    }
  }

  /**
   * dRM.Decode: decodes each of the n1 duplicated words to an octet. It is a
   * deterministic best effort: no failure is signaled.
   */
  decode(msg: Uint8Array, cdw: Uint32Array, n1: number): void {
    const mult = this._multiplicity;
    const sums = this._bitSums;
    const coeffs = this._hadamardCoeffs;
    for (let i = 0, p = 0; i < n1; i++) {
      // dRM.Decode.ExpandAndSum
      sums.fill(0);
      for (let j = 0; j < mult; j++) {
        for (let part = 0; part < RM_WORDS; part++, p++) {
          const w = cdw[p];
          for (let bit = 0; bit < 32; bit++) {
            sums[32 * part + bit] += (w >>> (bit ^ 7)) & 1;
          }
        }
      }
      // dRM.Decode.Hadamard: the result of the 7 stages ends up in coeffs.
      let src = sums;
      let dst = coeffs;
      for (let stage = 0; stage < 7; stage++) {
        for (let j = 0; j < 64; j++) {
          dst[j] = src[2 * j] + src[2 * j + 1];
          dst[j + 64] = src[2 * j] - src[2 * j + 1];
        }
        const swap = src;
        src = dst;
        dst = swap;
      }
      // The bits are summed as 0 and 1 instead of -1 and 1.
      coeffs[0] -= 64 * mult;
      // dRM.Decode.FindPeaks: the first position of the highest absolute
      // value, with the most significant bit set if the peak is positive.
      let peakAbs = 0;
      let peakValue = 0;
      let peakPos = 0;
      for (let j = 0; j < RM_N3; j++) {
        const t = coeffs[j];
        const positive = -t >> 31;
        const abs = (positive & t) | (~positive & -t);
        const greater = (peakAbs - abs) >> 31;
        peakValue ^= greater & (peakValue ^ t);
        peakPos ^= greater & (peakPos ^ j);
        peakAbs ^= greater & (peakAbs ^ abs);
      }
      msg[i] = peakPos | ((-peakValue >> 31) & 0x80);
    }
  }

  /** Wipes the working memory. */
  clear(): void {
    this._bitSums.fill(0);
    this._hadamardCoeffs.fill(0);
  }
}
