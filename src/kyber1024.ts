/**
 * This implementation is based on https://github.com/antontutoveanu/crystals-kyber-javascript,
 * which was deveploped under the MIT licence below:
 * https://github.com/antontutoveanu/crystals-kyber-javascript/blob/main/LICENSE
 */
import { N, Q } from "./consts.ts";
import { KyberBase } from "./kyberBase.ts";
import { byte, int16, uint16, uint32 } from "./utils.ts";

/**
 * Represents the MlKem1024 class.
 *
 * MlKem1024 is a subclass of KyberBase and implements specific methods for the Kyber-1024 parameter set.
 *
 * @example
 *
 * ```ts
 * // import { MlKem1024 } from "crystals-kyber-js"; // Node.js
 * import { MlKem1024 } from "http://deno.land/x/crystals_kyber/mod.ts"; // Deno
 *
 * const recipient = new MlKem1024();
 * const [pkR, skR] = await recipient.generateKeyPair();

 * const sender = new MlKem1024();
 * const [ct, ssS] = await sender.encap(pkR);

 * const ssR = await recipient.decap(ct, skR);
 * // ssS === ssR
 * ```
 */
export class MlKem1024 extends KyberBase {
  protected _k = 4;
  protected _du = 11;
  protected _dv = 5;
  protected _eta1 = 2;
  protected _eta2 = 2;

  /**
   * Constructs a new instance of the MlKem1024 class.
   */
  constructor() {
    super();
    this._skSize = 12 * this._k * N / 8;
    this._pkSize = this._skSize + 32;
    this._compressedUSize = this._k * this._du * N / 8;
    this._compressedVSize = this._dv * N / 8;
  }

  // compressU lossily compresses and serializes a vector of polynomials.

  /**
   * Lossily compresses and serializes a vector of polynomials.
   *
   * @param u - The vector of polynomials to compress.
   * @returns The compressed and serialized data as a Uint8Array.
   */
  protected override _compressU(
    r: Uint8Array,
    u: Array<Array<number>>,
  ): Uint8Array {
    const t = new Array<number>(8);
    for (let rr = 0, i = 0; i < this._k; i++) {
      for (let j = 0; j < N / 8; j++) {
        for (let k = 0; k < 8; k++) {
          t[k] = uint16(
            (((uint32(u[i][8 * j + k]) << 11) + uint32(Q / 2)) /
              uint32(Q)) & 0x7ff,
          );
        }
        r[rr++] = byte(t[0] >> 0);
        r[rr++] = byte((t[0] >> 8) | (t[1] << 3));
        r[rr++] = byte((t[1] >> 5) | (t[2] << 6));
        r[rr++] = byte(t[2] >> 2);
        r[rr++] = byte((t[2] >> 10) | (t[3] << 1));
        r[rr++] = byte((t[3] >> 7) | (t[4] << 4));
        r[rr++] = byte((t[4] >> 4) | (t[5] << 7));
        r[rr++] = byte(t[5] >> 1);
        r[rr++] = byte((t[5] >> 9) | (t[6] << 2));
        r[rr++] = byte((t[6] >> 6) | (t[7] << 5));
        r[rr++] = byte(t[7] >> 3);
      }
    }
    return r;
  }

  // compressV lossily compresses and subsequently serializes a polynomial.

  /**
   * Lossily compresses and serializes a polynomial.
   *
   * @param r - The output buffer to store the compressed data.
   * @param v - The polynomial to compress.
   * @returns The compressed and serialized data as a Uint8Array.
   */
  protected override _compressV(r: Uint8Array, v: Array<number>): Uint8Array {
    const t = new Uint8Array(8);
    for (let rr = 0, i = 0; i < N / 8; i++) {
      for (let j = 0; j < 8; j++) {
        t[j] = byte(
          ((uint32(v[8 * i + j]) << 5) + uint32(Q / 2)) / uint32(Q),
        ) & 31;
      }
      r[rr++] = byte((t[0] >> 0) | (t[1] << 5));
      r[rr++] = byte((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
      r[rr++] = byte((t[3] >> 1) | (t[4] << 4));
      r[rr++] = byte((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
      r[rr++] = byte((t[6] >> 2) | (t[7] << 3));
    }
    return r;
  }

  // decompressU de-serializes and decompresses a vector of polynomials and
  // represents the approximate inverse of compress1. Since compression is lossy,
  // the results of decompression will may not match the original vector of polynomials.

  /**
   * Deserializes and decompresses a vector of polynomials.
   * This is the approximate inverse of the `_compressU` method.
   * Since compression is lossy, the decompressed data may not match the original vector of polynomials.
   *
   * @param a - The compressed and serialized data as a Uint8Array.
   * @returns The decompressed vector of polynomials.
   */
  protected override _decompressU(a: Uint8Array): Array<Array<number>> {
    const r = new Array<Array<number>>(this._k);
    for (let i = 0; i < this._k; i++) {
      r[i] = new Array<number>(384);
    }
    const t = new Array<number>(8);
    for (let aa = 0, i = 0; i < this._k; i++) {
      for (let j = 0; j < N / 8; j++) {
        t[0] = (uint16(a[aa + 0]) >> 0) | (uint16(a[aa + 1]) << 8);
        t[1] = (uint16(a[aa + 1]) >> 3) | (uint16(a[aa + 2]) << 5);
        t[2] = (uint16(a[aa + 2]) >> 6) | (uint16(a[aa + 3]) << 2) |
          (uint16(a[aa + 4]) << 10);
        t[3] = (uint16(a[aa + 4]) >> 1) | (uint16(a[aa + 5]) << 7);
        t[4] = (uint16(a[aa + 5]) >> 4) | (uint16(a[aa + 6]) << 4);
        t[5] = (uint16(a[aa + 6]) >> 7) | (uint16(a[aa + 7]) << 1) |
          (uint16(a[aa + 8]) << 9);
        t[6] = (uint16(a[aa + 8]) >> 2) | (uint16(a[aa + 9]) << 6);
        t[7] = (uint16(a[aa + 9]) >> 5) | (uint16(a[aa + 10]) << 3);
        aa = aa + 11;
        for (let k = 0; k < 8; k++) {
          r[i][8 * j + k] = (uint32(t[k] & 0x7FF) * Q + 1024) >> 11;
        }
      }
    }
    return r;
  }

  // decompressV de-serializes and subsequently decompresses a polynomial,
  // representing the approximate inverse of compress2.
  // Note that compression is lossy, and thus decompression will not match the
  // original input.

  /**
   * Decompresses a given polynomial, representing the approximate inverse of
   * compress2, in Uint8Array into an array of numbers.
   *
   * Note that compression is lossy, and thus decompression will not match the
   * original input.
   *
   * @param a - The Uint8Array to decompress.
   * @returns An array of numbers obtained from the decompression process.
   */
  protected override _decompressV(a: Uint8Array): Array<number> {
    const r = new Array<number>(384);
    const t = new Array<number>(8);
    for (let aa = 0, i = 0; i < N / 8; i++) {
      t[0] = a[aa + 0] >> 0;
      t[1] = (a[aa + 0] >> 5) | (a[aa + 1] << 3);
      t[2] = a[aa + 1] >> 2;
      t[3] = (a[aa + 1] >> 7) | (a[aa + 2] << 1);
      t[4] = (a[aa + 2] >> 4) | (a[aa + 3] << 4);
      t[5] = a[aa + 3] >> 1;
      t[6] = (a[aa + 3] >> 6) | (a[aa + 4] << 2);
      t[7] = a[aa + 4] >> 3;
      aa = aa + 5;
      for (let j = 0; j < 8; j++) {
        r[8 * i + j] = int16(((uint32(t[j] & 31) * uint32(Q)) + 16) >> 5);
      }
    }
    return r;
  }
}
