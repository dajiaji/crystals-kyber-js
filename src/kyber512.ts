/**
 * This implementation is based on https://github.com/antontutoveanu/crystals-kyber-javascript,
 * which was deveploped under the MIT licence below:
 * https://github.com/antontutoveanu/crystals-kyber-javascript/blob/main/LICENSE
 */
import { N } from "./consts.ts";
import { KyberBase } from "./kyberBase.ts";
import { byteopsLoad24, int16, prf } from "./utils.ts";

/**
 * Represents the MlKem512 class.
 *
 * This class extends the KyberBase class and provides specific implementation for MlKem512.
 *
 * @remarks
 *
 * MlKem512 is a specific implementation of the Kyber key encapsulation mechanism.
 *
 * @example
 *
 * ```ts
 * // import { MlKem512 } from "crystals-kyber-js"; // Node.js
 * import { MlKem512 } from "http://deno.land/x/crystals_kyber/mod.ts"; // Deno
 *
 * const recipient = new MlKem512();
 * const [pkR, skR] = await recipient.generateKeyPair();
 *
 * const sender = new MlKem512();
 * const [ct, ssS] = await sender.encap(pkR);
 *
 * const ssR = await recipient.decap(ct, skR);
 * // ssS === ssR
 * ```
 */
export class MlKem512 extends KyberBase {
  protected _k = 2;
  protected _du = 10;
  protected _dv = 4;
  protected _eta1 = 3;
  protected _eta2 = 2;

  /**
   * Constructs a new instance of the MlKem512 class.
   */
  constructor() {
    super();
    this._skSize = 12 * this._k * N / 8;
    this._pkSize = this._skSize + 32;
    this._compressedUSize = this._k * this._du * N / 8;
    this._compressedVSize = this._dv * N / 8;
  }

  /**
   * Samples a vector of polynomials from a seed.
   * @internal
   * @param sigma - The seed.
   * @param offset - The offset.
   * @param size - The size.
   * @returns The sampled vector of polynomials.
   */
  protected override _sampleNoise1(
    sigma: Uint8Array,
    offset: number,
    size: number,
  ): Array<Array<number>> {
    const r = new Array<Array<number>>(size);
    for (let i = 0; i < size; i++) {
      r[i] = byteopsCbd(prf(this._eta1 * N / 4, sigma, offset), this._eta1);
      offset++;
    }
    return r;
  }
}

/**
 * Performs the byte operations for the Cbd function.
 *
 * @param buf - The input buffer.
 * @param eta - The value of eta.
 * @returns An array of numbers representing the result of the byte operations.
 */
function byteopsCbd(buf: Uint8Array, eta: number): Array<number> {
  let t, d;
  let a, b;
  const r = new Array<number>(384).fill(0);
  for (let i = 0; i < N / 4; i++) {
    t = byteopsLoad24(buf.subarray(3 * i, buf.length));
    d = t & 0x00249249;
    d = d + ((t >> 1) & 0x00249249);
    d = d + ((t >> 2) & 0x00249249);
    for (let j = 0; j < 4; j++) {
      a = int16((d >> (6 * j + 0)) & 0x7);
      b = int16((d >> (6 * j + eta)) & 0x7);
      r[4 * i + j] = a - b;
    }
  }
  return r;
}
