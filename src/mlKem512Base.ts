/**
 * This implementation is based on https://github.com/antontutoveanu/crystals-kyber-javascript,
 * which was deveploped under the MIT licence below:
 * https://github.com/antontutoveanu/crystals-kyber-javascript/blob/main/LICENSE
 */
import { N } from "./consts.ts";
import { MlKemBase } from "./mlKemBase.ts";
import { byteopsLoad24, int16 } from "./utils.ts";

/**
 * Shared base for MlKem512 and MlKem512Impl.
 * Contains parameter configuration and the _sampleNoise1 override.
 */
export class MlKem512Base extends MlKemBase {
  override _k = 2;
  override _du = 10;
  override _dv = 4;
  override _eta1 = 3;
  override _eta2 = 2;

  constructor() {
    super();
    this._skSize = 12 * this._k * N / 8;
    this._pkSize = this._skSize + 32;
    this._compressedUSize = this._k * this._du * N / 8;
    this._compressedVSize = this._dv * N / 8;
    this._initPool();
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
  ): Array<Int16Array> {
    const r = new Array<Int16Array>(size);
    for (let i = 0; i < size; i++) {
      r[i] = this._noiseVecs[offset + i];
      byteopsCbd(r[i], this._prf1(sigma, offset + i), this._eta1);
    }
    return r;
  }
}

/**
 * Performs the byte operations for the Cbd function.
 *
 * @param out - The output array to write into.
 * @param buf - The input buffer.
 * @param eta - The value of eta.
 */
function byteopsCbd(out: Int16Array, buf: Uint8Array, eta: number): void {
  let t, d;
  let a, b;
  for (let i = 0; i < N / 4; i++) {
    t = byteopsLoad24(buf, 3 * i);
    d = t & 0x00249249;
    d = d + ((t >> 1) & 0x00249249);
    d = d + ((t >> 2) & 0x00249249);
    for (let j = 0; j < 4; j++) {
      a = int16((d >> (6 * j + 0)) & 0x7);
      b = int16((d >> (6 * j + eta)) & 0x7);
      out[4 * i + j] = a - b;
    }
  }
}
