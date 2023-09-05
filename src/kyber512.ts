/**
 * This implementation is based on https://github.com/antontutoveanu/crystals-kyber-javascript,
 * which was deveploped under the MIT licence below:
 * https://github.com/antontutoveanu/crystals-kyber-javascript/blob/main/LICENSE
 */
import { N, Q } from "./consts.ts";
import { KyberBase } from "./kyberBase.ts";
import { byte, byteopsLoad24, int16, prf, uint16, uint32 } from "./utils.ts";

export class Kyber512 extends KyberBase {
  protected _k = 2;
  protected _du = 10;
  protected _dv = 4;
  protected _eta1 = 3;
  protected _eta2 = 2;

  constructor() {
    super();
    this._skSize = 12 * this._k * N / 8;
    this._pkSize = this._skSize + 32;
    this._compressedUSize = this._k * this._du * N / 8;
    this._compressedVSize = this._dv * N / 8;
  }

  protected override _sampleNoise1(
    sigma: Uint8Array,
    offset: number,
    size: number,
  ): Array<Array<number>> {
    const r = new Array<Array<number>>(size);
    for (let i = 0; i < size; i++) {
      r[i] = byteopsCbd1(prf(this._eta1 * N / 4, sigma, offset), this._eta1);
      offset++;
    }
    return r;
  }

  protected override _compressU(
    r: Uint8Array,
    u: Array<Array<number>>,
  ): Uint8Array {
    const t = new Array<number>(4);
    for (let rr = 0, i = 0; i < this._k; i++) {
      for (let j = 0; j < N / 4; j++) {
        for (let k = 0; k < 4; k++) {
          // parse {0,...,3328} to {0,...,1023}
          t[k] = (((u[i][4 * j + k] << 10) + Q / 2) / Q) &
            0b1111111111;
        }
        // converts 4 12-bit coefficients {0,...,3328} to 5 8-bit bytes {0,...,255}
        // 48 bits down to 40 bits per block
        r[rr++] = byte(t[0] >> 0);
        r[rr++] = byte((t[0] >> 8) | (t[1] << 2));
        r[rr++] = byte((t[1] >> 6) | (t[2] << 4));
        r[rr++] = byte((t[2] >> 4) | (t[3] << 6));
        r[rr++] = byte(t[3] >> 2);
      }
    }
    return r;
  }

  protected override _compressV(r: Uint8Array, v: Array<number>): Uint8Array {
    // const r = new Uint8Array(128);
    const t = new Uint8Array(8);
    for (let rr = 0, i = 0; i < N / 8; i++) {
      for (let j = 0; j < 8; j++) {
        t[j] = byte(((v[8 * i + j] << 4) + Q / 2) / Q) & 0b1111;
      }
      r[rr++] = t[0] | (t[1] << 4);
      r[rr++] = t[2] | (t[3] << 4);
      r[rr++] = t[4] | (t[5] << 4);
      r[rr++] = t[6] | (t[7] << 4);
    }
    return r;
  }

  protected override _decompressU(a: Uint8Array): Array<Array<number>> {
    const r = new Array<Array<number>>(this._k);
    for (let i = 0; i < this._k; i++) {
      r[i] = new Array<number>(384);
    }
    const t = new Array<number>(4);
    for (let aa = 0, i = 0; i < this._k; i++) {
      for (let j = 0; j < N / 4; j++) {
        t[0] = (uint16(a[aa + 0]) >> 0) | (uint16(a[aa + 1]) << 8);
        t[1] = (uint16(a[aa + 1]) >> 2) | (uint16(a[aa + 2]) << 6);
        t[2] = (uint16(a[aa + 2]) >> 4) | (uint16(a[aa + 3]) << 4);
        t[3] = (uint16(a[aa + 3]) >> 6) | (uint16(a[aa + 4]) << 2);
        aa = aa + 5;
        for (let k = 0; k < 4; k++) {
          r[i][4 * j + k] = int16(
            (((uint32(t[k] & 0x3FF)) * (uint32(Q))) + 512) >> 10,
          );
        }
      }
    }
    return r;
  }

  protected override _decompressV(a: Uint8Array): Array<number> {
    const r = new Array<number>(384);
    for (let aa = 0, i = 0; i < N / 2; i++, aa++) {
      r[2 * i + 0] = int16(((uint16(a[aa] & 15) * uint16(Q)) + 8) >> 4);
      r[2 * i + 1] = int16(((uint16(a[aa] >> 4) * uint16(Q)) + 8) >> 4);
    }
    return r;
  }
}

function byteopsCbd1(buf: Uint8Array, eta: number): Array<number> {
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
