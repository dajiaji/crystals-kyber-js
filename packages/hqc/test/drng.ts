import { createCipheriv } from "node:crypto";

import type { HqcInterface } from "../mod.ts";

type GetRandomValuesInputType = Parameters<
  typeof Crypto.prototype.getRandomValues
>[0];

/**
 * The deterministic random bit generator of the NIST KAT generator (rng.c of
 * PQCgenKAT): CTR_DRBG with AES-256, without a derivation function, a
 * personalization string or prediction resistance (NIST SP 800-90A).
 *
 * The official KAT files of HQC are generated with it.
 */
export class NistDrbg {
  private _key = new Uint8Array(32);
  private _v = new Uint8Array(16);

  /**
   * @param entropy A 48-octet entropy input (`seed` in a KAT file).
   */
  constructor(entropy: Uint8Array) {
    if (entropy.length !== 48) {
      throw new Error("entropy must be 48 bytes in length");
    }
    this._update(entropy);
  }

  /** randombytes(): fills the buffer with the next octets. */
  fill(out: Uint8Array): void {
    for (let i = 0; i < out.length; i += 16) {
      const block = this._nextBlock();
      out.set(block.subarray(0, Math.min(16, out.length - i)), i);
    }
    this._update();
  }

  // AES256_ECB(Key, ++V)
  private _nextBlock(): Uint8Array {
    for (let j = 15; j >= 0; j--) {
      if (this._v[j] === 0xff) {
        this._v[j] = 0x00;
      } else {
        this._v[j]++;
        break;
      }
    }
    const cipher = createCipheriv("aes-256-ecb", this._key, null);
    cipher.setAutoPadding(false);
    return new Uint8Array(cipher.update(this._v));
  }

  // AES256_CTR_DRBG_Update
  private _update(providedData?: Uint8Array): void {
    const temp = new Uint8Array(48);
    for (let i = 0; i < 3; i++) {
      temp.set(this._nextBlock(), 16 * i);
    }
    if (providedData !== undefined) {
      for (let i = 0; i < 48; i++) {
        temp[i] ^= providedData[i];
      }
    }
    this._key = temp.slice(0, 32);
    this._v = temp.slice(32, 48);
  }
}

/**
 * Replaces the random number generator of an instance with a function which
 * fills a buffer.
 */
export function setRandom<T extends HqcInterface>(
  ctx: T,
  fill: (buffer: Uint8Array) => void,
): T {
  (ctx as unknown as { _api: Crypto })._api = {
    getRandomValues: <B extends GetRandomValuesInputType>(buffer: B) => {
      if (!(buffer instanceof Uint8Array)) throw new Error("Unsupported");
      fill(buffer);
      return buffer;
    },
  } as Crypto;
  return ctx;
}
