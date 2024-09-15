/**
 * This implementation is based on https://github.com/antontutoveanu/crystals-kyber-javascript,
 * which was deveploped under the MIT licence below:
 * https://github.com/antontutoveanu/crystals-kyber-javascript/blob/main/LICENSE
 */
import { N } from "./consts.ts";
import { KyberBase } from "./kyberBase.ts";

/**
 * Represents the MlKem768 class, which extends the KyberBase class.
 *
 * MlKem768 is a specific implementation of the Kyber key encapsulation mechanism.
 *
 * @remarks
 *
 * This class extends the KyberBase class and provides specific implementation for MlKem768.
 *
 * @example
 *
 * ```ts
 * // import { MlKem768 } from "crystals-kyber-js"; // Node.js
 * import { MlKem768 } from "http://deno.land/x/crystals_kyber/mod.ts"; // Deno
 *
 * const recipient = new MlKem768();
 * const [pkR, skR] = await recipient.generateKeyPair();
 *
 * const sender = new MlKem768();
 * const [ct, ssS] = await sender.encap(pkR);
 *
 * const ssR = await recipient.decap(ct, skR);
 * // ssS === ssR
 * ```
 */
export class MlKem768 extends KyberBase {
  protected _k = 3;
  protected _du = 10;
  protected _dv = 4;
  protected _eta1 = 2;
  protected _eta2 = 2;

  constructor() {
    super();
    this._skSize = 12 * this._k * N / 8;
    this._pkSize = this._skSize + 32;
    this._compressedUSize = this._k * this._du * N / 8;
    this._compressedVSize = this._dv * N / 8;
  }
}
