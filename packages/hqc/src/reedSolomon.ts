/**
 * The shortened Reed-Solomon code of HQC (Section 3.5.2 of the HQC
 * specifications v5.1), which is the external code of the concatenated code.
 *
 * The decoder follows the constant-time one of the reference implementation
 * v5.1.0: the sequence of operations does not depend on the number or the
 * positions of the errors.
 */
import { GF_ALPHA, GF_MUL_ORDER } from "./consts.ts";
import { gfInverse, gfMul } from "./gf256.ts";

// alpha^e, for a public exponent e.
function alphaPow(e: number): number {
  let r = 1;
  for (let i = 0; i < e; i++) {
    r = gfMul(r, GF_ALPHA);
  }
  return r;
}

// 0xff if x != 0, 0 otherwise, for x in [0, 255].
function nonzeroMask(x: number): number {
  return (-x >> 8) & 0xff;
}

/**
 * The Reed-Solomon code [n1, k1, 2 * t1 + 1] with its working memory.
 */
export class ReedSolomon {
  private _n1: number;
  private _k1: number;
  private _t1: number;

  // rs_generator_polynomial: (X + alpha)(X + alpha^2)...(X + alpha^(2 * t1))
  private _generator: Uint8Array;
  // alpha^((i + 1) * j) for i in [0, 2 * t1) and j in [1, n1)
  private _alphaIjPow: Uint8Array;
  // beta^j for j in [1, t1], where beta = alpha^-(n1 - k1 + i) is the
  // inverse of the locator of the message position i in [0, k1)
  private _evalAlphaPow: Uint8Array;

  // Working memory of the decoder
  private _syndromes: Uint8Array;
  private _sigma: Uint8Array;
  private _sigmaMu: Uint8Array;
  private _xSigmaRho: Uint8Array;
  private _errorPositions: Uint8Array;
  private _z: Uint8Array;
  private _sigmaOdd: Uint8Array;

  constructor(n1: number, k1: number, t1: number) {
    this._n1 = n1;
    this._k1 = k1;
    this._t1 = t1;

    const g = new Uint8Array(2 * t1 + 1);
    g[0] = 1;
    for (let i = 1; i <= 2 * t1; i++) {
      const root = alphaPow(i);
      for (let j = i - 1; j > 0; j--) {
        g[j] = gfMul(g[j], root) ^ g[j - 1];
      }
      g[0] = gfMul(g[0], root);
      g[i] = 1;
    }
    this._generator = g;

    this._alphaIjPow = new Uint8Array(2 * t1 * (n1 - 1));
    for (let i = 0; i < 2 * t1; i++) {
      const base = alphaPow(i + 1);
      let p = 1;
      for (let j = 0; j < n1 - 1; j++) {
        p = gfMul(p, base);
        this._alphaIjPow[i * (n1 - 1) + j] = p;
      }
    }

    this._evalAlphaPow = new Uint8Array(k1 * t1);
    for (let i = 0; i < k1; i++) {
      const beta = alphaPow(GF_MUL_ORDER - (n1 - k1 + i));
      let p = 1;
      for (let j = 0; j < t1; j++) {
        p = gfMul(p, beta);
        this._evalAlphaPow[i * t1 + j] = p;
      }
    }

    this._syndromes = new Uint8Array(2 * t1);
    this._sigma = new Uint8Array(t1 + 1);
    this._sigmaMu = new Uint8Array(t1 + 1);
    this._xSigmaRho = new Uint8Array(t1 + 1);
    this._errorPositions = new Uint8Array(k1);
    this._z = new Uint8Array(t1 + 1);
    this._sigmaOdd = new Uint8Array(t1 + 1);
  }

  /**
   * RS.Encode: encodes a message of k1 octets to a codeword of n1 octets in
   * the systematic form, with a linear feedback shift register.
   */
  encode(cdw: Uint8Array, msg: Uint8Array): void {
    const n1 = this._n1;
    const k1 = this._k1;
    const g = this._generator;
    const r = n1 - k1;
    cdw.fill(0);
    for (let i = 0; i < k1; i++) {
      const gate = msg[k1 - 1 - i] ^ cdw[r - 1];
      for (let j = r - 1; j > 0; j--) {
        cdw[j] = cdw[j - 1] ^ gfMul(gate, g[j]);
      }
      cdw[0] = gfMul(gate, g[0]);
    }
    cdw.set(msg, r);
  }

  /**
   * RS.Decode: decodes a received word of n1 octets to a message of k1
   * octets. It is a deterministic best effort: no failure is signaled.
   */
  decode(msg: Uint8Array, cdw: Uint8Array): void {
    this._computeSyndromes(cdw);
    this._computeErrorLocatorPolynomial();
    this._computeErrorPositions();
    this._correctErrors(msg, cdw);
  }

  /** Wipes the working memory. */
  clear(): void {
    this._syndromes.fill(0);
    this._sigma.fill(0);
    this._sigmaMu.fill(0);
    this._xSigmaRho.fill(0);
    this._errorPositions.fill(0);
    this._z.fill(0);
    this._sigmaOdd.fill(0);
  }

  // RS.Decode.ComputeSyndromes: the syndrome i is the received word
  // evaluated at alpha^(i + 1).
  private _computeSyndromes(cdw: Uint8Array): void {
    const n1 = this._n1;
    const pows = this._alphaIjPow;
    const s = this._syndromes;
    for (let i = 0, p = 0; i < 2 * this._t1; i++) {
      let v = cdw[0];
      for (let j = 1; j < n1; j++, p++) {
        v ^= gfMul(cdw[j], pows[p]);
      }
      s[i] = v;
    }
  }

  // RS.Decode.ComputeErrorLocatorPolynomial: Berlekamp's algorithm, of which
  // every update is computed and then kept or dropped with a mask.
  private _computeErrorLocatorPolynomial(): void {
    const t1 = this._t1;
    const syndromes = this._syndromes;
    const sigma = this._sigma;
    const sigmaMu = this._sigmaMu;
    const xSigmaRho = this._xSigmaRho;
    let degSigma = 0;
    let degSigmaRho = 0;
    let rho = -1;
    let dRho = 1;
    let dMu = syndromes[0];

    sigma.fill(0);
    sigma[0] = 1;
    xSigmaRho.fill(0);
    xSigmaRho[1] = 1;

    for (let mu = 0; mu < 2 * t1; mu++) {
      // all ones if the discrepancy is not zero
      const dNonzeroMask = -dMu >> 31;
      const last = mu + 1 < t1 ? mu + 1 : t1;

      sigmaMu.set(sigma);
      const degSigmaMu = degSigma;

      const dMuOverDRho = gfMul(dMu, gfInverse(dRho));
      for (let i = 1; i <= last; i++) {
        sigma[i] ^= gfMul(dMuOverDRho, xSigmaRho[i]);
      }

      const degXSigmaRho = mu - rho + degSigmaRho;
      // all ones if the degree of sigma grows
      const promoteMask = dNonzeroMask & ((degSigmaMu - degXSigmaRho) >> 31);

      degSigma ^= promoteMask & (degXSigmaRho ^ degSigma);
      for (let i = t1; i > 0; i--) {
        xSigmaRho[i] = (promoteMask & sigmaMu[i - 1]) ^
          (~promoteMask & xSigmaRho[i - 1]);
      }
      degSigmaRho ^= promoteMask & (degSigmaMu ^ degSigmaRho);
      rho ^= promoteMask & (mu ^ rho);
      dRho ^= promoteMask & (dMu ^ dRho);

      if (mu + 1 < 2 * t1) {
        dMu = syndromes[mu + 1];
        for (let i = 1; i <= last; i++) {
          dMu ^= gfMul(sigma[i], syndromes[mu + 1 - i]);
        }
      }
    }
  }

  // Evaluates a polynomial of degree at most t1 at the inverse of the
  // locator of the message position i.
  private _evaluate(poly: Uint8Array, i: number): number {
    const t1 = this._t1;
    const pows = this._evalAlphaPow;
    let v = poly[0];
    for (let j = 1, p = i * t1; j <= t1; j++, p++) {
      v ^= gfMul(poly[j], pows[p]);
    }
    return v;
  }

  // RS.Decode.ComputeErrorPositions: a message position has an error if the
  // inverse of its locator is a root of sigma.
  private _computeErrorPositions(): void {
    const e = this._errorPositions;
    for (let i = 0; i < this._k1; i++) {
      e[i] = (nonzeroMask(this._evaluate(this._sigma, i)) & 1) ^ 1;
    }
  }

  // RS.Decode.CorrectErrors: computes the error values of the message
  // positions with Forney's algorithm, and corrects them.
  private _correctErrors(msg: Uint8Array, cdw: Uint8Array): void {
    const t1 = this._t1;
    const k1 = this._k1;
    const syndromes = this._syndromes;
    const sigma = this._sigma;
    const z = this._z;
    const sigmaOdd = this._sigmaOdd;
    const offset = this._n1 - k1;

    // the error-evaluator polynomial
    z[0] = 1;
    for (let i = 0; i < t1; i++) {
      let v = syndromes[i];
      for (let j = 0; j < i; j++) {
        v ^= gfMul(sigma[j + 1], syndromes[i - 1 - j]);
      }
      z[i + 1] = v ^ sigma[i + 1];
    }

    // X times the formal derivative of sigma
    sigmaOdd.fill(0);
    for (let i = 1; i <= t1; i += 2) {
      sigmaOdd[i] = sigma[i];
    }

    for (let i = 0; i < k1; i++) {
      const numerator = this._evaluate(z, i);
      const denominator = this._evaluate(sigmaOdd, i);
      const valid = nonzeroMask(this._errorPositions[i]) &
        nonzeroMask(denominator);
      msg[i] = cdw[offset + i] ^
        (valid & gfMul(numerator, gfInverse(denominator)));
    }
  }
}
