// The parameter sets are plain literals, with no expression to evaluate, so
// that a bundler drops the ones which an application does not use.

/**
 * A parameter set of ML-DSA (FIPS 204, Table 1).
 */
export interface MlDsaParams {
  /** The number of rows of the matrix A. */
  readonly k: number;
  /** The number of columns of the matrix A. */
  readonly l: number;
  /** The private key range. */
  readonly eta: number;
  /** The number of +-1 in the challenge polynomial c. */
  readonly tau: number;
  /** The coefficient range of y is gamma1 = 2^gamma1Bits. */
  readonly gamma1Bits: number;
  /** The low-order rounding range. */
  readonly gamma2: number;
  /** The maximum number of 1 in the hint h. */
  readonly omega: number;
  /** The size of the commitment hash c~ in octets (lambda / 4). */
  readonly cTildeSize: number;
}

/** ML-DSA-44 (NIST security category 2). */
export const ML_DSA_44: MlDsaParams = {
  k: 4,
  l: 4,
  eta: 2,
  tau: 39,
  gamma1Bits: 17,
  gamma2: 95232, // (Q - 1) / 88
  omega: 80,
  cTildeSize: 32,
};

/** ML-DSA-65 (NIST security category 3). */
export const ML_DSA_65: MlDsaParams = {
  k: 6,
  l: 5,
  eta: 4,
  tau: 49,
  gamma1Bits: 19,
  gamma2: 261888, // (Q - 1) / 32
  omega: 55,
  cTildeSize: 48,
};

/** ML-DSA-87 (NIST security category 5). */
export const ML_DSA_87: MlDsaParams = {
  k: 8,
  l: 7,
  eta: 2,
  tau: 60,
  gamma1Bits: 19,
  gamma2: 261888, // (Q - 1) / 32
  omega: 75,
  cTildeSize: 64,
};
