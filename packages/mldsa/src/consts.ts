export const N = 256;

export const Q = 8380417;

// Q^-1 mod 2^32
export const Q_INV = 58728449;

// The number of dropped bits from t.
export const D = 13;

// 2^32 mod Q, the Montgomery factor R.
const MONT_R = 4193792;

// A primitive 512th root of unity modulo Q.
const ROOT_OF_UNITY = 1753;

// Products of two values below Q stay below 2^46, so they are exact in a
// double. This is only used on the public constants below.
function mulModQ(a: number, b: number): number {
  return (a * b) % Q;
}

function center(a: number): number {
  return a > (Q - 1) / 2 ? a - Q : a;
}

/**
 * ZETAS[k] = R * ROOT_OF_UNITY^brv8(k) mod Q in Montgomery form, as centered
 * representatives. ZETAS[0] is never used.
 */
export const NTT_ZETAS: Int32Array = /* @__PURE__ */ (() => {
  const powers = new Array<number>(N);
  powers[0] = 1;
  for (let i = 1; i < N; i++) {
    powers[i] = mulModQ(powers[i - 1], ROOT_OF_UNITY);
  }
  const zetas = new Int32Array(N);
  for (let k = 1; k < N; k++) {
    let brv = 0;
    for (let b = 0; b < 8; b++) {
      brv |= ((k >> b) & 1) << (7 - b);
    }
    zetas[k] = center(mulModQ(powers[brv], MONT_R));
  }
  return zetas;
})();

// R^2 / 256 mod Q, which the inverse NTT multiplies by at the end.
// 256^-1 mod Q = Q - (Q - 1) / 256.
export const INV_NTT_F: number = /* @__PURE__ */ mulModQ(
  /* @__PURE__ */ mulModQ(MONT_R, MONT_R),
  Q - (Q - 1) / 256,
);
