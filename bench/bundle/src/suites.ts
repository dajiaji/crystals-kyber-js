/**
 * Algorithms to benchmark.
 *
 * Each library side is described as `[package, exportName]`.
 *
 * - `webpqc`: the packages of this repository, bundled from their sources.
 * - `noble`: `@noble/post-quantum`, the pure JavaScript implementation which
 *   is most widely used.
 */

/** `[package, exportName]` */
export type Import = readonly [pkg: string, name: string];

/** A key encapsulation mechanism or a digital signature algorithm. */
export type Kind = "kem" | "dsa";

export interface Suite {
  readonly id: string;
  readonly label: string;
  readonly kind: Kind;
  readonly webpqc: Import;
  readonly noble: Import;
}

const NOBLE_ML_KEM = "@noble/post-quantum/ml-kem.js";
const NOBLE_ML_DSA = "@noble/post-quantum/ml-dsa.js";

export const SUITES: readonly Suite[] = [
  {
    id: "mlkem512",
    label: "ML-KEM-512",
    kind: "kem",
    webpqc: ["@webpqc/mlkem", "createMlKem512"],
    noble: [NOBLE_ML_KEM, "ml_kem512"],
  },
  {
    id: "mlkem768",
    label: "ML-KEM-768",
    kind: "kem",
    webpqc: ["@webpqc/mlkem", "createMlKem768"],
    noble: [NOBLE_ML_KEM, "ml_kem768"],
  },
  {
    id: "mlkem1024",
    label: "ML-KEM-1024",
    kind: "kem",
    webpqc: ["@webpqc/mlkem", "createMlKem1024"],
    noble: [NOBLE_ML_KEM, "ml_kem1024"],
  },
  {
    id: "mldsa44",
    label: "ML-DSA-44",
    kind: "dsa",
    webpqc: ["@webpqc/mldsa", "createMlDsa44"],
    noble: [NOBLE_ML_DSA, "ml_dsa44"],
  },
  {
    id: "mldsa65",
    label: "ML-DSA-65",
    kind: "dsa",
    webpqc: ["@webpqc/mldsa", "createMlDsa65"],
    noble: [NOBLE_ML_DSA, "ml_dsa65"],
  },
  {
    id: "mldsa87",
    label: "ML-DSA-87",
    kind: "dsa",
    webpqc: ["@webpqc/mldsa", "createMlDsa87"],
    noble: [NOBLE_ML_DSA, "ml_dsa87"],
  },
];
