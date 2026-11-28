/**
 * Algorithms to benchmark.
 *
 * Each library side is described as `[package, exportName]`.
 *
 * - `webpqc`: the packages of this repository, bundled from their sources.
 *   `@webpqc/mldsa` has a factory function per role: the signer does key
 *   generation and signing, and the verifier only verification.
 * - `noble`: `@noble/post-quantum`, the pure JavaScript implementation which
 *   is most widely used.
 */

/** `[package, exportName]` */
export type Import = readonly [pkg: string, name: string];

/** A key encapsulation mechanism or a digital signature algorithm. */
export type Kind = "kem" | "dsa";

export const ROLES = {
  kem: ["keygen", "encap", "decap"],
  dsa: ["keygen", "sign", "verify"],
} as const satisfies Record<Kind, readonly string[]>;
export type Role = (typeof ROLES)[Kind][number];

export interface Suite {
  readonly id: string;
  readonly label: string;
  readonly kind: Kind;
  /** The factory function which the application of the role uses. */
  readonly webpqc: (role: Role) => Import;
  readonly noble: Import;
}

const WEBPQC_ML_KEM = "@webpqc/mlkem";
const WEBPQC_ML_DSA = "@webpqc/mldsa";

/** One factory function for all the roles. */
const mlKem = (size: number) => (): Import => [
  WEBPQC_ML_KEM,
  `createMlKem${size}`,
];

/** The verifier for `verify`, and the signer for the other roles. */
const mlDsa = (size: number) => (role: Role): Import => [
  WEBPQC_ML_DSA,
  `createMlDsa${size}${role === "verify" ? "Verifier" : "Signer"}`,
];

const NOBLE_ML_KEM = "@noble/post-quantum/ml-kem.js";
const NOBLE_ML_DSA = "@noble/post-quantum/ml-dsa.js";

export const SUITES: readonly Suite[] = [
  {
    id: "mlkem512",
    label: "ML-KEM-512",
    kind: "kem",
    webpqc: mlKem(512),
    noble: [NOBLE_ML_KEM, "ml_kem512"],
  },
  {
    id: "mlkem768",
    label: "ML-KEM-768",
    kind: "kem",
    webpqc: mlKem(768),
    noble: [NOBLE_ML_KEM, "ml_kem768"],
  },
  {
    id: "mlkem1024",
    label: "ML-KEM-1024",
    kind: "kem",
    webpqc: mlKem(1024),
    noble: [NOBLE_ML_KEM, "ml_kem1024"],
  },
  {
    id: "mldsa44",
    label: "ML-DSA-44",
    kind: "dsa",
    webpqc: mlDsa(44),
    noble: [NOBLE_ML_DSA, "ml_dsa44"],
  },
  {
    id: "mldsa65",
    label: "ML-DSA-65",
    kind: "dsa",
    webpqc: mlDsa(65),
    noble: [NOBLE_ML_DSA, "ml_dsa65"],
  },
  {
    id: "mldsa87",
    label: "ML-DSA-87",
    kind: "dsa",
    webpqc: mlDsa(87),
    noble: [NOBLE_ML_DSA, "ml_dsa87"],
  },
];
