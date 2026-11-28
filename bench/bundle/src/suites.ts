/**
 * Algorithms to benchmark.
 *
 * Each library side is described as `[package, exportName]`.
 *
 * - `webpqc`: the packages of this repository, bundled from their sources.
 *   `@webpqc/mldsa` has a factory function per role: the signer does key
 *   generation and signing, and the verifier only verification.
 * - `noble`: `@noble/post-quantum`, the pure JavaScript implementation which
 *   is most widely used. It does not implement HQC, so the HQC suites are
 *   measured for `@webpqc/hqc` only.
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
  /** The size in bytes of the seed which a key pair is derived from. */
  readonly seedSize: number;
  /** The factory function which the application of the role uses. */
  readonly webpqc: (role: Role) => Import;
  /** Absent if `@noble/post-quantum` does not implement the algorithm. */
  readonly noble?: Import;
}

const WEBPQC_ML_KEM = "@webpqc/mlkem";
const WEBPQC_ML_DSA = "@webpqc/mldsa";
const WEBPQC_HQC = "@webpqc/hqc";

/** ML-KEM.KeyGen_internal takes d || z. */
const ML_KEM_SEED_SIZE = 64;
/** ML-DSA.KeyGen_internal takes xi. */
const ML_DSA_SEED_SIZE = 32;
/** HQC-KEM.Keygen derives a key pair from seed_kem. */
const HQC_SEED_SIZE = 32;

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

/** One factory function for all the roles. */
const hqc = (level: number) => (): Import => [
  WEBPQC_HQC,
  `createHqc${level}`,
];

const NOBLE_ML_KEM = "@noble/post-quantum/ml-kem.js";
const NOBLE_ML_DSA = "@noble/post-quantum/ml-dsa.js";

export const SUITES: readonly Suite[] = [
  {
    id: "mlkem512",
    label: "ML-KEM-512",
    kind: "kem",
    seedSize: ML_KEM_SEED_SIZE,
    webpqc: mlKem(512),
    noble: [NOBLE_ML_KEM, "ml_kem512"],
  },
  {
    id: "mlkem768",
    label: "ML-KEM-768",
    kind: "kem",
    seedSize: ML_KEM_SEED_SIZE,
    webpqc: mlKem(768),
    noble: [NOBLE_ML_KEM, "ml_kem768"],
  },
  {
    id: "mlkem1024",
    label: "ML-KEM-1024",
    kind: "kem",
    seedSize: ML_KEM_SEED_SIZE,
    webpqc: mlKem(1024),
    noble: [NOBLE_ML_KEM, "ml_kem1024"],
  },
  {
    id: "mldsa44",
    label: "ML-DSA-44",
    kind: "dsa",
    seedSize: ML_DSA_SEED_SIZE,
    webpqc: mlDsa(44),
    noble: [NOBLE_ML_DSA, "ml_dsa44"],
  },
  {
    id: "mldsa65",
    label: "ML-DSA-65",
    kind: "dsa",
    seedSize: ML_DSA_SEED_SIZE,
    webpqc: mlDsa(65),
    noble: [NOBLE_ML_DSA, "ml_dsa65"],
  },
  {
    id: "mldsa87",
    label: "ML-DSA-87",
    kind: "dsa",
    seedSize: ML_DSA_SEED_SIZE,
    webpqc: mlDsa(87),
    noble: [NOBLE_ML_DSA, "ml_dsa87"],
  },
  {
    id: "hqc1",
    label: "HQC-1",
    kind: "kem",
    seedSize: HQC_SEED_SIZE,
    webpqc: hqc(1),
  },
  {
    id: "hqc3",
    label: "HQC-3",
    kind: "kem",
    seedSize: HQC_SEED_SIZE,
    webpqc: hqc(3),
  },
  {
    id: "hqc5",
    label: "HQC-5",
    kind: "kem",
    seedSize: HQC_SEED_SIZE,
    webpqc: hqc(5),
  },
];
