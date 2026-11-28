/**
 * The constants shared by all the parameter sets of HQC. See Table 2 of the
 * HQC specifications v5.1 (https://pqc-hqc.org).
 */

/** The size of the seeds in octets. */
export const SEED_BYTES = 32;

/** The size of the salt in octets. */
export const SALT_BYTES = 16;

/** The size of the shared secret in octets. */
export const SHARED_SECRET_BYTES = 32;

/** The domain separator of the hash function G (SHA3-512). */
export const G_DOMAIN = 0x00;

/** The domain separator of the hash function H (SHA3-256). */
export const H_DOMAIN = 0x01;

/** The domain separator of the hash function I (SHA3-512). */
export const I_DOMAIN = 0x02;

/** The domain separator of the hash function J (SHA3-256). */
export const J_DOMAIN = 0x03;

/** The primitive element alpha of the field with 2^8 elements. */
export const GF_ALPHA = 0x03;

/** The order of the multiplicative group of the field with 2^8 elements. */
export const GF_MUL_ORDER = 255;

/** The length of the RM(1, 7) code in bits (n3). */
export const RM_N3 = 128;
