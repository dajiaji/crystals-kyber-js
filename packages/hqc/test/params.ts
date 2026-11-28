import { createHqc1, createHqc3, createHqc5 } from "../mod.ts";
import type { HqcInterface } from "../mod.ts";
import { Hqc1Impl } from "../src/hqc1.ts";
import { Hqc3Impl } from "../src/hqc3.ts";
import { Hqc5Impl } from "../src/hqc5.ts";

/**
 * A parameter set of HQC with the values of the HQC specifications v5.1
 * (Tables 4, 6, 7, 8 and 9), which the tests check the implementation
 * against.
 */
export interface HqcTestParams {
  /** The name of the parameter set. */
  name: string;
  /** The directory of its test vectors. */
  dir: string;
  create: () => Promise<HqcInterface>;
  Impl: new () => HqcInterface;
  n: number;
  n1: number;
  /** The multiplicity of the duplicated Reed-Muller code. */
  multiplicity: number;
  k1: number;
  t1: number;
  omega: number;
  omegaR: number;
  omegaE: number;
  maskN: number;
  rejectionThreshold: number;
  pkSize: number;
  skSize: number;
  ctSize: number;
  ssSize: number;
}

export const HQC_PARAMS: HqcTestParams[] = [
  {
    name: "HQC-1",
    dir: "hqc-1",
    create: createHqc1,
    Impl: Hqc1Impl,
    n: 17669,
    n1: 46,
    multiplicity: 3,
    k1: 16,
    t1: 15,
    omega: 67,
    omegaR: 76,
    omegaE: 76,
    maskN: 0x1f,
    rejectionThreshold: 16767881,
    pkSize: 2241,
    skSize: 32,
    ctSize: 4433,
    ssSize: 32,
  },
  {
    name: "HQC-3",
    dir: "hqc-3",
    create: createHqc3,
    Impl: Hqc3Impl,
    n: 35851,
    n1: 56,
    multiplicity: 5,
    k1: 24,
    t1: 16,
    omega: 101,
    omegaR: 114,
    omegaE: 114,
    maskN: 0x07,
    rejectionThreshold: 16742417,
    pkSize: 4514,
    skSize: 32,
    ctSize: 8978,
    ssSize: 32,
  },
  {
    name: "HQC-5",
    dir: "hqc-5",
    create: createHqc5,
    Impl: Hqc5Impl,
    n: 57637,
    n1: 90,
    multiplicity: 5,
    k1: 32,
    t1: 29,
    omega: 132,
    omegaR: 150,
    omegaE: 150,
    maskN: 0x1f,
    rejectionThreshold: 16772367,
    pkSize: 7237,
    skSize: 32,
    ctSize: 14421,
    ssSize: 32,
  },
];
