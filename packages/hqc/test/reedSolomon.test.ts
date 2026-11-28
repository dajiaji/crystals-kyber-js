import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

import { ReedSolomon } from "../src/reedSolomon.ts";
import { HQC_PARAMS } from "./params.ts";
import { parseRsTv, testVectorPath } from "./utils.ts";

type Internals = {
  _generator: Uint8Array;
  _alphaIjPow: Uint8Array;
  _evalAlphaPow: Uint8Array;
  _syndromes: Uint8Array;
  _sigma: Uint8Array;
  _errorPositions: Uint8Array;
};

// The generator polynomials of the shortened Reed-Solomon codes, from the
// lowest degree (HQC specifications v5.1, Section 3.5.2).
// deno-fmt-ignore
const GENERATOR_POLYNOMIALS: { [name: string]: number[] } = {
  "HQC-1": [
    74, 81, 224, 114, 221, 115, 110, 88, 91, 151, 139, 151, 84, 184, 21, 242,
    97, 199, 87, 113, 104, 184, 197, 111, 89, 81, 156, 71, 128, 217, 1,
  ],
  "HQC-3": [
    56, 180, 145, 30, 131, 105, 28, 60, 107, 33, 206, 184, 155, 249, 153, 231,
    112, 11, 231, 1, 144, 201, 71, 62, 8, 150, 142, 246, 33, 214, 26, 150, 1,
  ],
  "HQC-5": [
    35, 203, 35, 52, 165, 121, 125, 73, 136, 42, 235, 82, 232, 122, 67, 98,
    51, 188, 230, 82, 164, 117, 103, 184, 209, 218, 244, 181, 122, 10, 25, 138,
    216, 182, 225, 145, 100, 244, 5, 142, 213, 238, 15, 150, 59, 28, 244, 222,
    252, 85, 125, 59, 52, 215, 180, 34, 173, 208, 1,
  ],
};

// The head of the tables of the reference implementation v5.1.0
// (src/ref/hqc-*/reed_solomon.h): alpha_ij_pow[0], and the row 0 of
// eval_alpha_pow.
// deno-fmt-ignore
const TABLE_HEADS: { [name: string]: { alphaIjPow: number[]; evalAlphaPow: number[] } } = {
  "HQC-1": {
    alphaIjPow: [3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53],
    // beta = alpha^225
    evalAlphaPow: [
      0x36, 0x63, 0xef, 0xc2, 0x1d, 0x08, 0xab, 0x35, 0x39, 0x4a, 0xe8, 0x40,
      0x2f, 0xb3, 0xd3,
    ],
  },
};

HQC_PARAMS.forEach((params) =>
  describe(`${params.name}: Reed-Solomon code`, () => {
    const create = () => new ReedSolomon(params.n1, params.k1, params.t1);

    it("should have the generator polynomial of the specifications", () => {
      const rs = create() as unknown as Internals;
      assertEquals(
        Array.from(rs._generator),
        GENERATOR_POLYNOMIALS[params.name],
      );
    });

    it("should have the tables of the reference implementation", () => {
      const head = TABLE_HEADS[params.name];
      if (head === undefined) return;
      const rs = create() as unknown as Internals;
      assertEquals(
        Array.from(rs._alphaIjPow.subarray(0, head.alphaIjPow.length)),
        head.alphaIjPow,
      );
      assertEquals(
        Array.from(rs._evalAlphaPow.subarray(0, head.evalAlphaPow.length)),
        head.evalAlphaPow,
      );
    });

    // The official test vectors of the HQC team: 100 samples for each of 8
    // scenarios, from no error to a fully corrupted codeword, with the
    // values of every step of the decoder. See ./vectors/README.md.
    it("should match the test vectors", async () => {
      const samples = parseRsTv(
        await Deno.readTextFile(
          `${testVectorPath()}/rs/${params.dir}/rs.tv`,
        ),
      );
      assertEquals(samples.length, 800);
      const scenarios = [...new Set(samples.map((s) => s.scenario))];
      assertEquals(scenarios, [
        "clean_codeword_no_errors",
        "message_part_errors_only",
        "exactly_t1_errors_message_part_only",
        "parity_part_errors_only",
        "message_and_parity_errors_mixed",
        "exactly_t1_errors_any_position",
        "exceeds_t1_errors_any_position",
        "full_codeword_corruption",
      ]);
      console.log(
        `${params.name} Reed-Solomon test vector count: ${samples.length}`,
      );

      const rs = create();
      const internals = rs as unknown as Internals;
      const cdw = new Uint8Array(params.n1);
      const msg = new Uint8Array(params.k1);
      for (const sample of samples) {
        rs.encode(cdw, sample.message);
        assertEquals(cdw, sample.codeword);

        rs.decode(msg, sample.corrupted);
        assertEquals(internals._syndromes, sample.syndromes);
        assertEquals(internals._sigma, sample.sigma);
        assertEquals(internals._errorPositions, sample.errorPositions);
        assertEquals(msg, sample.decoded);
      }
    });

    it("should correct up to t1 errors at any positions", () => {
      const rs = create();
      const msg = new Uint8Array(params.k1);
      const cdw = new Uint8Array(params.n1);
      const decoded = new Uint8Array(params.k1);
      const rnd = new Uint8Array(2);
      for (let round = 0; round < 50; round++) {
        globalThis.crypto.getRandomValues(msg);
        rs.encode(cdw, msg);
        assertEquals(cdw.subarray(params.n1 - params.k1), msg);

        // distinct positions, each with a nonzero error value
        const weight = round % (params.t1 + 1);
        const positions = new Set<number>();
        while (positions.size < weight) {
          globalThis.crypto.getRandomValues(rnd);
          const pos = rnd[0] % params.n1;
          if (positions.has(pos)) continue;
          positions.add(pos);
          cdw[pos] ^= 1 + (rnd[1] % 255);
        }
        rs.decode(decoded, cdw);
        assertEquals(decoded, msg);
      }
    });

    it("should wipe its working memory", () => {
      const rs = create();
      const internals = rs as unknown as { [key: string]: Uint8Array };
      const cdw = new Uint8Array(params.n1).fill(0x5a);
      rs.decode(new Uint8Array(params.k1), cdw);
      const working = [
        "_syndromes",
        "_sigma",
        "_sigmaMu",
        "_xSigmaRho",
        "_errorPositions",
        "_z",
        "_sigmaOdd",
      ];
      assertEquals(
        working.some((key) => internals[key].some((x) => x !== 0)),
        true,
      );
      rs.clear();
      for (const key of working) {
        assertEquals(internals[key].every((x) => x === 0), true, key);
      }
    });
  })
);
