import { assertEquals, assertRejects } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import * as fs from "node:fs";
import * as readline from "node:readline";
import { shake128 } from "../src/deps.ts";

import { MlKem1024, MlKem512, MlKem768, MlKemError } from "../mod.ts";
import { loadCrypto } from "../src/utils.ts";
import { bytesToHex, hexToBytes, parseKAT, testVectorPath } from "./utils.ts";
import { getDeterministicMlKemClass } from "./drng.ts";

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const ret = new Uint8Array(a.length + b.length);
  ret.set(a, 0);
  ret.set(b, a.length);
  return ret;
}

[MlKem512, MlKem768, MlKem1024].forEach((MlKemClass) =>
  describe(MlKemClass.name, () => {
    const size = MlKemClass.name.substring(5);
    const DeterministicMlKemClass = getDeterministicMlKemClass(MlKemClass);

    describe("A sample code in README.", () => {
      it("should work normally", async () => {
        const recipient = new MlKemClass();
        const [pkR, skR] = await recipient.generateKeyPair();

        const sender = new MlKemClass();
        const [ct, ssS] = await sender.encap(pkR);

        const ssR = await recipient.decap(ct, skR);

        assertEquals(ssS, ssR);
      });

      it("should work normally with deriveKeyPair", async () => {
        const recipient = new MlKemClass();
        const api = await loadCrypto();
        const seed = new Uint8Array(64);
        api.getRandomValues(seed);
        const [pkR, skR] = await recipient.deriveKeyPair(seed);
        const [pkR2, skR2] = await recipient.deriveKeyPair(seed);
        assertEquals(pkR, pkR2);
        assertEquals(skR, skR2);

        const sender = new MlKemClass();
        const [ct, ssS] = await sender.encap(pkR);

        const ssR = await recipient.decap(ct, skR);

        assertEquals(ssS, ssR);
      });
    });

    describe("KAT vectors", () => {
      it("should match expected values", async () => {
        const kyber = new MlKemClass();
        const katData = await Deno.readTextFile(
          `${testVectorPath()}/kat/kat_MLKEM_${size}.rsp`,
        );
        const { z, d, ct, sk, ss, msg, pk } = parseKAT(katData);
        console.log(`KAT test vector count: ${sk.length}`);

        for (let i = 0; i < sk.length; i++) {
          const [pkActual, skActual] = await kyber.deriveKeyPair(
            concat(d[i], z[i]),
          );
          assertEquals(pkActual, pk[i]);
          assertEquals(skActual, sk[i]);

          const ssDecapActual = await kyber.decap(ct[i], sk[i]);
          assertEquals(ssDecapActual, ss[i]);

          const [ctActual, ssEncapActual] = await kyber.encap(pk[i], msg[i]);
          assertEquals(ctActual, ct[i]);
          assertEquals(ssEncapActual, ss[i]);
        }
      });
    });

    describe("CCTV/ML-KEM/modulus", () => {
      it("Invalid encapsulation keys", async () => {
        const sender = new MlKemClass();
        const rl = readline.createInterface({
          input: fs.createReadStream(
            `${testVectorPath()}/modulus/ML-KEM-${size}.txt`,
          ),
          crlfDelay: Infinity,
        });
        try {
          let count = 0;
          for await (const line of rl) {
            const invalidPk = hexToBytes(line);
            await assertRejects(
              () => sender.encap(invalidPk),
              MlKemError,
              "invalid encapsulation key",
            );
            count++;
          }
          console.log(`CCTV/ML-KEM/modulus test vector count: ${count}`);
        } catch (e) {
          console.error(e);
        } finally {
          rl.close();
        }
      });
    });

    describe("CCTV/ML-KEM/strcmp", () => {
      it("strcmp vectors that fail strcmp() is used in decap.", async () => {
        const kyber = new MlKemClass();
        const testData = await Deno.readTextFile(
          `${testVectorPath()}/strcmp/ML-KEM-${size}.txt`,
        );
        const { c: [ct], dk: [sk], K: [ss] } = parseKAT(testData);
        const res = await kyber.decap(ct, sk);
        assertEquals(res, ss);
        console.log("CCTV/ML-KEM/strcmp test vector count: 1");
      });
    });

    describe("CCTV/ML-KEM/unluckysample", () => {
      it("Unlucky NTT sampling vectors that require an unusually large number of XOF reads", async () => {
        const kyber = new MlKemClass();
        const testData = await Deno.readTextFile(
          `${testVectorPath()}/unluckysample/ML-KEM-${size}.txt`,
        );
        const { c: [ct], dk: [sk], K: [ss] } = parseKAT(testData);
        const res = await kyber.decap(ct, sk);
        assertEquals(res, ss);
        console.log("CCTV/ML-KEM/unluckysample test vector count: 1");
      });
    });

    describe("pq-crystals/kyber", () => {
      it("Accumulated vectors", async () => { // See https://github.com/C2SP/CCTV/blob/main/ML-KEM/README.md#accumulated-pq-crystals-vectors
        const deterministicMlKem = new DeterministicMlKemClass();
        const shakeInstance = shake128.create({ dkLen: 32 });
        /**
         * For each test, the following values are drawn from the RNG in order:
         *
         * d for K-PKE.KeyGen
         * z for ML-KEM.KeyGen
         * m for ML-KEM.Encaps
         * ct as an invalid ciphertext input to ML-KEM.Decaps
         * Then, the following values are written to a running SHAKE-128 instance in order:
         *
         * ek from ML-KEM.KeyGen
         * dk from ML-KEM.KeyGen
         * ct from ML-KEM.Encaps
         * k from ML-KEM.Encaps (which should be checked to match the output of ML-KEM.Decaps when provided with the correct ct)
         * k from ML-KEM.Decaps when provided with the random ct
         * The resulting hashes for 10 000 consecutive tests are:
         */
        const count = 100;
        const expectedHashes: { [key: string]: string } = {
          "MlKem512":
            "449120c6e320ef3e9fbfa2316e5f2d2e1e6dd37d8ff5d086d5d2db7d42aff0a1",
          "MlKem768":
            "8d65b902f28edc683cebee2872962fd165a4d197c9e24ec74caa4470270df0b7",
          "MlKem1024":
            "c3ffe9ebecfa479c142656cbfbc6417efa05b77e994fe538eef4daed166363df",
        };
        // const count = 10000;
        // const expectedHashes: { [key: string]: string } = {
        //   "MlKem512":
        //     "705dcffc87f4e67e35a09dcaa31772e86f3341bd3ccf1e78a5fef99ae6a35a13",
        //   "MlKem768":
        //     "f959d18d3d1180121433bf0e05f11e7908cf9d03edc150b2b07cb90bef5bc1c1",
        //   "MlKem1024":
        //     "e3bf82b013307b2e9d47dde791ff6dfc82e694e6382404abdb948b908b75bad5",
        // };
        // const count = 1000000;
        // const expectedHashes: { [key: string]: string } = {
        //   "MlKem512":
        //     "21dd330d4355f2ae2876b9fa2b9de62ecaf76aca1d598de8db2b467d36e36a6a",
        //   "MlKem768":
        //     "3b108396a277f2952ff3243a985c9709bcb95788c39b7b36a2c4e19d1a41e51e",
        //   "MlKem1024":
        //     "6377c4f0ecfdb32e63f7b58227960828784fe0b3e0e5e5e9f77be300f003512a",
        // };
        console.log("pq-crystals/kyber test vector count:", count);

        for (let i = 0; i < count; i++) {
          const [ek, dk] = await deterministicMlKem.generateKeyPair();
          const [ct, k] = await deterministicMlKem.encap(ek);
          const kActual = await deterministicMlKem.decap(ct, dk);
          assertEquals(kActual, k);
          // sample random, invalid ct
          // @ts-ignore private accessor
          const ctRandom = deterministicMlKem._api!.getRandomValues(
            new Uint8Array(ct.length),
          );
          const kRandom = await deterministicMlKem.decap(ctRandom, dk);
          // hash results
          shakeInstance.update(ek)
            .update(dk)
            .update(ct)
            .update(k)
            .update(kRandom);
        }
        const actualHash = shakeInstance.digest();
        assertEquals(bytesToHex(actualHash), expectedHashes[MlKemClass.name]);
      });
    });
  })
);
