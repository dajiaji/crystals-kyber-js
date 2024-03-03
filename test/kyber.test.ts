import { describe, it } from "testing/bdd.ts";
import {
  assertEquals,
  assertRejects,
} from "https://deno.land/std@0.216.0/assert/mod.ts";
import { shake128 } from "../src/deps.ts";

import { MlKem1024, MlKem512, MlKem768, MlKemError } from "../mod.ts";
import { loadCrypto } from "../src/utils.ts";
import { parseKAT, testVectorPath } from "./utils.ts";
import { bytesToHex, hexToBytes } from "./utils.ts";
import { getDeterministicKyberClass } from "./drng.ts";

[MlKem512, MlKem768, MlKem1024].forEach((KyberClass) =>
  describe(KyberClass.name, () => {
    const size = KyberClass.name.substring(5);
    const DeterministicKyberClass = getDeterministicKyberClass(KyberClass);

    describe("KAT vectors", () => {
      it("should match expected values", async () => {
        const kyber = new KyberClass();
        const katData = await Deno.readTextFile(
          `${testVectorPath()}/kat/kat_MLKEM_${size}.rsp`,
        );
        const { ct, sk, ss, msg, pk } = parseKAT(katData);
        console.log(`test vector count: ${sk.length}`);

        for (let i = 0; i < sk.length; i++) {
          const ssDecapActual = await kyber.decap(ct[i], sk[i]);
          assertEquals(ssDecapActual, ss[i]);

          const [ctActual, ssEncapActual] = await kyber.encap(pk[i], msg[i]);
          assertEquals(ctActual, ct[i]);
          assertEquals(ssEncapActual, ss[i]);
        }
      });
    });

    describe("A sample code in README.", () => {
      it("should work normally", async () => {
        const recipient = new KyberClass();
        const [pkR, skR] = await recipient.generateKeyPair();

        const sender = new KyberClass();
        const [ct, ssS] = await sender.encap(pkR);

        const ssR = await recipient.decap(ct, skR);

        assertEquals(ssS, ssR);
      });

      it("should work normally with deriveKeyPair", async () => {
        const recipient = new KyberClass();
        const api = await loadCrypto();
        const seed = new Uint8Array(64);
        api.getRandomValues(seed);
        const [pkR, skR] = await recipient.deriveKeyPair(seed);
        const [pkR2, skR2] = await recipient.deriveKeyPair(seed);
        assertEquals(pkR, pkR2);
        assertEquals(skR, skR2);

        const sender = new KyberClass();
        const [ct, ssS] = await sender.encap(pkR);

        const ssR = await recipient.decap(ct, skR);

        assertEquals(ssS, ssR);
      });
    });

    describe("Advanced testing", () => {
      it("Invalid encapsulation keys", async () => {
        const sender = new KyberClass();
        const testData = await Deno.readTextFile(
          `${testVectorPath()}/modulus/ML-KEM-${size}.txt`,
        );
        const invalidPk = hexToBytes(testData);
        await assertRejects(
          () => sender.encap(invalidPk),
          MlKemError,
          "invalid encapsulation key",
        );
      });

      it("'Unlucky' vectors that require an unusually large number of XOF reads", async () => {
        const kyber = new KyberClass();
        const testData = await Deno.readTextFile(
          `${testVectorPath()}/unluckysample/ML-KEM-${size}.txt`,
        );
        const { c: [ct], dk: [sk], K: [ss] } = parseKAT(testData);
        const res = await kyber.decap(ct, sk);
        assertEquals(res, ss);
      });

      it("Accumulated vectors", async () => { // See https://github.com/C2SP/CCTV/blob/main/ML-KEM/README.md#accumulated-pq-crystals-vectors
        const deterministicKyber = new DeterministicKyberClass();
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
        const expectedHashes: { [key: string]: string } = {
          "MlKem512":
            "845913ea5a308b803c764a9ed8e9d814ca1fd9c82ba43c7b1e64b79c7a6ec8e4",
          "MlKem768":
            "f7db260e1137a742e05fe0db9525012812b004d29040a5b606aad3d134b548d3",
          "MlKem1024":
            "47ac888fe61544efc0518f46094b4f8a600965fc89822acb06dc7169d24f3543",
        };

        for (let i = 0; i < 10000; i++) {
          const [ek, dk] = await deterministicKyber.generateKeyPair();
          const [ct, k] = await deterministicKyber.encap(ek);
          const kActual = await deterministicKyber.decap(ct, dk);
          assertEquals(kActual, k);
          // sample random, invalid ct
          // @ts-ignore private accessor
          const ctRandom = deterministicKyber._api!.getRandomValues(
            new Uint8Array(ct.length),
          );
          const kRandom = await deterministicKyber.decap(ctRandom, dk);
          // hash results
          shakeInstance.update(ek)
            .update(dk)
            .update(ct)
            .update(k)
            .update(kRandom);
        }

        const actualHash = shakeInstance.digest();
        assertEquals(bytesToHex(actualHash), expectedHashes[KyberClass.name]);
      });
    });
  })
);
