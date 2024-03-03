import { expect } from "@esm-bundle/chai";
import { MlKem1024, MlKem512, MlKem768 } from "crystals-kyber";

describe("Browser basic tests", () => {
  [MlKem512, MlKem768, MlKem1024].forEach((KyberClass) =>
    it("key generation and roundtrip", async () => {
      const kyber = new KyberClass();
      const [pkR, skR] = await kyber.generateKeyPair();
      const [ct, ssS] = await kyber.encap(pkR);
      const ssR = await kyber.decap(ct, skR);
      expect(ssS).to.deep.equal(ssR);

      // deriveKeyPair
      const seed = new Uint8Array(64);
      globalThis.crypto.getRandomValues(seed);
      const [dPkR, dSkR] = await kyber.deriveKeyPair(seed);
      const [dPkR2, dSkR2] = await kyber.deriveKeyPair(seed);
      expect(dPkR).to.deep.equal(dPkR2);
      expect(dSkR).to.deep.equal(dSkR2);
    })
  );
});
