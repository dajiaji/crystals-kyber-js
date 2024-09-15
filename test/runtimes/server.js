import { MlKem1024, MlKem512, MlKem768 } from "./crystals-kyber.js";

function compare(x, y) {
  if (x.length != y.length) {
    return false;
  }
  const v = new Uint8Array([0]);
  for (let i = 0; i < x.length; i++) {
    v[0] |= x[i] ^ y[i];
  }
  const z = new Uint8Array([0]);
  z[0] = ~(v[0] ^ z[0]);
  z[0] &= z[0] >> 4;
  z[0] &= z[0] >> 2;
  z[0] &= z[0] >> 1;
  return z[0] === 1 ? true : false;
}

export async function testServer(request) {
  const url = new URL(request.url);

  if (url.pathname === "/mlkem512") {
    try {
      // generateKeyPair/encap/decap
      const recipient = new MlKem512();
      const [pkR, skR] = await recipient.generateKeyPair();
      const sender = new MlKem512();
      const [ct, ssS] = await sender.encap(pkR);
      const ssR = await recipient.decap(ct, skR);
      if (!compare(ssS, ssR)) {
        throw new Error("The two shared secrets mismatch.");
      }

      // deriveKeyPair
      const seed = new Uint8Array(64);
      globalThis.crypto.getRandomValues(seed);
      const [dPkR, dSkR] = await recipient.deriveKeyPair(seed);
      const [dPkR2, dSkR2] = await recipient.deriveKeyPair(seed);
      if (!compare(dPkR, dPkR2) || !compare(dSkR, dSkR2)) {
        throw new Error("The two derived keypairs mismatch.");
      }
    } catch (e) {
      return new Response("ng: " + e.message);
    }
    return new Response("ok");
  }
  if (url.pathname === "/mlkem768") {
    try {
      // generateKeyPair/encap/decap
      const recipient = new MlKem768();
      const [pkR, skR] = await recipient.generateKeyPair();
      const sender = new MlKem768();
      const [ct, ssS] = await sender.encap(pkR);
      const ssR = await recipient.decap(ct, skR);
      if (!compare(ssS, ssR)) {
        throw new Error("The two shared secrets mismatch.");
      }

      // deriveKeyPair
      const seed = new Uint8Array(64);
      globalThis.crypto.getRandomValues(seed);
      const [dPkR, dSkR] = await recipient.deriveKeyPair(seed);
      const [dPkR2, dSkR2] = await recipient.deriveKeyPair(seed);
      if (!compare(dPkR, dPkR2) || !compare(dSkR, dSkR2)) {
        throw new Error("The two derived keypairs mismatch.");
      }
    } catch (e) {
      return new Response("ng: " + e.message);
    }
    return new Response("ok");
  }
  if (url.pathname === "/mlkem1024") {
    try {
      // generateKeyPair/encap/decap
      const recipient = new MlKem1024();
      const [pkR, skR] = await recipient.generateKeyPair();
      const sender = new MlKem1024();
      const [ct, ssS] = await sender.encap(pkR);
      const ssR = await recipient.decap(ct, skR);
      if (!compare(ssS, ssR)) {
        throw new Error("The two shared secrets mismatch.");
      }

      // deriveKeyPair
      const seed = new Uint8Array(64);
      globalThis.crypto.getRandomValues(seed);
      const [dPkR, dSkR] = await recipient.deriveKeyPair(seed);
      const [dPkR2, dSkR2] = await recipient.deriveKeyPair(seed);
      if (!compare(dPkR, dPkR2) || !compare(dSkR, dSkR2)) {
        throw new Error("The two derived keypairs mismatch.");
      }
    } catch (e) {
      return new Response("ng: " + e.message);
    }
    return new Response("ok");
  }
  return new Response("ng: invalid path", { status: 404 });
}
