import { createHqc1, createHqc3, createHqc5 } from "./hqc.js";

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

const SUITES = {
  "/hqc1": createHqc1,
  "/hqc3": createHqc3,
  "/hqc5": createHqc5,
};

export async function testServer(request) {
  const url = new URL(request.url);

  const createHqc = SUITES[url.pathname];
  if (createHqc === undefined) {
    return new Response("ng: invalid path", { status: 404 });
  }
  try {
    // generateKeyPair/encap/decap
    const recipient = await createHqc();
    const [pkR, skR] = recipient.generateKeyPair();
    const sender = await createHqc();
    const [ct, ssS] = sender.encap(pkR);
    const ssR = recipient.decap(ct, skR);
    if (!compare(ssS, ssR)) {
      throw new Error("The two shared secrets mismatch.");
    }

    // deriveKeyPair
    const seed = new Uint8Array(32);
    globalThis.crypto.getRandomValues(seed);
    const [dPkR, dSkR] = recipient.deriveKeyPair(seed);
    const [dPkR2, dSkR2] = recipient.deriveKeyPair(seed);
    if (!compare(dPkR, dPkR2) || !compare(dSkR, dSkR2)) {
      throw new Error("The two derived keypairs mismatch.");
    }
    const [dCt, dSsS] = sender.encap(dPkR);
    const dSsR = recipient.decap(dCt, dSkR);
    if (!compare(dSsS, dSsR)) {
      throw new Error(
        "The two shared secrets mismatch for the derived keypair.",
      );
    }
  } catch (e) {
    return new Response("ng: " + e.message);
  }
  return new Response("ok");
}
