Deno.bench("P-256::generateKeyPair", async (b) => {
  b.start();
  const _ret = await globalThis.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  b.end();
});

Deno.bench("P-384::generateKeyPair", async (b) => {
  b.start();
  const _ret = await globalThis.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-384" },
    true,
    ["deriveBits"],
  );
  b.end();
});
