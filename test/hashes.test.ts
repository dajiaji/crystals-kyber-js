/**
 * This file is based on noble-hashes (https://github.com/paulmillr/noble-hashes).
 *
 * noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com)
 *
 * The original file is located at:
 * https://github.com/paulmillr/noble-hashes/blob/4e358a46d682adfb005ae6314ec999f2513086b9/test/u64.test.ts
 */

import { assertEquals, assertThrows } from "@std/assert";
import { describe, it } from "@std/testing/bdd";
import { createHash } from "node:crypto";
import {
  // sha3_224,
  sha3_256,
  // sha3_384,
  sha3_512,
  shake128,
  shake256,
} from "../src/sha3/sha3.ts";
import { concatBytes, hexToBytes, utf8ToBytes } from "../src/sha3/utils.ts";
import { repeat, TYPE_TEST } from "./utils.ts";

// NIST test vectors (https://www.di-mgt.com.au/sha_testvectors.html)
const NIST_VECTORS = [
  [1, utf8ToBytes("abc")],
  [1, utf8ToBytes("")],
  [1, utf8ToBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")],
  [
    1,
    utf8ToBytes(
      "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    ),
  ],
  [1000000, utf8ToBytes("a")],
  // Very slow, 1GB
  //[16777216, utf8ToBytes('abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno')],
].map(([r, buf]) => [r, buf, repeat(buf as Uint8Array, r as number)]);

// Main idea: write 16k buffer with different values then test sliding window against node-js implementation
const testBuf = new Uint8Array(4096);
for (let i = 0; i < testBuf.length; i++) testBuf[i] = i;

const HASHES = {
  // SHA3_224: {
  //   name: "SHA3_224",
  //   fn: sha3_224,
  //   obj: sha3_224.create,
  //   node: (buf: Uint8Array) =>
  //     Uint8Array.from(
  //       createHash("sha3-224").update(buf).digest(),
  //     ),
  //   node_obj: () => createHash("sha3-224"),
  //   nist: [
  //     "e642824c3f8cf24a d09234ee7d3c766f c9a3a5168d0c94ad 73b46fdf",
  //     "6b4e03423667dbb7 3b6e15454f0eb1ab d4597f9a1b078e3f 5b5a6bc7",
  //     "8a24108b154ada21 c9fd5574494479ba 5c7e7ab76ef264ea d0fcce33",
  //     "543e6868e1666c1a 643630df77367ae5 a62a85070a51c14c bf665cbc",
  //     "d69335b93325192e 516a912e6d19a15c b51c6ed5c15243e7 a7fd653c",
  //     "c6d66e77ae289566 afb2ce39277752d6 da2a3c46010f1e0a 0970ff60",
  //   ],
  // },
  SHA3_256: {
    name: "SHA3_256",
    fn: sha3_256,
    obj: sha3_256.create,
    node: (buf: Uint8Array) =>
      Uint8Array.from(
        createHash("sha3-256").update(buf).digest(),
      ),
    node_obj: () => createHash("sha3-256"),
    nist: [
      "3a985da74fe225b2 045c172d6bd390bd 855f086e3e9d525b 46bfe24511431532",
      "a7ffc6f8bf1ed766 51c14756a061d662 f580ff4de43b49fa 82d80a4b80f8434a",
      "41c0dba2a9d62408 49100376a8235e2c 82e1b9998a999e21 db32dd97496d3376",
      "916f6061fe879741 ca6469b43971dfdb 28b1a32dc36cb325 4e812be27aad1d18",
      "5c8875ae474a3634 ba4fd55ec85bffd6 61f32aca75c6d699 d0cdcb6c115891c1",
      "ecbbc42cbf296603 acb2c6bc0410ef43 78bafb24b710357f 12df607758b33e2b",
    ],
  },
  // SHA3_384: {
  //   name: "SHA3_384",
  //   fn: sha3_384,
  //   obj: sha3_384.create,
  //   node: (buf: Uint8Array) =>
  //     Uint8Array.from(
  //       createHash("sha3-384").update(buf).digest(),
  //     ),
  //   node_obj: () => createHash("sha3-384"),
  //   nist: [
  //     "ec01498288516fc9 26459f58e2c6ad8d f9b473cb0fc08c25 96da7cf0e49be4b2 98d88cea927ac7f5 39f1edf228376d25",
  //     "0c63a75b845e4f7d 01107d852e4c2485 c51a50aaaa94fc61 995e71bbee983a2a c3713831264adb47 fb6bd1e058d5f004",
  //     "991c665755eb3a4b 6bbdfb75c78a492e 8c56a22c5c4d7e42 9bfdbc32b9d4ad5a a04a1f076e62fea1 9eef51acd0657c22",
  //     "79407d3b5916b59c 3e30b09822974791 c313fb9ecc849e40 6f23592d04f625dc 8c709b98b43b3852 b337216179aa7fc7",
  //     "eee9e24d78c18553 37983451df97c8ad 9eedf256c6334f8e 948d252d5e0e7684 7aa0774ddb90a842 190d2c558b4b8340",
  //     "a04296f4fcaae148 71bb5ad33e28dcf6 9238b04204d9941b 8782e816d014bcb7 540e4af54f30d578 f1a1ca2930847a12",
  //   ],
  // },
  SHA3_512: {
    name: "SHA3_512",
    fn: sha3_512,
    obj: sha3_512.create,
    node: (buf: Uint8Array) =>
      Uint8Array.from(
        createHash("sha3-512").update(buf).digest(),
      ),
    node_obj: () => createHash("sha3-512"),
    nist: [
      "b751850b1a57168a 5693cd924b6b096e 08f621827444f70d 884f5d0240d2712e 10e116e9192af3c9 1a7ec57647e39340 57340b4cf408d5a5 6592f8274eec53f0",
      "a69f73cca23a9ac5 c8b567dc185a756e 97c982164fe25859 e0d1dcc1475c80a6 15b2123af1f5f94c 11e3e9402c3ac558 f500199d95b6d3e3 01758586281dcd26",
      "04a371e84ecfb5b8 b77cb48610fca818 2dd457ce6f326a0f d3d7ec2f1e91636d ee691fbe0c985302 ba1b0d8dc78c0863 46b533b49c030d99 a27daf1139d6e75e",
      "afebb2ef542e6579 c50cad06d2e578f9 f8dd6881d7dc824d 26360feebf18a4fa 73e3261122948efc fd492e74e82e2189 ed0fb440d187f382 270cb455f21dd185",
      "3c3a876da14034ab 60627c077bb98f7e 120a2a5370212dff b3385a18d4f38859 ed311d0a9d5141ce 9cc5c66ee689b266 a8aa18ace8282a0e 0db596c90b0a7b87",
      "235ffd53504ef836 a1342b488f483b39 6eabbfe642cf78ee 0d31feec788b23d0 d18d5c339550dd59 58a500d4b95363da 1b5fa18affc1bab2 292dc63b7d85097c",
    ],
  },
  SHAKE128: {
    name: "SHAKE128",
    fn: shake128,
    obj: shake128.create,
    node: (buf: Uint8Array) =>
      Uint8Array.from(
        createHash("shake128", { outputLength: 16 }).update(buf).digest(),
      ),
    node_obj: () => createHash("shake128"),
    // There is no official vectors, so we created them via:
    // > NIST_VECTORS.map((i) => createHash('shake128').update(i[2]).digest('hex'))
    nist: [
      "5881092dd818bf5cf8a3ddb793fbcba7",
      "7f9c2ba4e88f827d616045507605853e",
      "1a96182b50fb8c7e74e0a707788f55e9",
      "7b6df6ff181173b6d7898d7ff63fb07b",
      "9d222c79c4ff9d092cf6ca86143aa411",
    ],
  },
  SHAKE256: {
    name: "SHAKE256",
    fn: shake256,
    obj: shake256.create,
    node: (buf: Uint8Array) =>
      Uint8Array.from(
        createHash("shake256", { outputLength: 32 }).update(buf).digest(),
      ),
    node_obj: () => createHash("shake256"),
    // There is no official vectors, so we created them via:
    // > NIST_VECTORS.map((i) => createHash('shake256').update(i[2]).digest('hex'))
    nist: [
      "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739",
      "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
      "4d8c2dd2435a0128eefbb8c36f6f87133a7911e18d979ee1ae6be5d4fd2e3329",
      "98be04516c04cc73593fef3ed0352ea9f6443942d6950e29a372a681c3deaf45",
      "3578a7a4ca9137569cdf76ed617d31bb994fca9c1bbf8b184013de8234dfd13a",
    ],
  },
};

const BUF_768 = new Uint8Array(256 * 3);
// Fill with random data
for (let i = 0; i < (256 * 3) / 32; i++) {
  BUF_768.set(createHash("sha256").update(new Uint8Array(i)).digest(), i * 32);
}

Object.values(HASHES).forEach((hash) =>
  describe(hash.name, () => {
    // All hashes has NIST vectors, some generated manually
    it("NIST vectors", () => {
      for (let i = 0; i < NIST_VECTORS.length; i++) {
        if (!NIST_VECTORS[i]) continue;
        const [r, rbuf, buf] = NIST_VECTORS[i] as [
          number,
          Uint8Array,
          Uint8Array,
        ];
        assertEquals(
          hash.obj().update(buf).digest(),
          hexToBytes(hash.nist[i].replace(/ /g, "")),
          `vector ${i}`,
        );
        const tmp = hash.obj();
        for (let j = 0; j < r; j++) tmp.update(rbuf);
        assertEquals(
          tmp.digest(),
          hexToBytes(hash.nist[i].replace(/ /g, "")),
          `partial vector ${i}`,
        );
      }
    });
    it("accept data in compact call form (Uint8Array)", () => {
      assertEquals(
        hash.fn(utf8ToBytes("abc")),
        hexToBytes(hash.nist[0].replace(/ /g, "")),
      );
    });
    it("throw on update after digest", async () => {
      const tmp = hash.obj();
      tmp.update(utf8ToBytes("abc")).digest();
      await assertThrows(
        () => tmp.update(utf8ToBytes("abc")),
        Error,
        "Hash instance has been destroyed",
      );
    });
    it("throw on second digest call", async () => {
      const tmp = hash.obj();
      tmp.update(utf8ToBytes("abc")).digest();
      await assertThrows(
        () => tmp.digest(),
        Error,
        "digest() was already called",
      );
    });
    it("throw on wrong argument type", async () => {
      // Allowed only: undefined (for compact form only), string, Uint8Array
      for (const t of TYPE_TEST.bytes) {
        await assertThrows(
          () => hash.fn(t),
          Error,
        );
        await assertThrows(
          () => hash.obj().update(t).digest(),
          Error,
        );
      }
      await assertThrows(
        () => hash.fn(undefined as unknown as Uint8Array),
        Error,
      );
      await assertThrows(
        () => hash.obj().update(undefined as unknown as Uint8Array).digest(),
        Error,
      );
      for (const t of TYPE_TEST.opts) {
        await assertThrows(
          () => hash.fn(undefined as unknown as Uint8Array, t),
          Error,
        );
      }
    });

    it("clone", () => {
      const exp = hash.fn(BUF_768);
      const t = hash.obj();
      t.update(BUF_768.subarray(0, 10));
      const t2 = t.clone();
      t2.update(BUF_768.subarray(10));
      assertEquals(t2.digest(), exp);
      t.update(BUF_768.subarray(10));
      assertEquals(t.digest(), exp);
    });

    it("partial", () => {
      const fnH = hash.fn(BUF_768);
      for (let i = 0; i < 256; i++) {
        const b1 = BUF_768.subarray(0, i);
        for (let j = 0; j < 256; j++) {
          const b2 = BUF_768.subarray(i, i + j);
          const b3 = BUF_768.subarray(i + j);
          assertEquals(concatBytes(b1, b2, b3), BUF_768);
          assertEquals(
            hash.obj().update(b1).update(b2).update(b3).digest(),
            fnH,
          );
        }
      }
    });
    // Same as before, but creates copy of each slice, which changes dataoffset of typed array
    // Catched bug in blake2
    it("partial (copy): partial", () => {
      const fnH = hash.fn(BUF_768);
      for (let i = 0; i < 256; i++) {
        const b1 = BUF_768.subarray(0, i).slice();
        for (let j = 0; j < 256; j++) {
          const b2 = BUF_768.subarray(i, i + j).slice();
          const b3 = BUF_768.subarray(i + j).slice();
          assertEquals(concatBytes(b1, b2, b3), BUF_768);
          assertEquals(
            hash.obj().update(b1).update(b2).update(b3).digest(),
            fnH,
          );
        }
      }
    });
    if (hash.node) {
      // if (!!process.versions.bun && ["BLAKE2s", "BLAKE2b"].includes(h)) {
      //   return;
      // }
      it("node.js cross-test", () => {
        for (let i = 0; i < testBuf.length; i++) {
          assertEquals(
            hash.obj().update(testBuf.subarray(0, i)).digest(),
            hash.node(testBuf.subarray(0, i)),
          );
        }
      });
      it("node.js cross-test chained", () => {
        const b = new Uint8Array([1, 2, 3]);
        let nodeH = hash.node(b);
        let nobleH = hash.fn(b);
        for (let i = 0; i < 256; i++) {
          nodeH = hash.node(nodeH);
          nobleH = hash.fn(nobleH);
          assertEquals(nodeH, nobleH);
        }
      });
      it("node.js cross-test partial", () => {
        assertEquals(hash.fn(BUF_768), hash.node(BUF_768));
      });
    }
  })
);
