import { assertEquals } from "testing/asserts.ts";
import { describe, it } from "testing/bdd.ts";

describe("Cloudflare Workers", () => {
  describe("GET /kyber512", () => {
    it("should return ok", async () => {
      const res = await fetch("http://localhost:8787/kyber512");
      assertEquals("ok", await res.text());
    });
  });

  describe("GET /kyber768", () => {
    it("should return ok", async () => {
      const res = await fetch("http://localhost:8787/kyber768");
      assertEquals("ok", await res.text());
    });
  });

  describe("GET /kyber1024", () => {
    it("should return ok", async () => {
      const res = await fetch("http://localhost:8787/kyber1024");
      assertEquals("ok", await res.text());
    });
  });
});
