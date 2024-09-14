import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("Cloudflare Workers", () => {
  describe("GET /kyber512", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch("https://example.com/kyber512");
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("GET /kyber768", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch("https://example.com/kyber768");
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("GET /kyber1024", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch("https://example.com/kyber1024");
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });
});
