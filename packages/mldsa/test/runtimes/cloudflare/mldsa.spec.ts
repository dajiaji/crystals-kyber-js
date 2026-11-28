import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("Cloudflare Workers", () => {
  describe("GET /mldsa44", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch("https://example.com/mldsa44");
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("GET /mldsa65", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch("https://example.com/mldsa65");
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("GET /mldsa87", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch("https://example.com/mldsa87");
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("GET /unknown", () => {
    it("should return 404", async () => {
      const res = await SELF.fetch("https://example.com/unknown");
      expect(res.status).toBe(404);
    });
  });
});
