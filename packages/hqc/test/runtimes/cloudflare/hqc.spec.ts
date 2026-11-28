import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("Cloudflare Workers", () => {
  describe("GET /hqc1", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch("https://example.com/hqc1");
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("GET /hqc3", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch("https://example.com/hqc3");
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("GET /hqc5", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch("https://example.com/hqc5");
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
