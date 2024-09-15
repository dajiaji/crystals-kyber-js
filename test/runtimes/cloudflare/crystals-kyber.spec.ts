import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("Cloudflare Workers", () => {
  describe("GET /mlkem512", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch("https://example.com/mlkem512");
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("GET /mlkem768", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch("https://example.com/mlkem768");
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });

  describe("GET /mlkem1024", () => {
    it("should return ok", async () => {
      const res = await SELF.fetch("https://example.com/mlkem1024");
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("ok");
    });
  });
});
