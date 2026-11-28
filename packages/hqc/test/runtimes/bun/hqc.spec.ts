import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

describe("Bun", () => {
  describe("GET /hqc1", () => {
    it("should return ok", async () => {
      const res = await fetch("http://localhost:3002/hqc1");
      assertEquals("ok", await res.text());
    });
  });

  describe("GET /hqc3", () => {
    it("should return ok", async () => {
      const res = await fetch("http://localhost:3002/hqc3");
      assertEquals("ok", await res.text());
    });
  });

  describe("GET /hqc5", () => {
    it("should return ok", async () => {
      const res = await fetch("http://localhost:3002/hqc5");
      assertEquals("ok", await res.text());
    });
  });
});
