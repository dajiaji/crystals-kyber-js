import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

describe("Bun", () => {
  describe("GET /mldsa44", () => {
    it("should return ok", async () => {
      const res = await fetch("http://localhost:3001/mldsa44");
      assertEquals("ok", await res.text());
    });
  });

  describe("GET /mldsa65", () => {
    it("should return ok", async () => {
      const res = await fetch("http://localhost:3001/mldsa65");
      assertEquals("ok", await res.text());
    });
  });

  describe("GET /mldsa87", () => {
    it("should return ok", async () => {
      const res = await fetch("http://localhost:3001/mldsa87");
      assertEquals("ok", await res.text());
    });
  });
});
