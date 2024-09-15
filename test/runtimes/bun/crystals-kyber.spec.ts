import { assertEquals } from "@std/assert";
import { describe, it } from "@std/testing/bdd";

describe("Bun", () => {
  describe("GET /mlkem512", () => {
    it("should return ok", async () => {
      const res = await fetch("http://localhost:3000/mlkem512");
      assertEquals("ok", await res.text());
    });
  });

  describe("GET /mlkem768", () => {
    it("should return ok", async () => {
      const res = await fetch("http://localhost:3000/mlkem768");
      assertEquals("ok", await res.text());
    });
  });

  describe("GET /mlkem1024", () => {
    it("should return ok", async () => {
      const res = await fetch("http://localhost:3000/mlkem1024");
      assertEquals("ok", await res.text());
    });
  });
});
