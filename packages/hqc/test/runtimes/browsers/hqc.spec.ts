import { expect, test } from "@playwright/test";

test("basic test", async ({ page }) => {
  await page.goto("/");
  await page.click("text=run");
  await expect(page.locator("id=pass")).toHaveText("3", { timeout: 30000 });
  await expect(page.locator("id=fail")).toHaveText("0");
});
