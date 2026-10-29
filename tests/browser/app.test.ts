import { test, expect } from "@playwright/test";

test("production build executes ARM64/SIMD and stops bounded guest code in its worker", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Payback 2 Web" })).toBeVisible();
  await page.getByRole("button", { name: "Check browser compatibility" }).click();
  await expect(page.getByRole("status")).toContainText("ARM64 execution check passed");
  await expect(page.getByLabel("Initialization diagnostics")).toContainText("Unicorn.js / AArch64");
  await expect(page.getByRole("button", { name: "Stop", exact: true })).toBeDisabled();
});

test("invalid local game data fails without uploading it", async ({ page }) => {
  const unexpected: string[] = [];
  page.on("request", request => { if (!request.url().startsWith("http://127.0.0.1:4173")) unexpected.push(request.url()); });
  await page.goto("/");
  await page.locator("#game").setInputFiles({ name: "invalid.apk", mimeType: "application/zip", buffer: Buffer.from("synthetic invalid archive") });
  await expect(page.getByRole("status")).toContainText("ZIP");
  await expect(page.locator("#game")).toBeEnabled();
  expect(unexpected).toEqual([]);
});

test("stop releases the worker and a new compatibility check can run", async ({ page }) => {
  await page.route("**/assets/engine.worker-*.js", route => route.fulfill({
    status: 200, contentType: "application/javascript", body: "self.onmessage = () => {};",
  }));
  await page.goto("/");
  await page.getByRole("button", { name: "Check browser compatibility" }).click();
  await page.getByRole("button", { name: "Stop", exact: true }).click();
  await expect(page.getByRole("status")).toHaveText("Stopped");
  await page.unrouteAll();
  await page.getByRole("button", { name: "Check browser compatibility" }).click();
  await expect(page.getByRole("status")).toContainText("ARM64 execution check passed");
});
