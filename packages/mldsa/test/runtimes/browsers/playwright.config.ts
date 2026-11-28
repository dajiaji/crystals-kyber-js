// playwright.config.ts
import type { PlaywrightTestConfig } from "@playwright/test";
import { devices } from "@playwright/test";

const config: PlaywrightTestConfig = {
  use: {
    baseURL: "http://127.0.0.1:8081",
  },
  // Serve the test page locally so that the tests run against the code under
  // test rather than the published GitHub Pages site.
  webServer: {
    command: "python3 -m http.server 8081 --bind 127.0.0.1 --directory pages",
    url: "http://127.0.0.1:8081/",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "firefox",
      use: { ...devices["Desktop Firefox"] },
    },
    {
      name: "webkit",
      use: { ...devices["Desktop Safari"] },
    },
  ],
};
export default config;
