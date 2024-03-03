import baseConfig from "./web-test-runner.config.mjs";
import { browserstackLauncher } from "@web/test-runner-browserstack";

// options shared between all browsers
const sharedCapabilities = {
  // your username and key for browserstack, you can get this from your browserstack account
  // it's recommended to store these as environment variables
  "browserstack.user": process.env.BROWSERSTACK_USERNAME,
  "browserstack.key": process.env.BROWSERSTACK_ACCESS_KEY,

  project: "@openpgpjs/crystals-kyber",
  name: process.env.GITHUB_WORKFLOW,
  build: process.env.GITHUB_SHA,
};

export default {
  ...baseConfig,
  // how many browsers to run concurrently in browserstack. increasing this significantly
  // reduces testing time, but your subscription might limit concurrent connections
  concurrentBrowsers: 1,
  browsers: [
    browserstackLauncher({
      capabilities: {
        ...sharedCapabilities,
        browserName: "Safari",
        browser_version: "13.1", // no BigInt support
        os: "OS X",
        os_version: "Catalina",
      },
    }),
  ],
};
