import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  globalSetup: "./global-setup.ts",
  fullyParallel: false,
  retries: 1,
  workers: 1,
  timeout: 120000,
  reporter: "list",

  use: {
    baseURL: "http://localhost:3000",
    trace: "on-first-retry",
    screenshot: "only-on-failure",
  },

  projects: [{
    name: "foxhound",
    use: {
      browserName: "firefox",
      launchOptions: {
        executablePath: "/opt/foxhound-3/foxhound/foxhound",
        headless: true,
      },
    },
  }],
});
