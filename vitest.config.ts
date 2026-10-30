import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Builds dist/ once, before any test file runs. Tests that spawn the CLI read dist/, so
    // nothing may rebuild it while they run.
    globalSetup: './test/build.ts',
  },
});
