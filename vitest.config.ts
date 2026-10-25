import { defineConfig } from 'vitest/config';

// Security gates (§11.3) map onto these projects. Adversarial and concurrency
// suites must stay deterministic: no live model, seeded clock fixtures only.
export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit',
          include: ['packages/*/test/**/*.test.ts', 'apps/*/test/**/*.test.ts', 'tests/unit/**/*.test.ts'],
        },
      },
      { test: { name: 'integration', include: ['tests/integration/**/*.test.ts'] } },
      { test: { name: 'adversarial', include: ['tests/adversarial/**/*.test.ts'] } },
      { test: { name: 'concurrency', include: ['tests/concurrency/**/*.test.ts'] } },
    ],
  },
});
