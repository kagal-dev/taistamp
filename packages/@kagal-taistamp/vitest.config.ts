import {
  cloudflareTest,
} from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    coverage: {
      provider: 'istanbul',
      reporter: ['text', 'json', 'html'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/**/*.test.ts',
        'src/**/__tests__/**',
      ],
      thresholds: {
        lines: 90,
        functions: 90,
        branches: 85,
      },
    },
    projects: [
      {
        plugins: [
          cloudflareTest({
            wrangler: {
              configPath: './wrangler.jsonc',
            },
          }),
        ],
        test: {
          name: 'workerd',
          include: ['src/**/*.workerd.test.ts'],
          server: {
            deps: {
              // Bundle jiti into the worker so its
              // internal `require('node:process')` is
              // handled by vite's transform rather than
              // routed to vitest-pool-workers' module
              // fallback, whose allowlist omits
              // `node:process`. Surfaced in the publish
              // run at
              // https://github.com/kagal-dev/taistamp/actions/runs/25879706794
              inline: ['jiti'],
            },
          },
        },
      },
      {
        test: {
          name: 'node',
          include: ['src/**/*.test.ts'],
          exclude: ['src/**/*.workerd.test.ts'],
        },
      },
    ],
  },
});
