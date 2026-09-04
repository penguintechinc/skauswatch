/// <reference types="vitest" />
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig({
  plugins: [react()],
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/client/tests/setup.ts'],
    include: ['src/client/tests/**/*.{test,spec}.{ts,tsx}'],
    exclude: ['src/client/tests/e2e/**', 'node_modules/**'],
    // Deterministic isolation: forked process + fresh module registry per
    // file prevents the cross-file vi.mock leakage that made the module-smoke
    // test flaky. (No mockReset/restoreMocks — those wipe the in-file vi.mock
    // factory implementations the tests rely on.)
    pool: 'forks',
    isolate: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'json', 'html'],
      include: ['src/client/**/*.{ts,tsx}'],
      exclude: [
        'node_modules/',
        'src/client/tests/',
        '**/*.test.{ts,tsx}',
        '**/*.spec.{ts,tsx}',
      ],
      lines: 90,
      functions: 90,
      branches: 90,
      statements: 90,
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src/client'),
    },
  },
});
