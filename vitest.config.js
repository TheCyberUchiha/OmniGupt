import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'jsdom',
    setupFiles: ['./tests/vitest.setup.js'],
    globals: true,
    exclude: ['**/node_modules/**', '**/tests/e2e/**'],
  },
});
