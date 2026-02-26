import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: ['src/index.ts'],
    format: ['esm'],
    target: 'node18',
    outDir: 'dist',
    clean: true,
    sourcemap: true,
    dts: false,
    shims: true,
    banner: {
      js: '#!/usr/bin/env node',
    },
  },
  {
    entry: ['src/app/server.ts'],
    format: ['esm'],
    target: 'node18',
    outDir: 'dist/app',
    sourcemap: true,
    dts: false,
    shims: true,
  },
]);
