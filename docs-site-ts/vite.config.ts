import { defineConfig } from 'vite';

export default defineConfig({
  root: '.',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    port: 8320,
    host: '127.0.0.1',
  },
  preview: {
    port: 8320,
    host: '127.0.0.1',
  },
});
