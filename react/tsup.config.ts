import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.tsx'],
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'es2020',
  minify: true,
  outDir: 'dist',
  external: ['react', 'react-dom', 'honeypot-feed-widget'],
})
