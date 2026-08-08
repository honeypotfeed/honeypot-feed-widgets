import { defineConfig } from 'tsup'

export default defineConfig([
  // ESM + CJS (for npm bundlers)
  {
    entry: ['src/index.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: true,
    clean: true,
    target: 'es2020',
    minify: true,
    outDir: 'dist',
  },
  // UMD (for CDN <script> tag)
  {
    entry: ['src/index.ts'],
    format: ['iife'],
    globalName: 'HoneypotFeedWidget',
    outDir: 'dist',
    outExtension: () => ({ js: '.umd.js' }),
    minify: true,
    sourcemap: true,
    platform: 'browser',
    target: 'es2020',
    footer: {
      js: 'if(typeof module!=="undefined")module.exports=HoneypotFeedWidget;',
    },
  },
])
