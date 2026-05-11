#!/usr/bin/env node
// Custom build script: esbuild (Go binary) + PostCSS API (pure JS)
// Avoids rollup/rolldown/parcel-watcher native .node binaries that fail on macOS 25 Team ID checks.

import * as esbuild from 'esbuild'
import postcss from 'postcss'
import tailwindcss from '@tailwindcss/postcss'
import { mkdirSync, writeFileSync, readFileSync } from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const OUT = path.join(__dirname, '../internal/api/dist')
const SRC = path.join(__dirname, 'src')

mkdirSync(OUT, { recursive: true })

// 1. Bundle JS/TSX with esbuild
const result = await esbuild.build({
  entryPoints: [path.join(SRC, 'main.tsx')],
  bundle: true,
  format: 'esm',
  splitting: false,
  sourcemap: false,
  minify: true,
  outfile: path.join(OUT, 'assets/index.js'),
  jsx: 'automatic',
  jsxImportSource: 'react',
  define: {
    'process.env.NODE_ENV': '"production"',
  },
  tsconfig: path.join(__dirname, 'tsconfig.app.json'),
  alias: {
    '@': SRC,
  },
  // CSS is processed separately by tailwindcss CLI
  external: ['*.css'],
  logLevel: 'info',
})

if (result.errors.length > 0) {
  console.error('esbuild errors:', result.errors)
  process.exit(1)
}

// 2. Build Tailwind CSS via PostCSS API (pure JS, no native bindings)
const cssInput = readFileSync(path.join(SRC, 'index.css'), 'utf8')
const cssResult = await postcss([tailwindcss]).process(cssInput, {
  from: path.join(SRC, 'index.css'),
  to: path.join(OUT, 'assets/index.css'),
})
writeFileSync(path.join(OUT, 'assets/index.css'), cssResult.css)

// 3. Write index.html
const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>TrustTunnel WebUI</title>
    <link rel="stylesheet" href="/assets/index.css" />
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/assets/index.js"></script>
  </body>
</html>`

writeFileSync(path.join(OUT, 'index.html'), html)

console.log('Build complete →', OUT)
