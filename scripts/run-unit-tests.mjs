/**
 * Runs the gateway's unit and simulation tests.
 *
 * They are TypeScript importing the TypeScript sources directly, and Node cannot run that (this
 * repo's CI uses Node 22 for typechecking only). Rather than add a test framework and a loader, the
 * files are bundled with esbuild — already a dependency of Vite, which is already a dependency of
 * the app — into a temporary directory, and `node --test` runs the bundles. That keeps the tests
 * dependency-free, runnable on the Node version the project ships with, and fast (the whole suite
 * bundles in well under a second).
 *
 *   node scripts/run-unit-tests.mjs            all gateway tests
 *   node scripts/run-unit-tests.mjs forwarder  only files whose name contains "forwarder"
 */

import { build } from 'esbuild'
import { mkdir, readdir, rm } from 'node:fs/promises'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawn } from 'node:child_process'

// fileURLToPath, not `.pathname`: on Windows the latter yields "/D:/a/...", and every
// path built from it doubles up into "D:\\D:\\a\\...".
const root = fileURLToPath(new URL('..', import.meta.url))
const sourceDir = join(root, 'test')
const outDir = join(root, '.tmp', 'unit-tests')
const filter = process.argv[2] ?? ''

async function findTests(dir) {
  const found = []
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) found.push(...(await findTests(path)))
    else if (entry.name.endsWith('.test.ts')) found.push(path)
  }
  return found
}

const all = await findTests(sourceDir)
const selected = filter ? all.filter((path) => path.includes(filter)) : all
if (selected.length === 0) {
  console.error(`No test files matched "${filter}" in ${sourceDir}`)
  process.exit(1)
}

await rm(outDir, { recursive: true, force: true })
await mkdir(outDir, { recursive: true })

await Promise.all(
  selected.map(async (path) => {
    const name = relative(sourceDir, path)
      .replace(/\.test\.ts$/, '.test.mjs')
      .replace(/[\\/]/g, '__')
    await build({
      entryPoints: [path],
      outfile: join(outDir, name),
      bundle: true,
      platform: 'node',
      format: 'esm',
      target: 'node20',
      // Electron and koffi (the FFI library the Windows capture backend loads lazily) are left
      // external: the tests import the modules that reference them but never take the Windows-only
      // paths, and bundling koffi would try to inline a binary for every platform.
      external: ['electron', 'koffi'],
      logLevel: 'warning'
    })
  })
)

const child = spawn(process.execPath, ['--test', '--test-reporter=spec', outDir], {
  stdio: 'inherit',
  cwd: root
})
child.on('exit', (code) => process.exit(code ?? 1))
