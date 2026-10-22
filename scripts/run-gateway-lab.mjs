/**
 * Runs the Windows lab: the tests that need a real Windows machine with the WinDivert driver.
 *
 * It does three things the ordinary unit runner does not:
 *
 *  1. bundles `test/windows/**` against the TypeScript sources (same esbuild trick as
 *     `run-unit-tests.mjs`, no test framework, no loader);
 *  2. bundles the **capture process** exactly the way the app ships it, so the lab is testing the
 *     real child process rather than a stand-in — that is where the bug that broke the first Windows
 *     build lived (an IPC channel that could never work), so it is the part that must be exercised;
 *  3. writes the driver's and the capture process's logs next to the results, so a red CI run comes
 *     with the evidence attached.
 *
 *   node scripts/run-gateway-lab.mjs
 *   node scripts/run-gateway-lab.mjs lab        only files whose name contains "lab"
 */

import { build } from 'esbuild'
import { mkdir, readdir, rm, writeFile } from 'node:fs/promises'
import { join, relative } from 'node:path'
import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'

const root = new URL('..', import.meta.url).pathname
const sourceDir = join(root, 'test', 'windows')
const outDir = join(root, '.tmp', 'windows-lab')
const filter = process.argv[2] ?? ''
const common = {
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node20',
  // koffi is a native module: it has to be resolved at runtime, and bundling it would inline a
  // binary for every platform. Electron is referenced by modules the lab never runs.
  external: ['electron', 'koffi'],
  logLevel: 'warning'
}

if (!existsSync(sourceDir)) {
  console.error(`No Windows lab tests in ${sourceDir}`)
  process.exit(1)
}

await rm(outDir, { recursive: true, force: true })
await mkdir(outDir, { recursive: true })

const tests = (await readdir(sourceDir))
  .filter((name) => name.endsWith('.test.ts'))
  .filter((name) => (filter ? name.includes(filter) : true))
if (tests.length === 0) {
  console.error(`No Windows lab tests matched "${filter}"`)
  process.exit(1)
}

await Promise.all(
  tests.map((name) =>
    build({
      ...common,
      entryPoints: [join(sourceDir, name)],
      outfile: join(outDir, name.replace(/\.test\.ts$/, '.test.mjs'))
    })
  )
)

// The capture process, built the way the app builds it: one file, its own entry point, external
// koffi. Its path is handed to the tests through the environment, which is also how a packaged app
// finds it.
const workerPath = join(outDir, 'winDivertWorker.mjs')
await build({
  ...common,
  entryPoints: [join(root, 'src/main/gateway/backends/winDivertWorker.ts')],
  outfile: workerPath
})

await writeFile(
  join(outDir, 'lab-info.txt'),
  [
    `platform: ${process.platform} ${process.arch}`,
    `node: ${process.version}`,
    `cwd: ${root}`,
    `capture process: ${workerPath}`,
    `tests: ${tests.join(', ')}`
  ].join('\n')
)

console.log(`[lab] capture process built: ${relative(root, workerPath)}`)

const child = spawn(
  process.execPath,
  ['--test', '--test-reporter=spec', '--test-timeout=120000', outDir],
  {
    stdio: 'inherit',
    cwd: root,
    env: { ...process.env, PLEXO_LAB_WORKER: workerPath }
  }
)
child.on('exit', (code) => process.exit(code ?? 1))
