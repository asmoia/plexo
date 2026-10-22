/**
 * Checks the capture process as the *bundler emits it*, not as the lab builds it.
 *
 * The lab compiles the worker itself, which proves the source works. This proves the thing that
 * ships works: `electron-vite`'s output is started the way the app starts it (the app's own binary in
 * Node mode, with an IPC channel) and has to answer. The bug that broke the first Windows build was
 * exactly here — a process that could not reach its parent and exited with code 1 before saying so —
 * and no test noticed, because the source looked right.
 *
 *   node scripts/check-bundled-worker.mjs
 */

import { spawn } from 'node:child_process'
import { existsSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

const root = new URL('..', import.meta.url).pathname
const candidates = [
  join(root, 'out', 'main', 'winDivertWorker.js'),
  join(root, 'out', 'main', 'chunks', 'winDivertWorker.js')
]
const workerPath = candidates.find((path) => existsSync(path))

if (!workerPath) {
  console.error(
    `The capture process was not emitted. Looked for:\n  ${candidates.join('\n  ')}\n` +
      `Found in out/main: ${existsSync(join(root, 'out', 'main')) ? readdirSync(join(root, 'out', 'main')).join(', ') : '(no out/main)'}`
  )
  process.exit(1)
}
console.log(`[worker] built at ${workerPath}`)

const child = spawn(process.execPath, [workerPath], {
  // Exactly how the app starts it. Electron would be `process.execPath` there; node is the same
  // contract, and this runs without an Electron install.
  env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
  stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  cwd: root
})

const messages = []
const output = []
child.stdout?.on('data', (chunk) => output.push(chunk.toString()))
child.stderr?.on('data', (chunk) => output.push(chunk.toString()))
child.on('message', (message) => messages.push(message))

const finished = new Promise((resolve) => {
  child.on('exit', (code) => resolve(code))
  setTimeout(() => {
    child.kill()
    resolve('timeout')
  }, 20_000)
})

child.send({
  type: 'start',
  // A path that cannot load, so the process has to reach the driver call and report its failure —
  // which is precisely the journey that used to end in silence.
  dllPath: join(root, 'resources', 'windivert', 'does-not-exist.dll'),
  flags: { SNIFF: 1, DROP: 2, RECV_ONLY: 4, SEND_ONLY: 8, NO_INSTALL: 16 },
  config: {
    downstreamIfIdx: 9999,
    uplinks: [],
    publicPorts: { min: 20_000, max: 29_999 }
  }
})

const code = await finished
const stderr = output.join('').trim()
const first = messages[0]

console.log(`[worker] exit: ${code}`)
if (first) console.log(`[worker] first message: ${first.type} — ${first.message ?? ''}`)
if (stderr) console.log(`[worker] output: ${stderr.split('\n').slice(0, 6).join('\n')}`)

if (!first) {
  console.error(
    '\nThe capture process answered nothing. Either it could not reach its parent (the bug this ' +
      'script exists to catch) or it died before loading the driver:\n' +
      (stderr || '(nothing on stdout or stderr)')
  )
  process.exit(1)
}
if (first.type !== 'error') {
  console.error(`\nExpected an error about the missing DLL, got a "${first.type}" message.`)
  process.exit(1)
}
if (!/load|library|WinDivert|dll/i.test(first.message)) {
  console.error(`\nThe failure does not mention the driver: ${first.message}`)
  process.exit(1)
}
console.log(
  '[worker] ok: the bundled capture process starts, reports, and exits non-zero on failure'
)
process.exit(0)
