/**
 * The Windows capture backend: WinDivert, driven from a dedicated process.
 *
 * WinDivert is a signed kernel driver plus a small user-mode DLL that lets a process see and inject
 * packets at the Windows Filtering Platform. It is the only practical way to do this on Windows:
 * Windows gives user space no TUN device, and its routing table cannot be told "this connection
 * goes out *that* adapter" — both the interception and the per-flow choice of uplink come from
 * WinDivert's ability to receive from, and inject into, a named interface.
 *
 * The split of work:
 *
 *  - `winDivertWorker.ts`, run by Electron's own binary in Node mode (`ELECTRON_RUN_AS_NODE=1`),
 *    owns the two driver handles and the blocking receive loop. Nothing else runs there. It is a
 *    child process rather than `utilityProcess` because it must be able to block: the receive loop
 *    sits in `WinDivertRecv` and only returns when a packet arrives or the handle is shut.
 *  - This class is the app-side half: it starts that process, relays packets to and from the engine,
 *    and reports status. If the driver dies, the worker exits and this reports why instead of
 *    leaving the UI claiming to be running.
 *
 * Two handles, never one: a **receive** handle whose filter matches the console's port and every
 * uplink inbound, and a **send-only** handle used purely for injection. A send-only handle cannot
 * receive, so a packet the gateway injects can never come back into its own receive loop, which
 * would translate it twice.
 */

import { spawn, type ChildProcess } from 'node:child_process'
import { appendFileSync, existsSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { OPEN_FLAGS } from './winDivertDriver'
import type { WorkerRequest, WorkerResponse } from './winDivertProtocol'
import type {
  CaptureBackend,
  CaptureBackendConfig,
  CaptureBackendHandlers,
  CaptureBackendStatus
} from './capture'
import type { Transmit } from '../forwarder'
import { buildFilter, buildUplinkFilter, WINDIVERT_LAYER } from './windivertAddress'

/** Where the DLL is looked for: bundled next to the app, then the system directory. */
export function candidateDllPaths(resourcesPath?: string): string[] {
  const paths: string[] = []
  if (resourcesPath) {
    paths.push(join(resourcesPath, 'windivert', 'WinDivert.dll'))
    // A packaged build keeps `resources/**` unpacked beside the archive, which is where the driver
    // has to live: it is loaded from disk, and it loads its .sys from the same folder.
    paths.push(join(resourcesPath, 'app.asar.unpacked', 'resources', 'windivert', 'WinDivert.dll'))
    paths.push(join(resourcesPath, 'WinDivert.dll'))
  }
  // Running from the source tree (`npm run dev`): the bundled copy lives in resources/windivert.
  paths.push(join(process.cwd(), 'resources', 'windivert', 'WinDivert.dll'))
  paths.push(join(process.cwd(), 'windivert', 'WinDivert.dll'))
  paths.push('C:\\Windows\\System32\\WinDivert.dll')
  return paths
}

/**
 * Where the capture process ended up. Three shapes, because the bundler and the packager each move
 * it: next to this module (`out/main`), next to it from inside a shared chunk (`out/main/chunks`),
 * and unpacked beside the archive a packaged app runs from — a file inside `app.asar` cannot be
 * spawned. Development from the source tree covers the last one.
 */
export function workerCandidatePaths(): string[] {
  const candidates = [
    join(__dirname, 'winDivertWorker.js'),
    join(__dirname, '..', 'winDivertWorker.js'),
    join(process.cwd(), 'out', 'main', 'winDivertWorker.js')
  ]
  if (process.resourcesPath) {
    candidates.push(
      join(process.resourcesPath, 'app.asar.unpacked', 'out', 'main', 'winDivertWorker.js')
    )
  }
  return candidates
}

function findWorker(): string {
  for (const candidate of workerCandidatePaths()) {
    if (existsSync(candidate)) return candidate
  }
  return workerCandidatePaths()[0]
}

/** Whether WinDivert (DLL and, from the same folder, its driver) can be found. */
export function findWinDivert(resourcesPath?: string): string | null {
  for (const candidate of candidateDllPaths(resourcesPath)) {
    if (existsSync(candidate)) return candidate
  }
  return null
}

export interface WinDivertOptions {
  /** Overrides the DLL search, for a build that ships it elsewhere. */
  dllPath?: string
  resourcesPath?: string
  /** The compiled capture process. Defaults to the file next to this one. */
  workerPath?: string
  /** Injected by the tests: replaces the real child process. */
  spawnWorker?: (path: string) => ChildProcess
  /**
   * A file to append the capture process's account to. The panel shows the last lines; this keeps
   * the whole session, which is what someone needs to send when a run fails on a machine nobody
   * else can look at.
   */
  logPath?: string
}

/**
 * The backend. `start` resolves once the capture process says it is receiving, and rejects with a
 * sentence the window can show when it cannot (no driver, no Administrator, adapter gone).
 */
export class WinDivertBackend implements CaptureBackend {
  readonly name = 'windivert'
  private child: ChildProcess | null = null
  private handlers: CaptureBackendHandlers | null = null
  private stopping = false
  private ready: { resolve: () => void; reject: (error: Error) => void } | null = null
  private counters = { received: 0, sent: 0, dropped: 0 }
  private lastError: string | null = null
  private running = false
  /** What the capture process said about itself, newest last. Surfaced in the panel's detail box. */
  private readonly diagnostics: string[] = []

  constructor(private readonly options: WinDivertOptions = {}) {}

  async start(config: CaptureBackendConfig, handlers: CaptureBackendHandlers): Promise<void> {
    if (process.platform !== 'win32') throw new Error('WinDivert is only available on Windows')
    const dllPath = this.options.dllPath ?? findWinDivert(this.options.resourcesPath)
    if (!dllPath) {
      throw new Error(
        'WinDivert.dll was not found. Install WinDivert 1.4 (or use a Plexo build that bundles it), then try again.'
      )
    }
    const workerPath = this.options.workerPath ?? findWorker()
    if (!existsSync(workerPath)) {
      throw new Error(`The capture process is missing (${workerPath}). This build is incomplete.`)
    }

    this.handlers = handlers
    this.stopping = false
    this.counters = { received: 0, sent: 0, dropped: 0 }
    this.lastError = null

    const child = this.options.spawnWorker
      ? this.options.spawnWorker(workerPath)
      : spawnWorkerProcess(workerPath)
    this.child = child

    const request: WorkerRequest = {
      type: 'start',
      dllPath,
      flags: OPEN_FLAGS,
      config: {
        downstreamIfIdx: config.downstreamIfIdx,
        uplinks: config.uplinks,
        publicPorts: config.publicPorts,
        sniff: config.sniff ?? false
      }
    }
    this.diagnostics.length = 0
    this.note(`starting: ${workerPath}`)
    this.note(`driver: ${dllPath}`)
    this.note(`filter: ${describeFilter(request)}`)

    const ready = new Promise<void>((resolve, reject) => {
      this.ready = { resolve, reject }
      // A driver that cannot start (no Administrator, driver blocked by policy) answers quickly;
      // ten seconds is the point at which "something is wrong" is a better answer than "waiting".
      setTimeout(() => {
        if (this.ready) {
          this.ready = null
          reject(new Error('The capture process did not start in time.'))
        }
      }, 10_000).unref?.()
    })

    // The child's own output is the only explanation available when it dies before it can send
    // anything — a Node-level failure in the capture process never reaches the message channel.
    child.stderr?.on('data', (chunk: Buffer | string) => {
      for (const line of chunk.toString().split(/\r?\n/)) {
        if (line.trim().length > 0) this.note(line.trim())
      }
    })
    child.stdout?.on('data', (chunk: Buffer | string) => {
      for (const line of chunk.toString().split(/\r?\n/)) {
        if (line.trim().length > 0) this.note(line.trim())
      }
    })

    child.on('message', (message: WorkerResponse) => this.onMessage(message))
    child.on('error', (error: Error) => {
      this.lastError = error.message
      this.running = false
      this.ready?.reject(error)
      this.ready = null
    })
    child.on('exit', (code, signal) => {
      this.running = false
      this.note(`capture process exited (code ${code ?? 'null'}, signal ${signal ?? 'none'})`)
      if (!this.stopping) {
        this.lastError =
          this.lastError ??
          `The capture process stopped (${signal ?? `exit code ${code}`}). ` +
            (this.diagnostics.length > 0
              ? this.diagnostics[this.diagnostics.length - 1]
              : 'It gave no reason.')
      }
      this.ready?.reject(new Error(this.lastError ?? 'The capture process exited.'))
      this.ready = null
      this.child = null
    })

    send(child, request)
    await ready
    this.running = true
  }

  private onMessage(message: WorkerResponse): void {
    switch (message.type) {
      case 'ready':
        this.note('capture is open and receiving')
        this.ready?.resolve()
        this.ready = null
        this.running = true
        return
      case 'outbound':
        this.counters.received++
        this.handlers?.outbound(Buffer.from(message.packet))
        return
      case 'inbound':
        this.counters.received++
        this.handlers?.inbound(Buffer.from(message.packet), message.ifIdx)
        return
      case 'stats':
        this.counters.received = message.stats.received
        this.counters.sent = message.stats.sent
        this.counters.dropped = message.stats.dropped
        if (message.stats.lastError) this.lastError = message.stats.lastError
        return
      case 'stopped':
        this.running = false
        this.note('capture stopped')
        return
      case 'error':
        this.lastError = message.message
        this.running = false
        this.note(`capture error: ${message.message}`)
        for (const line of message.detail.split('\n').slice(0, 6)) this.note(line)
        this.ready?.reject(new Error(message.message))
        this.ready = null
        return
    }
  }

  send(packets: readonly Transmit[]): void {
    if (!this.child || packets.length === 0) return
    // One message per batch: the engine can produce a dozen fragments or a burst of deliveries, and
    // batching keeps the message rate proportional to the packet rate rather than tripling it.
    send(this.child, {
      type: 'send',
      packets: packets.map((entry) => ({ packet: entry.packet, ifIdx: entry.ifIdx }))
    })
    this.counters.sent += packets.length
  }

  async stop(): Promise<void> {
    this.stopping = true
    this.running = false
    this.handlers = null
    const child = this.child
    if (!child) return
    try {
      send(child, { type: 'stop' })
    } catch {
      // The process may already be gone.
    }
    await new Promise<void>((resolve) => {
      const timer = setTimeout(() => {
        // A wedged driver handle must not hold up a shutdown; the process is disposable.
        child.kill()
        resolve()
      }, 2000)
      child.once('exit', () => {
        clearTimeout(timer)
        resolve()
      })
    })
    this.child = null
  }

  status(): CaptureBackendStatus {
    return {
      running: this.running && this.lastError === null,
      error: this.lastError,
      ...this.counters,
      diagnostics: [...this.diagnostics]
    }
  }

  /** Keeps the last few lines for the panel, and every line for the log file. */
  private note(line: string): void {
    const stamped = `${new Date().toISOString()} ${line}`
    this.diagnostics.push(line)
    if (this.diagnostics.length > 24) this.diagnostics.shift()
    if (this.options.logPath) {
      try {
        appendFileSync(this.options.logPath, `${stamped}\n`)
      } catch {
        // A log that cannot be written must not stop the gateway from running.
      }
    }
  }

  /**
   * Opens a capture handle, then closes it: what the window's "test" button runs, and what turns
   * "not supported" into a specific reason instead of a generic failure.
   */
  async selfTest(config: CaptureBackendConfig): Promise<{ ok: boolean; detail: string }> {
    if (process.platform !== 'win32') return { ok: false, detail: 'WinDivert is a Windows driver.' }
    const dllPath = this.options.dllPath ?? findWinDivert(this.options.resourcesPath)
    if (!dllPath) return { ok: false, detail: 'WinDivert.dll was not found.' }
    try {
      // Loading here, in the app's process, is safe: opening a sniffing handle does not block.
      const { KoffiWinDivertDriver } = await import('./winDivertDriver')
      const driver = await KoffiWinDivertDriver.create(dllPath)
      // Exactly the filter a real run would use, so a filter WinDivert rejects is caught here
      // rather than at the moment the user starts the gateway.
      const filter = describeFilter({
        type: 'start',
        dllPath,
        flags: OPEN_FLAGS,
        config: {
          downstreamIfIdx: config.downstreamIfIdx,
          uplinks: config.uplinks,
          publicPorts: config.publicPorts
        }
      })
      const handle = driver.open(filter.replace(/^filter: /, ''), OPEN_FLAGS.RECV_ONLY)
      driver.close(handle)
      return {
        ok: true,
        detail: `WinDivert is working (${dllPath}); interface ${config.downstreamIfIdx} can be captured.`
      }
    } catch (error) {
      return { ok: false, detail: (error as Error).message }
    }
  }
}

/** `spawn` rather than Electron's `utilityProcess`, so this module stays testable off Electron. */
function spawnWorkerProcess(path: string): ChildProcess {
  const child = spawn(process.execPath, [path], {
    // Electron's binary is not a Node runtime unless told to be.
    env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
    // stdout and stderr are kept: a capture process that dies before it can say anything over IPC
    // explains itself here, and that text is what the panel shows.
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    windowsHide: true
  })
  return child
}

/**
 * The filter both the capture loop and the self-test use, rendered once here so the text in the
 * diagnostics is exactly what the driver was asked for.
 */
function describeFilter(request: Extract<WorkerRequest, { type: 'start' }>): string {
  const parts = [
    buildFilter({ ifIdx: request.config.downstreamIfIdx, direction: 'inbound' }),
    ...request.config.uplinks.map((uplink) =>
      buildUplinkFilter({
        ifIdx: uplink.ifIdx,
        minPort: request.config.publicPorts.min,
        maxPort: request.config.publicPorts.max
      })
    )
  ]
  return parts.join(' or ')
}

function send(child: ChildProcess, message: WorkerRequest): void {
  child.send?.(message)
}

/** Every WinDivert build ships these; used to tell "not installed" from "installed, broken". */
export function driverFilesIn(dir: string): string[] {
  try {
    return readdirSync(dir).filter((name) => /^WinDivert/i.test(name))
  } catch {
    return []
  }
}

export { WINDIVERT_LAYER }
