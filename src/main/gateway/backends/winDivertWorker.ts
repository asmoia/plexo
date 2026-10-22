/**
 * The capture process.
 *
 * It is spawned by `winDivert.ts` as a plain child process running Electron's own binary in Node
 * mode (`ELECTRON_RUN_AS_NODE=1`), which is what lets it block forever inside `WinDivertRecv`
 * without freezing the window — and what makes a driver crash take this process down instead of the
 * app. The main process sees the exit and reports it, rather than dying with it.
 *
 * The transport is therefore `child_process`'s IPC (`process.send` / `process.on('message')`), not
 * Electron's `utilityProcess` `parentPort`. Both are supported here because getting this wrong is
 * silent: an unsupported channel throws at import time, the process exits with code 1 before it can
 * say anything, and the app reports the driver as broken when the driver was fine.
 *
 * It does one thing: receive packets, forward them to the main process, inject what comes back.
 * The engine (NAT, balancing, failover) lives in the main process, where the measurements, the
 * settings and the window are — one implementation, unit-tested, rather than a second copy here.
 */

import { KoffiWinDivertDriver } from './winDivertDriver'
import { CaptureLoop, type LoopConfig } from './winDivertLoop'
import type { WorkerRequest } from './winDivertProtocol'
import { openTransport, type CaptureTransport, type TransportSource } from './winDivertTransport'

let loop: CaptureLoop | null = null

function start(
  transport: CaptureTransport,
  request: Extract<WorkerRequest, { type: 'start' }>
): void {
  void (async () => {
    try {
      // The DLL path and the whole driver conversation happen here, so a failure carries the
      // driver's own words back to the panel instead of an exit code with no explanation.
      const driver = await KoffiWinDivertDriver.create(request.dllPath)
      const config: LoopConfig = request.config
      const created = new CaptureLoop(
        driver,
        config,
        {
          outbound: (packet) => transport.send({ type: 'outbound', packet }),
          inbound: (packet, ifIdx) => transport.send({ type: 'inbound', packet, ifIdx })
        },
        request.flags
      )
      created.open()
      loop = created
      transport.send({ type: 'ready', filter: created.filter() })
      // Statistics on a slow timer so the window's numbers are live without a message per packet;
      // the loop itself never yields.
      const reporter = setInterval(() => {
        if (loop) transport.send({ type: 'stats', stats: loop.report() })
      }, 1000)
      reporter.unref?.()
      created.run()
      clearInterval(reporter)
      transport.send({ type: 'stopped', stats: created.report() })
    } catch (error) {
      const detail = error instanceof Error ? (error.stack ?? error.message) : String(error)
      try {
        transport.send({ type: 'error', message: (error as Error).message, detail })
      } catch {
        // The channel is gone; stderr is the only place left, and `winDivert.ts` keeps it.
        process.stderr.write(`capture failed: ${detail}\n`)
      }
      // Leave nothing running: a capture process that failed has no reason to hold the channel open,
      // and the app reads the exit code as the end of this attempt.
      setImmediate(() => process.exit(1))
    }
  })()
}

function main(): void {
  let transport: CaptureTransport
  try {
    transport = openTransport(process as unknown as TransportSource)
  } catch (error) {
    process.stderr.write(`${(error as Error).message}\n`)
    process.exit(1)
  }
  transport.receive((raw) => {
    const message = raw as WorkerRequest
    switch (message.type) {
      case 'start':
        start(transport, message)
        break
      case 'send':
        loop?.send(
          message.packets.map((entry) => ({
            packet: Buffer.from(entry.packet),
            ifIdx: entry.ifIdx
          }))
        )
        break
      case 'stop':
        if (loop) {
          loop.stop()
        } else {
          // Nothing was ever opened; there is nothing to wait for.
          process.exit(0)
        }
        break
    }
  })
}

// The parent going away must not leave a driver handle open — and must not leave this process
// behind holding one, which is what an orphan on a capture handle would be.
process.on('disconnect', () => {
  loop?.close()
  process.exit(0)
})
process.on('exit', () => loop?.close())

try {
  main()
} catch (error) {
  process.stderr.write(`capture process failed to start: ${(error as Error).stack ?? ''}\n`)
  process.exit(1)
}
