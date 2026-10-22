/**
 * The capture loop, in one place and driver-agnostic.
 *
 * It is deliberately dumb: receive, hand the packet to the engine, send back whatever the engine
 * produced. Every decision — NAT, uplink choice, failing over, fragmentation — belongs to the
 * engine; this loop only exists because a blocking `recv` has to live somewhere, and putting it in
 * its own process keeps the window responsive and a driver crash away from the app.
 *
 * Because it is separate and has no platform code, the loop is tested against a fake driver.
 */

import type { Transmit } from '../forwarder'
import type { WinDivertDriver } from './winDivertDriver'
import { buildFilter, buildUplinkFilter } from './windivertAddress'

/** The WinDivert open flags, as a plain number record so callers can pass variants. */
export type OpenFlagSet = Record<
  'SNIFF' | 'DROP' | 'RECV_ONLY' | 'SEND_ONLY' | 'NO_INSTALL',
  number
>

const DEFAULT_FLAGS: OpenFlagSet = {
  SNIFF: 0x0001,
  DROP: 0x0002,
  RECV_ONLY: 0x0004,
  SEND_ONLY: 0x0008,
  NO_INSTALL: 0x0010
}

export interface LoopConfig {
  /** The console's interface index. */
  downstreamIfIdx: number
  /** Uplinks, in preference order, with their interface indexes. */
  uplinks: { ifIdx: number; id: string }[]
  /**
   * The public ports the gateway allocates for the console, and therefore the only ones whose
   * return traffic it may take off an uplink. Everything else on those adapters belongs to the PC
   * and must be left alone — see `buildUplinkFilter`.
   */
  publicPorts: { min: number; max: number }
  /**
   * Open the receive handle as a sniffer: packets are copied to this process and left in the stack.
   * Never used for real forwarding (a forwarded packet must not also be delivered to Windows), but it
   * is what lets the Windows test lab look at live traffic on a machine whose own network must keep
   * working.
   */
  sniff?: boolean
  /** Queue length and time, so a burst is absorbed rather than dropped. */
  queueLength?: number
  queueTimeMs?: number
  priority?: number
}

export interface LoopHandlers {
  /** A packet from the console. */
  outbound: (packet: Buffer, ifIdx: number) => void
  /** A packet from an uplink. */
  inbound: (packet: Buffer, ifIdx: number) => void
}

export interface LoopStats {
  received: number
  sent: number
  /** Packets the driver refused to send, and packets that could not be delivered. */
  dropped: number
  /** Reads that found nothing waiting. Normal on an idle connection, so never a reason to stop. */
  idleReads: number
  lastError: string | null
}

/**
 * A read that returns "nothing waiting" is the ordinary state of an idle connection — a console
 * asleep on the dashboard, or the second before it sends anything. The loop waits a moment and reads
 * again, forever. Only a *failed* read (a handle the driver closed, an adapter that vanished) ends
 * the loop, and even that has to fail repeatedly to be believed.
 */
const IDLE_BACKOFF_MS = 1
const MAX_ERRORS_IN_A_ROW = 5

/** A synchronous sleep, which is what this process's blocking loop wants. */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
}

export class CaptureLoop {
  private receiveHandle: number | null = null
  private sendHandle: number | null = null
  private stopping = false
  private errorsInARow = 0
  private readonly stats: LoopStats = {
    received: 0,
    sent: 0,
    dropped: 0,
    idleReads: 0,
    lastError: null
  }

  constructor(
    private readonly driver: WinDivertDriver,
    private readonly config: LoopConfig,
    private readonly handlers: LoopHandlers,
    /** Injected so the tests can use small, readable bit values instead of the real ones. */
    private readonly flags: OpenFlagSet = DEFAULT_FLAGS
  ) {}

  /**
   * The filter handed to the driver.
   *
   * The console's port is taken whole: nothing else is on that cable, and those packets are for the
   * internet, so they must be removed from the stack rather than dropped by it.
   *
   * Each uplink is taken **only for the gateway's own public ports**. Capturing an entire uplink
   * would take the PC's own traffic — this app's downloads included — off the stack, and the computer
   * would lose its internet.
   */
  filter(): string {
    const parts = [buildFilter({ ifIdx: this.config.downstreamIfIdx, direction: 'inbound' })]
    for (const uplink of this.config.uplinks) {
      parts.push(
        buildUplinkFilter({
          ifIdx: uplink.ifIdx,
          minPort: this.config.publicPorts.min,
          maxPort: this.config.publicPorts.max
        })
      )
    }
    return parts.join(' or ')
  }

  /** Opens the handles. Throws with the driver's message when it refuses. */
  open(): void {
    const filter = this.filter()
    const receiveFlags = this.config.sniff
      ? this.flags.RECV_ONLY | this.flags.SNIFF
      : this.flags.RECV_ONLY
    this.receiveHandle = this.driver.open(filter, receiveFlags, this.config.priority ?? 0)
    this.driver.setQueue(
      this.receiveHandle,
      this.config.queueLength ?? 4096,
      this.config.queueTimeMs ?? 2000
    )
    // A separate, send-only handle: a packet injected through it cannot be captured back, which is
    // what stops the gateway from re-processing its own translated packets in a loop.
    this.sendHandle = this.driver.open('false', this.flags.SEND_ONLY | this.flags.NO_INSTALL, 0)
  }

  /**
   * Runs until `stop()`. Blocking on `recv` inside this process is the point: the caller (a
   * utilityProcess) has nothing else to do, and the app's own event loop is in another process.
   */
  run(): void {
    if (this.receiveHandle === null) this.open()
    const handle = this.receiveHandle
    if (handle === null) throw new Error('the capture handle is not open')
    while (!this.stopping) {
      let result
      try {
        result = this.driver.recv(handle)
      } catch (error) {
        this.stats.lastError = (error as Error).message
        break
      }
      if (result.kind === 'idle') {
        // Nothing arrived. Wait a millisecond so an idle console costs no CPU, and read again.
        this.stats.idleReads++
        sleepSync(IDLE_BACKOFF_MS)
        continue
      }
      if (result.kind === 'aborted' || this.stopping) break
      if (result.kind === 'error') {
        this.stats.lastError = result.message
        this.errorsInARow++
        if (this.errorsInARow >= MAX_ERRORS_IN_A_ROW) break
        sleepSync(IDLE_BACKOFF_MS)
        continue
      }
      this.errorsInARow = 0
      const received = result.received
      if (received.ipv6) {
        // IPv6 is not translated by the gateway; the filter excludes it, and anything that slips
        // through is not forwarded rather than leaked untranslated.
        this.stats.dropped++
        continue
      }
      this.stats.received++
      if (received.ifIdx === this.config.downstreamIfIdx)
        this.handlers.outbound(received.packet, received.ifIdx)
      else this.handlers.inbound(received.packet, received.ifIdx)
    }
    this.close()
  }

  /** Injects what the engine produced, one call per packet, with the uplink's interface index. */
  send(packets: readonly Transmit[]): void {
    const handle = this.sendHandle
    if (handle === null) return
    for (const entry of packets) {
      try {
        if (this.driver.send(handle, entry.packet, entry.ifIdx)) this.stats.sent++
        else this.stats.dropped++
      } catch (error) {
        this.stats.dropped++
        this.stats.lastError = (error as Error).message
      }
    }
  }

  stop(): void {
    this.stopping = true
    const handle = this.receiveHandle
    if (handle !== null) {
      try {
        this.driver.shutdown(handle)
      } catch {
        // A handle the driver already closed needs nothing.
      }
    }
  }

  close(): void {
    if (this.receiveHandle !== null) {
      try {
        this.driver.close(this.receiveHandle)
      } catch {
        // As above.
      }
      this.receiveHandle = null
    }
    if (this.sendHandle !== null) {
      try {
        this.driver.close(this.sendHandle)
      } catch {
        // As above.
      }
      this.sendHandle = null
    }
  }

  report(): LoopStats {
    return { ...this.stats }
  }
}
