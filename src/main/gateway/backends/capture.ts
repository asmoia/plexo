/**
 * What a packet-capture backend must do, so the gateway's engine never depends on one.
 *
 * The engine (`forwarder.ts`) decides; a backend moves bytes. Windows has exactly one way to do
 * that without a kernel driver of our own (WinDivert), but keeping the seam means the service, the
 * DHCP/DNS servers and the whole UI can run — and be tested — on a machine where nothing can be
 * intercepted, with the gateway honestly reporting "not intercepting" instead of pretending.
 */

import type { Transmit } from '../forwarder'

export interface CaptureBackendStatus {
  /** Packets are actually being intercepted right now. */
  running: boolean
  /** One sentence for the UI when they are not. */
  error: string | null
  /** Packets received since start, and packets sent. */
  received: number
  sent: number
  /** Packets the driver refused, or that could not be parsed. */
  dropped: number
  /**
   * The last few lines the capture process wrote about itself, for the panel's detail box: the
   * driver's errors, and the exit code when it died. Without this the UI can only say "it stopped".
   */
  diagnostics: string[]
}

export interface CaptureBackendHandlers {
  /** A packet arrived on the console port. */
  outbound: (packet: Buffer) => void
  /** A packet arrived on one of the uplinks, whose interface index is given. */
  inbound: (packet: Buffer, ifIdx: number) => void
}

export interface CaptureBackendConfig {
  /** The console's interface index: its packets are the ones to relay. */
  downstreamIfIdx: number
  /** Uplink interface indices, and the addresses to NAT to, in preference order. */
  uplinks: { ifIdx: number; id: string }[]
  /** Interface index → id, so an inbound packet can be attributed to an uplink. */
  labels: Map<number, string>
  /**
   * The public ports the NAT allocates. Return traffic is only captured for these, so the PC's own
   * internet traffic on the same adapters is never touched.
   */
  publicPorts: { min: number; max: number }
  /** Copy packets instead of taking them, so a machine's own networking is unaffected. */
  sniff?: boolean
}

export interface CaptureBackend {
  readonly name: string
  /** Opens the capture; resolves once packets are flowing or rejects with a reason. */
  start(config: CaptureBackendConfig, handlers: CaptureBackendHandlers): Promise<void>
  stop(): Promise<void>
  /** Sends the packets the engine produced. Fire-and-forget: a dropped packet is a retransmit. */
  send(packets: readonly Transmit[]): void
  status(): CaptureBackendStatus
  /** Runs a self-test (open, inject nothing, close) and reports what happened. */
  selfTest(config: CaptureBackendConfig): Promise<{ ok: boolean; detail: string }>
}
