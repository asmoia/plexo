/**
 * The messages between the app and its capture process. One file, both directions, so a change to
 * one side is a compile error on the other.
 */

import type { LoopConfig, LoopStats, OpenFlagSet } from './winDivertLoop'

export type WorkerRequest =
  | {
      type: 'start'
      config: LoopConfig
      dllPath: string
      flags: OpenFlagSet
    }
  | { type: 'send'; packets: { packet: Uint8Array; ifIdx: number }[] }
  | { type: 'stop' }

export type WorkerResponse =
  /** The handles are open and packets are about to arrive; `filter` is what the driver accepted. */
  | { type: 'ready'; filter: string }
  | { type: 'outbound'; packet: Uint8Array }
  | { type: 'inbound'; packet: Uint8Array; ifIdx: number }
  | { type: 'stats'; stats: LoopStats }
  | { type: 'stopped'; stats: LoopStats }
  /** A failure with the driver's own words, plus where in this process it happened. */
  | { type: 'error'; message: string; detail: string }
