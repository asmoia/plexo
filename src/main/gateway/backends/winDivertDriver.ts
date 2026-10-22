/**
 * The driver interface the capture loop runs against, and its WinDivert implementation.
 *
 * Splitting the loop from the driver is what makes the loop testable: `winDivertLoop.test.ts` runs
 * it against a fake driver that hands over scripted packets, which pins the dispatch rules, the
 * send path and the shutdown behaviour without a Windows machine or a kernel driver.
 *
 * The WinDivert calls here are **synchronous on purpose**. `WinDivertRecv` blocks until a packet
 * arrives, which is exactly right in a process whose only job is capturing — and disastrous in the
 * one that draws the window. So this driver only ever runs in the capture process spawned by
 * `winDivert.ts`, where blocking costs nothing.
 */

import {
  decodeAddress,
  encodeAddress,
  WINDIVERT_ADDRESS_SIZE,
  WINDIVERT_LAYER,
  WINDIVERT_PARAM
} from './windivertAddress'

/** What `WinDivertOpen` may be told to do. */
export const OPEN_FLAGS = {
  SNIFF: 0x0001,
  DROP: 0x0002,
  /** A handle that cannot receive: used for injection, so its packets never re-enter the capture. */
  RECV_ONLY: 0x0004,
  SEND_ONLY: 0x0008,
  /** Do not try to install the driver: if it is not there, fail rather than raise a UAC prompt from
   * a background process. Installation is the installer's job. */
  NO_INSTALL: 0x0010
} as const

/** A packet the driver handed over. */
export interface ReceivedPacket {
  packet: Buffer
  /** The adapter it arrived on. */
  ifIdx: number
  ipv6: boolean
  /**
   * Whether the driver says the checksum was already computed/verified (NIC offload), in which case
   * the bytes in the packet may not match the header's checksum field.
   */
  checksumsValid: boolean
}

/**
 * What one `recv` amounted to. Distinguishing "nothing arrived" from "the handle is gone" is the
 * difference between a gateway that idles quietly and one that shuts itself down the first time the
 * console is silent for a moment.
 */
export type RecvResult =
  | { kind: 'packet'; received: ReceivedPacket }
  /** The call timed out, or the driver had nothing to give. Not an error: keep waiting. */
  | { kind: 'idle' }
  /** The handle was shut down (stop, close, or the parent going away). The loop should end. */
  | { kind: 'aborted' }
  | { kind: 'error'; message: string }

export interface WinDivertDriver {
  /** Opens a handle; throws with a useful message when the driver refuses. */
  open(filter: string, flags: number, priority?: number): number
  /** Blocks until something happens, and says what. */
  recv(handle: number): RecvResult
  /** Injects a packet out of `ifIdx`. Returns false when the driver refused it. */
  send(handle: number, packet: Buffer, ifIdx: number): boolean
  setQueue(handle: number, length: number, timeMs: number): void
  /** Makes a blocked `recv` return. */
  shutdown(handle: number): void
  close(handle: number): void
  /** The last OS error, for a helpful message. */
  lastError(): string
}

const PACKET_BUFFER_BYTES = 65_535

/** The Win32 errors this code distinguishes, in words the UI can show without a lookup. */
const WIN_ERRORS: Record<number, string> = {
  0: 'no error',
  5: 'access denied — Plexo must run as Administrator',
  6: 'invalid handle',
  8: 'not enough memory to open the capture handle',
  87: 'the capture filter was rejected',
  232: 'no packet was waiting',
  995: 'the capture handle was shut down',
  1460: 'the receive timed out',
  1058: 'the WinDivert driver is disabled — run the installer again or reboot',
  1275: 'the WinDivert driver was blocked by Windows — driver signature or memory integrity'
}

/**
 * A handle the driver returned, as a number. koffi gives a `uintptr_t` back as a number, or as a
 * BigInt on a platform where it prefers that; either way this is what the rest of the file uses.
 */
function handleValue(value: unknown): number {
  if (typeof value === 'bigint') return Number(value)
  if (typeof value === 'number') return Number.isFinite(value) ? value : 0
  // A `void *` declaration would give an opaque pointer object here; its address is still readable,
  // and treating it as 0 would report a healthy handle as a failure.
  return Number(String(value)) || 0
}

function describeWinError(code: number): string {
  const known = WIN_ERRORS[code]
  return known ? `${known} (error ${code})` : `Windows error ${code}`
}

/** The real thing: koffi → WinDivert.dll → the WinDivert kernel driver. */
export class KoffiWinDivertDriver implements WinDivertDriver {
  private readonly lib: {
    open: (filter: string, layer: number, priority: number, flags: number) => unknown
    lastError: () => number
    recv: (...args: unknown[]) => unknown
    send: (...args: unknown[]) => unknown
    close: (handle: number) => unknown
    setParam: (handle: number, param: number, value: bigint) => unknown
    shutdown: (handle: number, how: number) => unknown
  }
  private readonly packet = Buffer.alloc(PACKET_BUFFER_BYTES)
  private readonly receivedLength = Buffer.alloc(4)
  private readonly address = Buffer.alloc(WINDIVERT_ADDRESS_SIZE)
  private error = 'no error'

  // Declared here so the type of `lib` is the koffi function shape; built in `create`.
  private constructor(lib: KoffiWinDivertDriver['lib']) {
    this.lib = lib
  }

  /**
   * The prototypes are declared with `uintptr_t` handles, not `void *`.
   *
   * koffi returns a `void *` as an opaque object, and that object throws on every conversion —
   * `!handle`, `handle === 0`, `Number(handle)` — with "Cannot convert object to primitive value".
   * That is exactly what the first version did, so `WinDivertOpen` succeeded and the code immediately
   * threw on the result, and every Windows start failed with that sentence. `uintptr_t` is the same
   * ABI (a pointer-sized integer) and arrives as a number, which is comparable and printable.
   */
  static async create(dllPath: string): Promise<KoffiWinDivertDriver> {
    const { default: koffi } = await import('koffi')
    const lib = koffi.load(dllPath)
    // WinDivert reports why a call failed through the OS's last-error value, which koffi does not
    // surface by itself.
    const kernel32 = koffi.load('kernel32.dll')
    const getLastError = kernel32.func('uint32_t GetLastError()')
    return new KoffiWinDivertDriver({
      lastError: () => Number(getLastError()) || 0,
      open: lib.func(
        'uintptr_t WinDivertOpen(const char *filter, int layer, int16_t priority, uint64_t flags)'
      ),
      recv: lib.func(
        'bool WinDivertRecv(uintptr_t handle, void *packet, uint32_t packetLen, uint32_t *recvLen, void *addr)'
      ),
      send: lib.func(
        'bool WinDivertSend(uintptr_t handle, const void *packet, uint32_t packetLen, uint32_t *sendLen, const void *addr)'
      ),
      close: lib.func('bool WinDivertClose(uintptr_t handle)'),
      setParam: lib.func('bool WinDivertSetParam(uintptr_t handle, int param, uint64_t value)'),
      shutdown: lib.func('bool WinDivertShutdown(uintptr_t handle, int how)')
    })
  }

  open(filter: string, flags: number, priority = 0): number {
    const handle = handleValue(this.lib.open(filter, WINDIVERT_LAYER.NETWORK, priority, flags))
    if (handle === 0) {
      const code = this.lib.lastError()
      this.error = `WinDivertOpen failed: ${describeWinError(code)}`
      throw new Error(this.error)
    }
    return handle
  }

  recv(handle: number): RecvResult {
    this.receivedLength.writeUInt32LE(0, 0)
    const ok = this.lib.recv(
      handle,
      this.packet,
      PACKET_BUFFER_BYTES,
      this.receivedLength,
      this.address
    )
    if (!ok) {
      const code = this.lib.lastError()
      // 995 ERROR_OPERATION_ABORTED: WinDivertShutdown closed the handle under us. That is the
      // normal way this loop ends.
      if (code === 995) return { kind: 'aborted' }
      // 232 ERROR_NO_DATA / 1460 ERROR_TIMEOUT: nothing arrived. Not a failure.
      if (code === 232 || code === 1460) return { kind: 'idle' }
      this.error = `WinDivertRecv failed: ${describeWinError(code)}`
      return { kind: 'error', message: this.error }
    }
    const length = this.receivedLength.readUInt32LE(0)
    if (length === 0 || length > PACKET_BUFFER_BYTES) return { kind: 'idle' }
    const decoded = decodeAddress(this.address)
    return {
      kind: 'packet',
      received: {
        // A copy: the engine may keep these bytes to fragment or re-send them.
        packet: Buffer.from(this.packet.subarray(0, length)),
        ifIdx: decoded.ifIdx,
        ipv6: decoded.ipv6,
        checksumsValid: decoded.ipChecksum && decoded.tcpChecksum && decoded.udpChecksum
      }
    }
  }

  send(handle: number, packet: Buffer, ifIdx: number): boolean {
    const sentLength = Buffer.alloc(4)
    const address = encodeAddress({ ifIdx, outbound: true })
    const ok = this.lib.send(handle, packet, packet.length, sentLength, address)
    if (!ok) this.error = `WinDivertSend failed: ${describeWinError(this.lib.lastError())}`
    return Boolean(ok)
  }

  setQueue(handle: number, length: number, timeMs: number): void {
    // A deep queue absorbs a console's burst instead of dropping it while the engine is busy.
    this.lib.setParam(handle, WINDIVERT_PARAM.QUEUE_LEN, BigInt(length))
    this.lib.setParam(handle, WINDIVERT_PARAM.QUEUE_TIME, BigInt(timeMs))
  }

  shutdown(handle: number): void {
    // WINDIVERT_SHUTDOWN_RECV = 1: makes the blocked recv in this process return.
    this.lib.shutdown(handle, 1)
  }

  close(handle: number): void {
    this.lib.close(handle)
  }

  lastError(): string {
    return this.error
  }
}
