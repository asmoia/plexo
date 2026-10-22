/**
 * The WINDIVERT_ADDRESS structure, encoded and decoded by hand.
 *
 * WinDivert tells the caller, for every packet, where it came from and where it should go — and a
 * NAT needs the second half of that: sending a rewritten packet out of a *chosen* adapter is the
 * one thing the WinDivert API offers that the Windows routing table does not (Windows would send it
 * out the default route and ignore the interface we picked).
 *
 * The struct is a C bitfield, so it is handled as a fixed-size buffer with the offsets written out
 * rather than as a koffi struct: koffi's bitfield support depends on the platform's C ABI, and a
 * silent mismatch here sends packets out of the wrong adapter — or nowhere.
 *
 * The layout below is **WinDivert 2.2.2's**, byte for byte, which is the version this app ships:
 *
 *   INT64  Timestamp;                     offset 0,  8 bytes
 *   UINT32 Layer:8, Event:8, Sniffed:1, Outbound:1, Loopback:1, Impostor:1, IPv6:1,
 *          IPChecksum:1, TCPChecksum:1, UDPChecksum:1, Reserved1:8;   offset 8,  4 bytes
 *   UINT32 Reserved2;                     offset 12, 4 bytes
 *   union { WINDIVERT_DATA_NETWORK { UINT32 IfIdx; UINT32 SubIfIdx; }; …; UINT8 Reserved3[64]; };
 *                                         offset 16, 64 bytes
 *
 *   sizeof(WINDIVERT_ADDRESS) == 80
 *
 * Getting this wrong is not a small thing, and it was wrong once: an earlier version used WinDivert
 * **1.4's** layout (64 bytes, IfIdx at offset 12, no Reserved2), so every captured packet decoded
 * with interface index 0 — and an interface index is the whole mechanism by which the gateway chooses
 * an uplink. A 64-byte buffer was also 16 bytes too small for the driver to write into.
 *
 * `windivertAddress.test.ts` pins every field of the codec, and the Windows lab checks the codec
 * against the driver that actually fills it in.
 */

/** `WINDIVERT_LAYER` values. */
export const WINDIVERT_LAYER = {
  NETWORK: 0,
  NETWORK_FORWARD: 1,
  FLOW: 2,
  SOCKET: 3,
  REFLECT: 4
} as const

/** `WINDIVERT_EVENT` for network-layer packets. */
export const WINDIVERT_EVENT_NETWORK_PACKET = 0

/** `WINDIVERT_PARAM` values used to size the queue. */
export const WINDIVERT_PARAM = { QUEUE_LEN: 0, QUEUE_TIME: 1, QUEUE_SIZE: 2 } as const

/** `sizeof(WINDIVERT_ADDRESS)` in WinDivert 2.2.2. The driver writes all 80 bytes. */
export const WINDIVERT_ADDRESS_SIZE = 80

/** The flags byte triple at offset 8. */
export interface AddressFlags {
  layer: number
  event: number
  sniffed: boolean
  outbound: boolean
  loopback: boolean
  impostor: boolean
  ipv6: boolean
  ipChecksum: boolean
  tcpChecksum: boolean
  udpChecksum: boolean
}

export interface WinDivertAddress extends AddressFlags {
  timestamp: bigint
  ifIdx: number
  subIfIdx: number
}

const FLAG_BYTE = 8
/** The union starts here in 2.2.2: `Reserved2` sits between the flags and the network data. */
const UNION_START = 16
const IFIDX = UNION_START
const SUBIFIDX = UNION_START + 4

/**
 * Reads an address out of the 64 bytes the driver filled. Anything past the fields we use is left
 * alone, so an address from a version with extra fields still parses.
 */
export function decodeAddress(buffer: Buffer): WinDivertAddress {
  const flags = buffer.readUInt32LE(FLAG_BYTE)
  return {
    timestamp: buffer.readBigInt64LE(0),
    layer: flags & 0xff,
    event: (flags >>> 8) & 0xff,
    sniffed: ((flags >>> 16) & 1) === 1,
    outbound: ((flags >>> 17) & 1) === 1,
    loopback: ((flags >>> 18) & 1) === 1,
    impostor: ((flags >>> 19) & 1) === 1,
    ipv6: ((flags >>> 20) & 1) === 1,
    ipChecksum: ((flags >>> 21) & 1) === 1,
    tcpChecksum: ((flags >>> 22) & 1) === 1,
    udpChecksum: ((flags >>> 23) & 1) === 1,
    ifIdx: buffer.readUInt32LE(IFIDX),
    subIfIdx: buffer.readUInt32LE(SUBIFIDX)
  }
}

export interface EncodeAddressOptions {
  /** The adapter to send the packet out of. */
  ifIdx: number
  /** True for a packet leaving this machine (which is what forwarding is). */
  outbound?: boolean
  /** Set for an IPv6 packet; the engine drops those, so normally false. */
  ipv6?: boolean
  /** The driver computed the checksums itself (it does not; we compute them). */
  checksumsValid?: boolean
  layer?: number
  event?: number
}

/**
 * Builds the address for `WinDivertSend`: an empty struct with the outbound flag, the IPv4 flag, and
 * the interface index set — which is the whole mechanism by which a flow is pinned to an uplink.
 */
export function encodeAddress(options: EncodeAddressOptions): Buffer {
  const buffer = Buffer.alloc(WINDIVERT_ADDRESS_SIZE)
  const layer = options.layer ?? WINDIVERT_LAYER.NETWORK
  const event = options.event ?? WINDIVERT_EVENT_NETWORK_PACKET
  let flags = (layer & 0xff) | ((event & 0xff) << 8)
  if (options.outbound ?? true) flags |= 1 << 17
  if (options.ipv6) flags |= 1 << 20
  if (options.checksumsValid) flags |= (1 << 21) | (1 << 22) | (1 << 23)
  buffer.writeUInt32LE(flags >>> 0, FLAG_BYTE)
  // Offset 12 is Reserved2 and must stay zero; IfIdx and SubIfIdx live in the union at 16 and 20.
  buffer.writeUInt32LE(0, 12)
  buffer.writeUInt32LE(options.ifIdx, IFIDX)
  buffer.writeUInt32LE(0, SUBIFIDX)
  return buffer
}

/**
 * The WinDivert filter for one direction. The gateway uses separate handles per direction and per
 * interface (each handle becomes its own capture loop with its own queue), so the filters stay
 * simple and a packet can never be captured twice by the same loop.
 */
export function buildFilter(options: {
  ifIdx: number
  direction: 'inbound' | 'outbound' | 'both'
}): string {
  const direction =
    options.direction === 'both'
      ? ''
      : options.direction === 'inbound'
        ? 'inbound and '
        : 'outbound and '
  // IPv4 only: the gateway does not translate IPv6, and capturing it would only create work it
  // has to drop. Loopback is excluded so traffic inside the PC never enters the engine.
  return `${direction}ifIdx == ${options.ifIdx} and ip and not loopback`
}

/**
 * The filter for an uplink's inbound side.
 *
 * It must not match everything: the PC's own traffic (Plexo's downloads, the browser, Windows
 * Update) arrives on the same adapters, and a capture handle that takes it would remove it from the
 * stack, so the whole machine would lose its internet the moment the gateway started. The gateway
 * only ever needs the *return* traffic of the console's flows, and every one of those is addressed
 * to a public port the gateway allocated for itself — a port the PC's own sockets never use, because
 * the allocator owns the whole range.
 *
 * Ports are compared rather than listed: WinDivert filters have no set membership, and a filter
 * rebuilt on every allocation would mean reopening handles mid-download.
 */
export function buildUplinkFilter(options: {
  ifIdx: number
  minPort: number
  maxPort: number
}): string {
  const range = (protocol: string, field: string): string =>
    `(${protocol} and ${field} >= ${options.minPort} and ${field} <= ${options.maxPort})`
  return (
    `inbound and ifIdx == ${options.ifIdx} and ip and not loopback and ` +
    `(${range('tcp', 'tcp.DstPort')} or ${range('udp', 'udp.DstPort')})`
  )
}
