/**
 * IPv4 / TCP / UDP / ICMP wire-format handling for the LAN gateway.
 *
 * Everything the gateway does to a packet — source-NAT, sending it out a chosen adapter, translating
 * it back, clamping the MSS, splitting it to fit an uplink's MTU, refusing a flow — is a rewrite of
 * the bytes an adapter handed us. This module is the only place that knows those bytes' layout: it
 * parses what it needs, rewrites in place on a copy, and recomputes every checksum it invalidated.
 *
 * No Node sockets and no OS calls here, on purpose: the whole gateway engine is exercised by
 * `npm run test:unit` on any platform, and only the capture backend (backends/) is Windows-specific.
 *
 * IPv4 only. The PS4's traffic is IPv4 in practice (PSN over IPv4, and a LAN with no DHCPv6 or
 * router advertisements from us has no way to get an IPv6 address), and NAT for IPv6 is a different
 * problem; the gateway forwards IPv6 only if the uplink's own prefix happens to cover the LAN, so by
 * default IPv6 is dropped rather than leaked out untranslated.
 */

/** IANA protocol numbers the gateway understands. */
export const IPPROTO = { ICMP: 1, TCP: 6, UDP: 17 } as const

/** TCP flag bits, as they sit in byte 13 of the TCP header. */
export const TCP_FLAG = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20
} as const

const IPV4_MIN_HEADER = 20
const TCP_MIN_HEADER = 20
const UDP_HEADER = 8
const ICMP_HEADER = 8

/** Anything above this is not a packet we will ever forward; keeps a bogus length from allocating. */
const MAX_PACKET_BYTES = 65_535

export interface Ipv4Packet {
  /** The bytes, starting at the IP header (no link-layer header). */
  buffer: Buffer
  /** Header length in bytes, options included. */
  headerLength: number
  /** Bytes of the whole datagram as the header claims. */
  totalLength: number
  protocol: number
  ttl: number
  /** Don't-fragment bit. */
  dontFragment: boolean
  /** 0 for the first (or only) fragment. */
  fragmentOffset: number
  moreFragments: boolean
  identification: number
  srcIp: string
  dstIp: string
  /** Where the L4 header starts. */
  payloadOffset: number
}

export interface TcpHeader {
  srcPort: number
  dstPort: number
  seq: number
  ack: number
  /** Header length in bytes, options included. */
  headerLength: number
  flags: number
  window: number
}

export interface UdpHeader {
  srcPort: number
  dstPort: number
  length: number
}

/** An IPv4 address as its four octets. */
export interface Ipv4Address {
  bytes: [number, number, number, number]
}

export function parseIpv4Address(text: string): Ipv4Address | null {
  const parts = text.split('.')
  if (parts.length !== 4) return null
  const bytes: number[] = []
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const value = Number(part)
    if (value > 255) return null
    bytes.push(value)
  }
  const [a, b, c, d] = bytes
  return { bytes: [a, b, c, d] }
}

export function formatIpv4Address(address: Ipv4Address): string {
  return address.bytes.join('.')
}

export function ipv4ToNumber(address: string): number | null {
  const parsed = parseIpv4Address(address)
  if (!parsed) return null
  const [a, b, c, d] = parsed.bytes
  // >>> 0 keeps it an unsigned 32-bit value rather than a negative int32.
  return ((a << 24) | (b << 16) | (c << 8) | d) >>> 0
}

/** Whether `address` lies in `subnet` (CIDR, e.g. "192.168.137.0/24"). */
export function inSubnet(address: string, subnet: string | null | undefined): boolean {
  if (!subnet) return true
  const [network, bitsText] = subnet.split('/')
  const bits = Number(bitsText)
  const value = ipv4ToNumber(address)
  const range = ipv4ToNumber(network)
  if (value === null || range === null || !Number.isFinite(bits)) return false
  if (bits <= 0) return true
  if (bits >= 32) return value === range
  const mask = (0xffffffff << (32 - bits)) >>> 0
  return (value & mask) === (range & mask)
}

/** Whether an address can be a downstream client's: private, CGNAT or link-local. */
export function isPrivateIpv4(address: string): boolean {
  return (
    inSubnet(address, '10.0.0.0/8') ||
    inSubnet(address, '172.16.0.0/12') ||
    inSubnet(address, '192.168.0.0/16') ||
    inSubnet(address, '100.64.0.0/10') ||
    inSubnet(address, '169.254.0.0/16')
  )
}

/** Folds a running 32-bit one's-complement sum into 16 bits. */
function fold(sum: number): number {
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16)
  return sum
}

/**
 * The RFC 1071 running sum over `length` bytes from `start`, added to `initial`. Not complemented:
 * TCP and UDP need to add a pseudo-header's sum to a segment's before complementing, which is only
 * correct if the two are summed together *before* the complement.
 */
function runningSum(buffer: Buffer, start: number, length: number, initial = 0): number {
  let sum = initial
  let index = start
  const end = start + length
  while (index + 1 < end) {
    sum += (buffer[index] << 8) | buffer[index + 1]
    index += 2
  }
  // An odd trailing byte is padded on the right, as if a zero octet followed it.
  if (index < end) sum += buffer[index] << 8
  return sum
}

/** The Internet checksum (RFC 1071) over `length` bytes starting at `start`. */
export function internetChecksum(
  buffer: Buffer,
  start = 0,
  length = buffer.length - start
): number {
  return ~fold(runningSum(buffer, start, length)) & 0xffff
}

/**
 * The checksum over a TCP/UDP pseudo-header plus the segment, which is what a TCP/UDP checksum
 * actually covers. `segmentLength` is the L4 length; `protocol` 6 or 17.
 */
function transportChecksum(
  srcIp: string,
  dstIp: string,
  protocol: number,
  segment: Buffer,
  segmentLength: number
): number {
  const src = parseIpv4Address(srcIp)
  const dst = parseIpv4Address(dstIp)
  if (!src || !dst) return 0
  let sum = 0
  for (let i = 0; i < 4; i += 2) {
    sum += (src.bytes[i] << 8) | src.bytes[i + 1]
    sum += (dst.bytes[i] << 8) | dst.bytes[i + 1]
  }
  sum += protocol
  sum += segmentLength
  sum = runningSum(segment, 0, segmentLength, sum)
  return ~fold(sum) & 0xffff
}

/**
 * Reads an IPv4 packet, or returns null for anything the gateway must not touch: a non-IPv4 version,
 * a truncated header, a length that disagrees with what arrived (a short read from the driver), or
 * a header whose own checksum is wrong. A packet that cannot be parsed is dropped, never guessed at.
 */
export function parseIpv4(
  buffer: Buffer,
  options: { allowTruncated?: boolean } = {}
): Ipv4Packet | null {
  if (buffer.length < IPV4_MIN_HEADER) return null
  if (buffer.length > MAX_PACKET_BYTES) return null
  const version = buffer[0] >> 4
  if (version !== 4) return null
  const headerLength = (buffer[0] & 0x0f) * 4
  if (headerLength < IPV4_MIN_HEADER || headerLength > buffer.length) return null
  const claimedLength = buffer.readUInt16BE(2)
  if (claimedLength < headerLength) return null
  // An ICMP error quotes only the first 8 bytes of the datagram that caused it, so its header
  // claims more bytes than arrived. That is the one case where a truncated parse is correct, and
  // then everything downstream must work from the bytes that are actually here.
  if (claimedLength > buffer.length && !options.allowTruncated) return null
  const totalLength = Math.min(claimedLength, buffer.length)
  // A header checksum of 0 means the capture backend already verified it (WinDivert sets
  // IPChecksum when the NIC offloaded or the driver validated it); otherwise verify.
  if (internetChecksum(buffer, 0, headerLength) !== 0) return null
  const flagsAndOffset = buffer.readUInt16BE(6)

  return {
    buffer,
    headerLength,
    totalLength,
    protocol: buffer[9],
    ttl: buffer[8],
    dontFragment: (flagsAndOffset & 0x4000) !== 0,
    fragmentOffset: (flagsAndOffset & 0x1fff) * 8,
    moreFragments: (flagsAndOffset & 0x2000) !== 0,
    identification: buffer.readUInt16BE(4),
    srcIp: `${buffer[12]}.${buffer[13]}.${buffer[14]}.${buffer[15]}`,
    dstIp: `${buffer[16]}.${buffer[17]}.${buffer[18]}.${buffer[19]}`,
    payloadOffset: headerLength
  }
}

export function parseTcp(packet: Ipv4Packet): TcpHeader | null {
  const start = packet.payloadOffset
  if (packet.totalLength - start < TCP_MIN_HEADER) return null
  const headerLength = (packet.buffer[start + 12] >> 4) * 4
  if (headerLength < TCP_MIN_HEADER || start + headerLength > packet.totalLength) return null
  return {
    srcPort: packet.buffer.readUInt16BE(start),
    dstPort: packet.buffer.readUInt16BE(start + 2),
    seq: packet.buffer.readUInt32BE(start + 4),
    ack: packet.buffer.readUInt32BE(start + 8),
    headerLength,
    flags: packet.buffer[start + 13],
    window: packet.buffer.readUInt16BE(start + 14)
  }
}

export function parseUdp(packet: Ipv4Packet): UdpHeader | null {
  const start = packet.payloadOffset
  if (packet.totalLength - start < UDP_HEADER) return null
  const length = packet.buffer.readUInt16BE(start + 4)
  if (length < UDP_HEADER || start + length > packet.totalLength) return null
  return {
    srcPort: packet.buffer.readUInt16BE(start),
    dstPort: packet.buffer.readUInt16BE(start + 2),
    length
  }
}

/**
 * The L4 ports of any packet we translate, or null when it has none (a later fragment) or is too
 * short to carry them. Deliberately lenient about the rest of the L4 header: an ICMP error quotes
 * only the first 8 bytes of the datagram that caused it, and those 8 bytes are all a NAT needs to
 * find the mapping.
 */
export function portsOf(packet: Ipv4Packet): { srcPort: number; dstPort: number } | null {
  if (packet.fragmentOffset !== 0) return null // Only the first fragment carries the L4 header.
  if (packet.protocol === IPPROTO.TCP || packet.protocol === IPPROTO.UDP) {
    const start = packet.payloadOffset
    if (packet.totalLength - start < 4) return null
    return {
      srcPort: packet.buffer.readUInt16BE(start),
      dstPort: packet.buffer.readUInt16BE(start + 2)
    }
  }
  if (packet.protocol === IPPROTO.ICMP) {
    if (packet.totalLength < packet.payloadOffset + ICMP_HEADER) return null
    return {
      // The echo identifier doubles as the "port" of an ICMP flow, exactly how a NAT treats it.
      srcPort: packet.buffer.readUInt16BE(packet.payloadOffset + 4),
      dstPort: 0
    }
  }
  return null
}

/** The ICMP type and code, for the ICMP messages the gateway answers or learns from. */
export function parseIcmp(packet: Ipv4Packet): { type: number; code: number; rest: number } | null {
  if (packet.protocol !== IPPROTO.ICMP) return null
  if (packet.totalLength < packet.payloadOffset + ICMP_HEADER) return null
  return {
    type: packet.buffer[packet.payloadOffset],
    code: packet.buffer[packet.payloadOffset + 1],
    rest: packet.buffer.readUInt32BE(packet.payloadOffset + 4)
  }
}

/** The MSS a TCP SYN or SYN-ACK advertises, or null when it carries no MSS option. */
export function tcpMssOption(packet: Ipv4Packet): number | null {
  const tcp = parseTcp(packet)
  if (!tcp) return null
  let index = packet.payloadOffset + TCP_MIN_HEADER
  const end = packet.payloadOffset + tcp.headerLength
  while (index < end) {
    const kind = packet.buffer[index]
    if (kind === 0) return null // End of options.
    if (kind === 1) {
      // No-op padding.
      index += 1
      continue
    }
    const length = packet.buffer[index + 1]
    if (length < 2 || index + length > end) return null
    if (kind === 2 && length === 4) return packet.buffer.readUInt16BE(index + 2)
    index += length
  }
  return null
}

/**
 * The largest segment this side may send, for a path whose IP MTU is `mtu`: the MTU less the IP
 * and TCP headers. 40 bytes is the IPv4 + TCP-over-IPv4 minimum, and the RFC 879 floor (576) is
 * never advertised because no real TCP peer needs it and clamping below it would break stacks that
 * refuse small segments.
 */
export function mssForMtu(mtu: number): number {
  return Math.max(536, mtu - 40)
}

/** What to change in a packet. Every field is optional; unset ones are left alone. */
export interface Rewrite {
  srcIp?: string
  dstIp?: string
  srcPort?: number
  dstPort?: number
  /** Lower the TTL by one, as forwarding a packet does. */
  decrementTtl?: boolean
  /** Replace the MSS option, when the packet is a SYN carrying one. */
  clampMssTo?: number
  /** Whether the IP header's DF bit should be set (false lets an uplink fragment it). */
  dontFragment?: boolean
}

export type RewriteOutcome =
  { ok: true; packet: Buffer } | { ok: false; reason: 'malformed' | 'ttl-expired' }

/**
 * Rewrites a packet's addresses/ports and repairs everything the change invalidated: the IP header
 * checksum, the TCP/UDP checksum (over the new pseudo-header, so the addresses are covered), and the
 * MSS option. The input is never modified — `buffer.subarray`/copies are cheap and a captured packet
 * must remain untouched for the backend to be able to drop it.
 */
export function rewritePacket(packet: Ipv4Packet, change: Rewrite): RewriteOutcome {
  // A fragment holds only part of its datagram, so a TCP/UDP checksum cannot be recomputed over it
  // — but it need not be: only the header words change, and a checksum can be adjusted for exactly
  // those (RFC 1624), which is how a NAT translates fragmented traffic without reassembling it.
  if (packet.fragmentOffset !== 0 || packet.moreFragments) {
    return rewriteFragment(packet, change)
  }
  const tcp = packet.protocol === IPPROTO.TCP ? parseTcp(packet) : null
  const udp = packet.protocol === IPPROTO.UDP ? parseUdp(packet) : null
  if (packet.protocol === IPPROTO.TCP && !tcp) return { ok: false, reason: 'malformed' }
  if (packet.protocol === IPPROTO.UDP && !udp) return { ok: false, reason: 'malformed' }

  const next = Buffer.from(packet.buffer.subarray(0, packet.totalLength))
  const srcIp = change.srcIp ?? packet.srcIp
  const dstIp = change.dstIp ?? packet.dstIp

  if (change.decrementTtl) {
    // A forwarded packet that runs out of hops is dropped, exactly as a router does.
    if (next[8] <= 1) return { ok: false, reason: 'ttl-expired' }
    next[8] -= 1
  }
  if (change.dontFragment !== undefined) {
    const flagsAndOffset = next.readUInt16BE(6)
    next.writeUInt16BE(change.dontFragment ? flagsAndOffset | 0x4000 : flagsAndOffset & ~0x4000, 6)
  }
  if (change.srcIp || change.dstIp) {
    const src = parseIpv4Address(srcIp)
    const dst = parseIpv4Address(dstIp)
    if (!src || !dst) return { ok: false, reason: 'malformed' }
    next.set(src.bytes, 12)
    next.set(dst.bytes, 16)
  }

  const l4 = packet.payloadOffset
  if (tcp && (change.srcPort !== undefined || change.dstPort !== undefined)) {
    if (change.srcPort !== undefined) next.writeUInt16BE(change.srcPort, l4)
    if (change.dstPort !== undefined) next.writeUInt16BE(change.dstPort, l4 + 2)
    next.writeUInt16BE(0, l4 + 16) // Checksum, recomputed below.
  }
  if (udp && (change.srcPort !== undefined || change.dstPort !== undefined)) {
    if (change.srcPort !== undefined) next.writeUInt16BE(change.srcPort, l4)
    if (change.dstPort !== undefined) next.writeUInt16BE(change.dstPort, l4 + 2)
    next.writeUInt16BE(0, l4 + 6)
  }
  if (tcp && change.clampMssTo !== undefined && (tcp.flags & TCP_FLAG.SYN) !== 0) {
    const advertised = tcpMssOption(packet)
    // Only ever lower it: a peer that already asks for less than the link allows is left alone.
    if (advertised !== null)
      clampMss(next, packet, Math.max(536, Math.min(change.clampMssTo, advertised)))
  }

  // The IP header checksum covers the header alone, and is cheap.
  next.writeUInt16BE(0, 10)
  next.writeUInt16BE(internetChecksum(next, 0, packet.headerLength), 10)

  if (tcp) {
    const segmentLength = packet.totalLength - l4
    next.writeUInt16BE(0, l4 + 16)
    next.writeUInt16BE(
      transportChecksum(srcIp, dstIp, IPPROTO.TCP, next.subarray(l4), segmentLength),
      l4 + 16
    )
  } else if (udp) {
    // A UDP checksum of 0 means "not computed", which IPv4 allows; keep it that way rather than
    // inventing one a middlebox might mismatch.
    const original = packet.buffer.readUInt16BE(l4 + 6)
    next.writeUInt16BE(0, l4 + 6)
    if (original !== 0) {
      const segmentLength = udp.length
      const computed = transportChecksum(
        srcIp,
        dstIp,
        IPPROTO.UDP,
        next.subarray(l4),
        segmentLength
      )
      // A computed 0 is transmitted as 0xffff, since 0 means "no checksum".
      next.writeUInt16BE(computed === 0 ? 0xffff : computed, l4 + 6)
    }
  } else if (packet.protocol === IPPROTO.ICMP) {
    // An ICMP echo's identifier is its flow's "port": translating it is what lets two downstream
    // clients ping the same host and be told apart on the way back.
    const icmp = parseIcmp(packet)
    if (icmp && (icmp.type === 8 || icmp.type === 0) && change.srcPort !== undefined) {
      next.writeUInt16BE(change.srcPort, l4 + 4)
    }
    // ICMPv4 has no pseudo-header: the checksum covers the message alone.
    next.writeUInt16BE(0, l4 + 2)
    next.writeUInt16BE(internetChecksum(next, l4, packet.totalLength - l4), l4 + 2)
  }

  return { ok: true, packet: next }
}

/**
 * Adjusts a one's-complement checksum for a header word changing from `oldWord` to `newWord`,
 * without seeing the data it covers (RFC 1624, the form that cannot produce a false zero). This is
 * what lets a fragmented datagram be translated: its checksum covers a payload no single fragment
 * has, but only the addresses and ports it covers change.
 */
function adjustChecksum(checksum: number, oldWord: number, newWord: number): number {
  if (oldWord === newWord) return checksum
  let sum = (~checksum & 0xffff) + (~oldWord & 0xffff) + newWord
  sum = fold(sum)
  const result = ~sum & 0xffff
  return result === 0 ? 0xffff : result
}

function wordsOf(address: string): [number, number] | null {
  const parsed = parseIpv4Address(address)
  if (!parsed) return null
  const [a, b, c, d] = parsed.bytes
  return [(a << 8) | b, (c << 8) | d]
}

/**
 * Rewrites a fragment: addresses, ports and TTL, with the L4 checksum adjusted for the words that
 * changed rather than recomputed. Used for every packet that is part of a larger datagram, and it
 * is careful to do nothing at all to a checksum the sender left as 0 ("not computed").
 */
export function rewriteFragment(packet: Ipv4Packet, change: Rewrite): RewriteOutcome {
  const next = Buffer.from(packet.buffer.subarray(0, packet.totalLength))
  const srcIp = change.srcIp ?? packet.srcIp
  const dstIp = change.dstIp ?? packet.dstIp
  if (change.srcIp || change.dstIp) {
    const src = parseIpv4Address(srcIp)
    const dst = parseIpv4Address(dstIp)
    if (!src || !dst) return { ok: false, reason: 'malformed' }
    next.set(src.bytes, 12)
    next.set(dst.bytes, 16)
  }
  if (change.decrementTtl) {
    if (next[8] <= 1) return { ok: false, reason: 'ttl-expired' }
    next[8] -= 1
  }
  const l4 = packet.payloadOffset
  const hasPorts = packet.totalLength - l4 >= 4
  if (hasPorts) {
    if (change.srcPort !== undefined) next.writeUInt16BE(change.srcPort, l4)
    if (change.dstPort !== undefined) next.writeUInt16BE(change.dstPort, l4 + 2)
  }

  const addressed = change.srcIp !== undefined || change.dstIp !== undefined
  const ported = hasPorts && (change.srcPort !== undefined || change.dstPort !== undefined)
  if (addressed || ported) {
    const oldSrc = wordsOf(packet.srcIp)
    const newSrc = wordsOf(srcIp)
    const oldDst = wordsOf(packet.dstIp)
    const newDst = wordsOf(dstIp)
    if (!oldSrc || !newSrc || !oldDst || !newDst) return { ok: false, reason: 'malformed' }
    const edits: [number, number][] = addressed
      ? [
          [oldSrc[0], newSrc[0]],
          [oldSrc[1], newSrc[1]],
          [oldDst[0], newDst[0]],
          [oldDst[1], newDst[1]]
        ]
      : []
    if (ported) {
      const oldSrcPort = packet.buffer.readUInt16BE(l4)
      const oldDstPort = packet.buffer.readUInt16BE(l4 + 2)
      if (change.srcPort !== undefined) edits.push([oldSrcPort, change.srcPort])
      if (change.dstPort !== undefined) edits.push([oldDstPort, change.dstPort])
    }

    const checksumOffset =
      packet.protocol === IPPROTO.TCP && packet.totalLength - l4 >= 18
        ? l4 + 16
        : packet.protocol === IPPROTO.UDP && packet.totalLength - l4 >= 8
          ? l4 + 6
          : packet.protocol === IPPROTO.ICMP && packet.totalLength - l4 >= 4
            ? l4 + 2
            : null
    if (checksumOffset !== null) {
      const stored = next.readUInt16BE(checksumOffset)
      // 0 in a UDP checksum means "the sender did not compute one"; leave it alone.
      if (!(packet.protocol === IPPROTO.UDP && stored === 0)) {
        let adjusted = stored
        for (const [oldWord, newWord] of edits)
          adjusted = adjustChecksum(adjusted, oldWord, newWord)
        next.writeUInt16BE(adjusted, checksumOffset)
      }
    }
  }

  next.writeUInt16BE(0, 10)
  next.writeUInt16BE(internetChecksum(next, 0, packet.headerLength), 10)
  return { ok: true, packet: next }
}

/** Sets the MSS option in an already-checksum-free SYN to `mss`, adding the option when absent. */
function clampMss(next: Buffer, packet: Ipv4Packet, mss: number): void {
  const tcp = parseTcp(packet)
  if (!tcp) return
  let index = packet.payloadOffset + TCP_MIN_HEADER
  const end = packet.payloadOffset + tcp.headerLength
  while (index < end) {
    const kind = next[index]
    if (kind === 0) break
    if (kind === 1) {
      index += 1
      continue
    }
    const length = next[index + 1]
    if (length < 2 || index + length > end) break
    if (kind === 2 && length === 4) {
      next.writeUInt16BE(mss, index + 2)
      return
    }
    index += length
  }
  // No MSS option: every OS sends one in a SYN, so adding one means growing the header, which
  // would shift the payload. Rather than re-lay-out the packet, leave it — the peer falls back to
  // the RFC default (536) and its own PMTU discovery, which is correct, if slower.
}

/**
 * Split an IPv4 datagram into pieces no larger than `mtu`, so a UDP packet that arrived on a
 * 1500-byte LAN can still leave through an uplink whose MTU is smaller (PPPoE, a VPN, some mobile
 * APNs). Returns one piece per fragment, each a complete IPv4 datagram, or null when the packet
 * cannot be split (DF set — the caller then owes the client an ICMP "fragmentation needed").
 */
export function fragmentIpv4(packet: Ipv4Packet, mtu: number): Buffer[] | null {
  const maxPayload = Math.floor((mtu - packet.headerLength) / 8) * 8
  if (maxPayload <= 0) return null
  if (packet.totalLength <= mtu) return [Buffer.from(packet.buffer.subarray(0, packet.totalLength))]
  if (packet.dontFragment) return null

  const payload = packet.buffer.subarray(packet.payloadOffset, packet.totalLength)
  const pieces: Buffer[] = []
  let offset = 0
  while (offset < payload.length) {
    const size = Math.min(maxPayload, payload.length - offset)
    const last = offset + size >= payload.length
    const header = Buffer.from(packet.buffer.subarray(0, packet.headerLength))
    header.writeUInt16BE(packet.headerLength + size, 2)
    const flagsAndOffset = (offset / 8) | (last ? 0 : 0x2000)
    header.writeUInt16BE(flagsAndOffset, 6)
    header.writeUInt16BE(0, 10)
    header.writeUInt16BE(internetChecksum(header, 0, packet.headerLength), 10)
    pieces.push(Buffer.concat([header, payload.subarray(offset, offset + size)]))
    offset += size
  }
  return pieces
}

/**
 * Builds the TCP RST that tells a downstream client its connection died, rather than leaving it to
 * discover that through a retransmit timeout (which is what a game or the PS Store sees as a 15–30
 * second freeze). Sent with the client's own addresses so its stack attributes the reset to the
 * connection it holds.
 *
 * RFC 793: a reset for an incoming segment that carried no ACK has SEQ 0, ACK = SEQ + segment
 * length; otherwise SEQ = the segment's ACK and RST gets the ACK flag.
 */
export function buildTcpReset(packet: Ipv4Packet, tcp: TcpHeader): Buffer | null {
  const header = Buffer.alloc(IPV4_MIN_HEADER + TCP_MIN_HEADER)
  header.writeUInt8(0x45, 0) // IPv4, 5 words of header.
  header.writeUInt8(0, 1) // DSCP/ECN
  header.writeUInt16BE(header.length, 2)
  header.writeUInt16BE(0, 4) // Identification
  header.writeUInt16BE(0x4000, 6) // DF
  header.writeUInt8(64, 8) // TTL
  header.writeUInt8(IPPROTO.TCP, 9)
  // From the server to the client: the client's destination becomes our source.
  const src = parseIpv4Address(packet.dstIp)
  const dst = parseIpv4Address(packet.srcIp)
  if (!src || !dst) return null
  header.set(src.bytes, 12)
  header.set(dst.bytes, 16)

  const l4 = IPV4_MIN_HEADER
  header.writeUInt16BE(tcp.dstPort, l4) // source: the server port, as the client expects it
  header.writeUInt16BE(tcp.srcPort, l4 + 2) // destination: the client's port
  const hadAck = (tcp.flags & TCP_FLAG.ACK) !== 0
  const segmentLength =
    packet.totalLength -
    packet.payloadOffset -
    tcp.headerLength +
    (tcp.flags & TCP_FLAG.SYN ? 1 : 0)
  if (hadAck) {
    header.writeUInt32BE(tcp.ack, l4 + 4)
    header.writeUInt32BE(0, l4 + 8)
    header.writeUInt8((TCP_FLAG.RST | TCP_FLAG.ACK) & 0xff, l4 + 13)
  } else {
    header.writeUInt32BE(0, l4 + 4)
    header.writeUInt32BE((tcp.seq + segmentLength) >>> 0, l4 + 8)
    header.writeUInt16BE(0, l4 + 14)
    header.writeUInt8(TCP_FLAG.RST, l4 + 13)
  }
  header.writeUInt8(5 << 4, l4 + 12) // 5 words of TCP header, no options.

  header.writeUInt16BE(0, 10)
  header.writeUInt16BE(internetChecksum(header, 0, IPV4_MIN_HEADER), 10)
  header.writeUInt16BE(
    transportChecksum(packet.dstIp, packet.srcIp, IPPROTO.TCP, header.subarray(l4), TCP_MIN_HEADER),
    l4 + 16
  )
  return header
}

/**
 * Reads a TCP RST's sequence/ack and flags, for the gateway's own bookkeeping (a backend may want
 * to know a reset it just sent was delivered). Kept here so all wire parsing lives in one file.
 */
export function isTcpReset(packet: Ipv4Packet): boolean {
  const tcp = parseTcp(packet)
  return tcp ? (tcp.flags & TCP_FLAG.RST) !== 0 : false
}

/**
 * Builds an ICMP Destination Unreachable / Fragmentation Needed message, which is how a downstream
 * client learns to shrink its segments or give up: type 3, code 4, with the MTU we can carry in
 * the unused half of the header field (RFC 1191).
 */
export function buildIcmpFragmentationNeeded(packet: Ipv4Packet, mtu: number): Buffer | null {
  // The message quotes the original IP header plus 8 bytes, per RFC 792.
  const quoted = Math.min(packet.totalLength, packet.headerLength + 8)
  const icmpLength = ICMP_HEADER + quoted
  const message = Buffer.alloc(icmpLength)
  message.writeUInt8(3, 0) // Destination Unreachable
  message.writeUInt8(4, 1) // Fragmentation needed and DF was set
  message.writeUInt16BE(0, 2) // checksum, below
  message.writeUInt16BE(0, 4)
  message.writeUInt16BE(Math.min(mtu, 0xffff), 6) // Next-hop MTU
  packet.buffer.copy(message, ICMP_HEADER, 0, quoted)
  message.writeUInt16BE(internetChecksum(message, 0, icmpLength), 2)

  const header = Buffer.alloc(IPV4_MIN_HEADER)
  header.writeUInt8(0x45, 0)
  header.writeUInt16BE(IPV4_MIN_HEADER + icmpLength, 2)
  header.writeUInt16BE(0, 6) // no DF: a small control message
  header.writeUInt8(64, 8)
  header.writeUInt8(IPPROTO.ICMP, 9)
  // ICMP errors go back to the sender, from the address it was talking to (the NAT's public
  // address for that flow, which the caller passes through `packet.dstIp` already translated).
  const src = parseIpv4Address(packet.dstIp)
  const dst = parseIpv4Address(packet.srcIp)
  if (!src || !dst) return null
  header.set(src.bytes, 12)
  header.set(dst.bytes, 16)
  header.writeUInt16BE(0, 10)
  header.writeUInt16BE(internetChecksum(header, 0, IPV4_MIN_HEADER), 10)
  return Buffer.concat([header, message])
}

/** A minimal IPv4/ICMP echo reply, used by the gateway's own reachability self-test. */
export function buildIcmpEchoReply(packet: Ipv4Packet): Buffer | null {
  const icmp = parseIcmp(packet)
  if (!icmp || icmp.type !== 8) return null
  const length = packet.totalLength - packet.payloadOffset
  const message = Buffer.from(packet.buffer.subarray(packet.payloadOffset, packet.totalLength))
  message.writeUInt8(0, 0) // Echo reply
  message.writeUInt16BE(0, 2)
  message.writeUInt16BE(internetChecksum(message, 0, length), 2)

  const header = Buffer.from(packet.buffer.subarray(0, packet.headerLength))
  const src = parseIpv4Address(packet.dstIp)
  const dst = parseIpv4Address(packet.srcIp)
  if (!src || !dst) return null
  header.set(src.bytes, 12)
  header.set(dst.bytes, 16)
  header.writeUInt8(64, 8)
  header.writeUInt16BE(0, 10)
  header.writeUInt16BE(internetChecksum(header, 0, packet.headerLength), 10)
  return Buffer.concat([header, message])
}

/**
 * Builds a complete IPv4/UDP datagram. Used by the gateway's own DHCP and DNS servers, which speak
 * from the LAN address to the downstream client, and by the tests to make realistic traffic.
 */
export function buildUdpPacket(options: {
  srcIp: string
  dstIp: string
  srcPort: number
  dstPort: number
  payload: Buffer
  ttl?: number
  identification?: number
  dontFragment?: boolean
}): Buffer | null {
  const src = parseIpv4Address(options.srcIp)
  const dst = parseIpv4Address(options.dstIp)
  if (!src || !dst) return null
  const udpLength = UDP_HEADER + options.payload.length
  const totalLength = IPV4_MIN_HEADER + udpLength
  if (totalLength > MAX_PACKET_BYTES) return null
  const buffer = Buffer.alloc(totalLength)
  buffer.writeUInt8(0x45, 0)
  buffer.writeUInt16BE(totalLength, 2)
  buffer.writeUInt16BE(options.identification ?? 0, 4)
  buffer.writeUInt16BE(options.dontFragment === false ? 0 : 0x4000, 6)
  buffer.writeUInt8(options.ttl ?? 64, 8)
  buffer.writeUInt8(IPPROTO.UDP, 9)
  buffer.set(src.bytes, 12)
  buffer.set(dst.bytes, 16)
  const l4 = IPV4_MIN_HEADER
  buffer.writeUInt16BE(options.srcPort, l4)
  buffer.writeUInt16BE(options.dstPort, l4 + 2)
  buffer.writeUInt16BE(udpLength, l4 + 4)
  options.payload.copy(buffer, l4 + UDP_HEADER)
  const checksum = transportChecksum(
    options.srcIp,
    options.dstIp,
    IPPROTO.UDP,
    buffer.subarray(l4),
    udpLength
  )
  buffer.writeUInt16BE(checksum === 0 ? 0xffff : checksum, l4 + 6)
  buffer.writeUInt16BE(internetChecksum(buffer, 0, IPV4_MIN_HEADER), 10)
  return buffer
}

/** Builds a complete IPv4/TCP datagram with an optional payload, for tests and synthetic flows. */
export function buildTcpPacket(options: {
  srcIp: string
  dstIp: string
  srcPort: number
  dstPort: number
  flags: number
  seq?: number
  ack?: number
  payload?: Buffer
  mss?: number
  window?: number
  ttl?: number
  dontFragment?: boolean
}): Buffer | null {
  const src = parseIpv4Address(options.srcIp)
  const dst = parseIpv4Address(options.dstIp)
  if (!src || !dst) return null
  const optionsLength = options.mss === undefined ? 0 : 4
  const tcpHeaderLength = TCP_MIN_HEADER + optionsLength
  const payload = options.payload ?? Buffer.alloc(0)
  const totalLength = IPV4_MIN_HEADER + tcpHeaderLength + payload.length
  if (totalLength > MAX_PACKET_BYTES) return null
  const buffer = Buffer.alloc(totalLength)
  buffer.writeUInt8(0x45, 0)
  buffer.writeUInt16BE(totalLength, 2)
  buffer.writeUInt16BE(0, 4)
  buffer.writeUInt16BE(options.dontFragment === false ? 0 : 0x4000, 6)
  buffer.writeUInt8(options.ttl ?? 64, 8)
  buffer.writeUInt8(IPPROTO.TCP, 9)
  buffer.set(src.bytes, 12)
  buffer.set(dst.bytes, 16)
  const l4 = IPV4_MIN_HEADER
  buffer.writeUInt16BE(options.srcPort, l4)
  buffer.writeUInt16BE(options.dstPort, l4 + 2)
  buffer.writeUInt32BE(options.seq ?? 0, l4 + 4)
  buffer.writeUInt32BE(options.ack ?? 0, l4 + 8)
  buffer.writeUInt8((tcpHeaderLength / 4) << 4, l4 + 12)
  buffer.writeUInt8(options.flags & 0xff, l4 + 13)
  buffer.writeUInt16BE(options.window ?? 65535, l4 + 14)
  if (options.mss !== undefined) {
    buffer.writeUInt8(2, l4 + TCP_MIN_HEADER)
    buffer.writeUInt8(4, l4 + TCP_MIN_HEADER + 1)
    buffer.writeUInt16BE(options.mss, l4 + TCP_MIN_HEADER + 2)
  }
  payload.copy(buffer, l4 + tcpHeaderLength)
  buffer.writeUInt16BE(internetChecksum(buffer, 0, IPV4_MIN_HEADER), 10)
  buffer.writeUInt16BE(
    transportChecksum(
      options.srcIp,
      options.dstIp,
      IPPROTO.TCP,
      buffer.subarray(l4),
      totalLength - l4
    ),
    l4 + 16
  )
  return buffer
}

/**
 * Verifies the IP and L4 checksums of a packet, so tests (and the self-test) can prove a rewrite
 * produced something a real stack would accept. Computed by zeroing the checksum field and
 * recomputing it, not by summing the packet with the field in place, because that only works if it
 * is the *only* thing being summed.
 */
export function verifyChecksums(packet: Ipv4Packet): boolean {
  if (internetChecksum(packet.buffer, 0, packet.headerLength) !== 0) return false
  const l4 = packet.payloadOffset
  if (packet.protocol === IPPROTO.TCP) {
    const tcp = parseTcp(packet)
    if (!tcp) return false
    const segment = Buffer.from(packet.buffer.subarray(l4, packet.totalLength))
    const stored = segment.readUInt16BE(16)
    segment.writeUInt16BE(0, 16)
    const expected = transportChecksum(
      packet.srcIp,
      packet.dstIp,
      IPPROTO.TCP,
      segment,
      segment.length
    )
    return stored === expected
  }
  if (packet.protocol === IPPROTO.UDP) {
    const udp = parseUdp(packet)
    if (!udp) return false
    const segment = Buffer.from(packet.buffer.subarray(l4, l4 + udp.length))
    const stored = segment.readUInt16BE(6)
    // Zero means the sender did not compute one, which IPv4 permits.
    if (stored === 0) return true
    segment.writeUInt16BE(0, 6)
    const expected = transportChecksum(
      packet.srcIp,
      packet.dstIp,
      IPPROTO.UDP,
      segment,
      segment.length
    )
    return stored === (expected === 0 ? 0xffff : expected)
  }
  if (packet.protocol === IPPROTO.ICMP) {
    const message = Buffer.from(packet.buffer.subarray(l4, packet.totalLength))
    const stored = message.readUInt16BE(2)
    message.writeUInt16BE(0, 2)
    return stored === internetChecksum(message)
  }
  return true
}
