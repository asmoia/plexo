/**
 * The decision engine: for every captured packet, what to do with it.
 *
 * It owns no sockets, no threads and no clock of its own — time comes in as an argument and
 * packets come in as bytes — so the same code runs in the Windows capture worker, in the
 * simulator the tests drive, and on a machine that cannot install a driver. Everything it decides
 * ends up as a list of "send these bytes out this interface", which is all a backend can do.
 *
 * The four jobs, in the order a packet meets them:
 *
 *  1. **Identify the flow** (protocol, client socket, destination) and find or create its NAT
 *     mapping. One mapping per client socket (see nat.ts), pinned to one uplink.
 *  2. **Place the flow.** A new flow goes where weighted rendezvous hashing sends it; an existing
 *     one stays where it is for as long as that uplink works.
 *  3. **Fail over** when it does not. UDP and ICMP have no connection to break, so their mapping
 *     moves to a surviving uplink and keeps its public port if it can — this is what keeps a
 *     game's connection alive through a Wi-Fi dropout. TCP cannot move: the server knows the old
 *     address. Rather than let the console hang for 15–30 seconds in retransmission, the gateway
 *     sends it a RST so it reconnects immediately, on a surviving uplink (configurable: `hold`
 *     leaves it to the console instead, for a server that resumes on a new address).
 *  4. **Fit the packet to the uplink** it is leaving through: TTL, MSS clamping on SYNs, and
 *     fragmentation (or an ICMP "fragmentation needed" back to the console) when an uplink's MTU
 *     is smaller than the LAN's.
 *
 * Return traffic is the mirror image, and the only hard part is ICMP errors: an uplink's "packet
 * too big" quotes the packet *we* sent, i.e. with our translated addresses, so the quote has to be
 * translated back as well or the console will not recognise its own connection in it.
 */

import {
  buildIcmpFragmentationNeeded,
  buildTcpReset,
  fragmentIpv4,
  inSubnet,
  internetChecksum,
  IPPROTO,
  mssForMtu,
  parseIcmp,
  parseIpv4,
  parseTcp,
  portsOf,
  rewritePacket,
  type Ipv4Packet
} from './packet'
import { flowId } from './flow'
import type { NatMapping, NatTable } from './nat'
import { selectUplink } from './scheduler'

/** An uplink as the forwarder needs it: where to send, how big, and how much to use it. */
export interface UplinkRuntime {
  id: string
  /** IPv4 address NAT'd to. */
  address: string
  mac: string | null
  /** OS interface index, for the backend's send. */
  ifIdx: number
  mtu: number
  /** Whether the gateway may use it at all (enabled, connected, reachable). */
  usable: boolean
  /** Share of new flows, ≥ 0; 0 keeps new flows off it even when usable. */
  weight: number
}

/** The console-facing port. */
export interface DownstreamRuntime {
  id: string
  address: string
  mac: string | null
  ifIdx: number
  mtu: number
  subnet: string | null
}

/** One packet to send, and where. */
export interface Transmit {
  packet: Buffer
  ifIdx: number
  /** The uplink it left through, or undefined for a packet delivered to the console. */
  linkId?: string
}

export type DropReason =
  | 'malformed'
  | 'ttl-expired'
  | 'no-uplink'
  | 'no-port'
  | 'not-downstream'
  | 'unknown-flow'
  | 'fragment-orphan'
  | 'fragment-needed'

export interface ForwardResult {
  /** Everything to send. Empty means the packet was dropped or answered. */
  transmit: Transmit[]
  /** Why nothing was sent, when nothing was. */
  dropped?: DropReason
  /** The packet went to an uplink, and to which. */
  linkId?: string
  /** The packet went to the console. */
  delivered?: boolean
}

export interface ForwarderOptions {
  /** What to do with a TCP connection whose uplink disappeared. */
  tcpFailover: 'reset' | 'hold'
  /**
   * DNS from the console addressed to the gateway itself. Off, those queries are ignored (the
   * console is expected to have a public resolver from DHCP). On, they are redirected to `resolver`
   * and NAT'd like any other flow, so a console configured by hand with the gateway as its DNS
   * server still resolves — and its queries are spread across the uplinks with everything else.
   */
  dnsRelay?: { enabled: boolean; resolver: string }
}

/** Per-uplink byte counters, as the UI shows them. */
export interface UplinkCounters {
  bytesOut: number
  bytesIn: number
}

const FRAGMENT_IDLE_MS = 30_000
const PATH_MTU_IDLE_MS = 10 * 60_000
/** ICMP type 3, code 4: destination unreachable, fragmentation needed, DF set (RFC 1191). */
const ICMP_FRAGMENTATION_NEEDED = 4

export class GatewayForwarder {
  /** Which uplink each fragmented datagram's later pieces follow, by (protocol, id, source). */
  private readonly fragments = new Map<string, { linkId: string; at: number }>()
  /** A path MTU smaller than the uplink's, learned from ICMP errors. */
  private readonly pathMtu = new Map<string, { mtu: number; at: number }>()
  private readonly counters = new Map<string, UplinkCounters>()
  readonly totals = {
    bytesUp: 0,
    bytesDown: 0,
    dropped: 0,
    resets: 0,
    repins: 0,
    fragments: 0,
    pmtuAnswers: 0
  }

  constructor(
    private readonly nat: NatTable,
    private readonly uplinks: () => readonly UplinkRuntime[],
    private readonly downstream: () => DownstreamRuntime | null,
    private readonly now: () => number,
    private readonly options: ForwarderOptions
  ) {}

  /**
   * Changes settings in place. The engine reads them per packet, so a change takes effect on the
   * next one — no restart, and no connection dropped for a settings edit.
   */
  setOptions(patch: Partial<ForwarderOptions>): void {
    Object.assign(this.options, patch)
  }

  /** A packet the console sent. */
  outbound(buffer: Buffer): ForwardResult {
    const now = this.now()
    const link = this.downstream()
    const packet = parseIpv4(buffer)
    if (!packet) return this.drop('malformed')
    if (!link) return this.drop('not-downstream')
    if (packet.srcIp !== link.address && !inSubnet(packet.srcIp, link.subnet)) {
      return this.drop('not-downstream')
    }
    // The console talking to the gateway itself. DHCP is answered before this engine runs (the
    // service intercepts it); DNS is either redirected to a real resolver — so a console configured
    // by hand with the gateway as its DNS still works — or left alone.
    let redirect: { dstIp: string; dstPort: number } | null = null
    if (packet.dstIp === link.address) {
      const ports = portsOf(packet)
      const dns = this.options.dnsRelay
      if (dns?.enabled && packet.protocol === IPPROTO.UDP && ports?.dstPort === 53) {
        redirect = { dstIp: dns.resolver, dstPort: 53 }
      } else {
        return { transmit: [] }
      }
    }

    const uplinks = this.uplinks()
    const usable = uplinks.filter((uplink) => uplink.usable)
    if (usable.length === 0) return this.drop('no-uplink')

    const proto = packet.protocol
    if (proto !== IPPROTO.TCP && proto !== IPPROTO.UDP && proto !== IPPROTO.ICMP) {
      // Anything else (GRE, ESP, SCTP) would need translation rules of its own.
      return this.drop('malformed')
    }

    // Fragments after the first carry no ports: they follow the mapping the first one created.
    if (packet.fragmentOffset !== 0) return this.forwardFragment(packet, now)

    const ports = portsOf(packet)
    if (!ports) return this.drop('malformed')
    const identity = { proto, clientIp: packet.srcIp, clientPort: ports.srcPort }

    let mapping: NatMapping | undefined = this.nat.lookup(proto, packet.srcIp, ports.srcPort)
    if (!mapping) {
      const chosen = selectUplink(
        flowId(identity),
        usable.map((uplink) => ({ id: uplink.id, weight: uplink.weight }))
      )
      const created = this.openMapping(identity, chosen, usable, now)
      if (!created) return this.drop('no-port')
      mapping = created
    } else if (!this.isUsable(mapping.linkId, uplinks)) {
      const failed = this.handleLinkLoss(mapping, packet, usable, link, now)
      if (failed) return failed
      mapping = this.nat.lookup(proto, packet.srcIp, ports.srcPort)
      if (!mapping) return this.drop('no-uplink')
    }

    const uplink = uplinks.find((candidate) => candidate.id === mapping.linkId)
    if (!uplink) return this.drop('no-uplink')
    return this.forwardThrough(packet, mapping, uplink, link, now, redirect)
  }

  /** A packet that arrived from an uplink. */
  inbound(buffer: Buffer, ifIdx: number): ForwardResult {
    const now = this.now()
    const link = this.downstream()
    if (!link) return { transmit: [] }
    const packet = parseIpv4(buffer)
    if (!packet) return this.drop('malformed')
    const uplink = this.uplinks().find((candidate) => candidate.ifIdx === ifIdx)
    if (!uplink) return this.drop('unknown-flow')

    const icmp = parseIcmp(packet)
    if (icmp && (icmp.type === 3 || icmp.type === 11)) {
      return this.inboundIcmpError(packet, uplink, link, now)
    }

    const ports = portsOf(packet)
    if (!ports) return this.drop('malformed')
    // An ICMP echo's identifier sits in the same place in a request and a reply, so it is always
    // the source "port"; TCP and UDP are matched on the port this packet was sent to.
    const icmpEcho = packet.protocol === IPPROTO.ICMP
    const demuxPort = icmpEcho ? ports.srcPort : ports.dstPort
    const mapping = this.nat.lookupPublic(uplink.id, packet.protocol, demuxPort)
    // Return traffic for a mapping that has expired, and broadcasts, are both normal; neither is
    // an error the console should hear about.
    if (!mapping) return { transmit: [] }

    const rewritten = rewritePacket(packet, {
      dstIp: mapping.clientIp,
      ...(icmpEcho
        ? { srcPort: mapping.clientPort !== ports.srcPort ? mapping.clientPort : undefined }
        : { dstPort: mapping.clientPort !== ports.dstPort ? mapping.clientPort : undefined }),
      decrementTtl: true,
      // A server's SYN-ACK may advertise a segment bigger than this path allows; clamping it keeps
      // the server's segments from arriving unforwardable.
      clampMssTo: mssForMtu(this.effectiveMtu(uplink))
    })
    if (!rewritten.ok)
      return this.drop(rewritten.reason === 'ttl-expired' ? 'ttl-expired' : 'malformed')

    const transmit = this.fragmentFor(rewritten.packet, link.mtu, link.ifIdx)
    if (!transmit) return this.drop('fragment-needed')

    this.nat.observeInbound(
      mapping,
      { dstIp: packet.srcIp, dstPort: ports.srcPort },
      packet.totalLength,
      now
    )
    this.countersFor(uplink.id).bytesIn += packet.totalLength
    this.totals.bytesDown += packet.totalLength
    return { transmit, delivered: true }
  }

  /** Where an uplink's traffic has gone, for the UI. */
  uplinkCounters(id: string): UplinkCounters {
    return this.counters.get(id) ?? { bytesOut: 0, bytesIn: 0 }
  }

  /** Forgets fragments and path-MTU measurements that have gone stale. Called on the tick. */
  housekeeping(now = this.now()): void {
    for (const [key, entry] of this.fragments) {
      if (now - entry.at > FRAGMENT_IDLE_MS) this.fragments.delete(key)
    }
    for (const [id, entry] of this.pathMtu) {
      if (now - entry.at > PATH_MTU_IDLE_MS) this.pathMtu.delete(id)
    }
  }

  /** The MTU to use towards an uplink: its own, or a smaller one an ICMP error taught us. */
  effectiveMtu(uplink: { id: string; mtu: number }): number {
    const learned = this.pathMtu.get(uplink.id)
    return learned ? Math.min(uplink.mtu, learned.mtu) : uplink.mtu
  }

  private isUsable(linkId: string, uplinks: readonly UplinkRuntime[]): boolean {
    return uplinks.some((uplink) => uplink.id === linkId && uplink.usable)
  }

  /**
   * Opens a mapping on the best uplink that has a port free. The scheduler's first choice can fail
   * only when that uplink has no ports left (an exhausted 64k range), in which case the next
   * preferred link is tried rather than dropping the console's connection.
   */
  private openMapping(
    identity: { proto: number; clientIp: string; clientPort: number },
    chosen: string | null,
    usable: readonly UplinkRuntime[],
    now: number
  ): NatMapping | null {
    const ordered = [
      ...usable.filter((uplink) => uplink.id === chosen),
      ...usable.filter((uplink) => uplink.id !== chosen)
    ]
    for (const uplink of ordered) {
      const mapping = this.nat.create({
        proto: identity.proto,
        clientIp: identity.clientIp,
        clientPort: identity.clientPort,
        linkId: uplink.id,
        publicIp: uplink.address,
        now
      })
      if (mapping) return mapping
    }
    return null
  }

  /**
   * The uplink a mapping was pinned to is gone. UDP and ICMP move; TCP either gets a reset (so the
   * console reconnects at once) or is left to time out on its own.
   */
  private handleLinkLoss(
    mapping: NatMapping,
    packet: Ipv4Packet,
    usable: readonly UplinkRuntime[],
    link: DownstreamRuntime,
    now: number
  ): ForwardResult | null {
    if (mapping.proto === IPPROTO.TCP) {
      const tcp = parseTcp(packet)
      if (this.options.tcpFailover === 'hold') {
        // The mapping is kept: if the uplink comes back within the console's retransmit window the
        // connection resumes. Nothing is sent, which is exactly what a dead link looks like.
        return { transmit: [], dropped: 'no-uplink' }
      }
      const reset = tcp ? buildTcpReset(packet, tcp) : null
      this.nat.remove(mapping)
      this.totals.resets++
      if (!reset) return this.drop('no-uplink')
      // Delivered on the LAN port, addressed as the server would address it. A backend that only
      // captures the console's own traffic must also accept these, so it filters on the LAN port
      // rather than on direction.
      return { transmit: [{ packet: reset, ifIdx: link.ifIdx }], dropped: 'no-uplink' }
    }

    // Prefer the link that should take new flows, but a weight of 0 means "no *new* flows", not
    // "never": when it is the only uplink still alive, moving to it beats dropping the game.
    const moved =
      selectUplink(
        `${flowId(mapping)}#failover`,
        usable.map((uplink) => ({ id: uplink.id, weight: uplink.weight }))
      ) ?? usable[0]?.id
    const target = usable.find((uplink) => uplink.id === moved)
    if (!target) return this.drop('no-uplink')
    if (!this.nat.move(mapping, target.id, target.address, now)) return this.drop('no-port')
    this.totals.repins++
    return null
  }

  /** Rewrites an outbound packet for its mapping's uplink and fits it to that uplink. */
  private forwardThrough(
    packet: Ipv4Packet,
    mapping: NatMapping,
    uplink: UplinkRuntime,
    link: DownstreamRuntime,
    now: number,
    redirect: { dstIp: string; dstPort: number } | null = null
  ): ForwardResult {
    const ports = portsOf(packet)
    if (!ports) return this.drop('malformed')
    const mtu = this.effectiveMtu(uplink)

    const rewritten = rewritePacket(packet, {
      srcIp: uplink.address,
      srcPort: mapping.publicPort !== ports.srcPort ? mapping.publicPort : undefined,
      ...(redirect ? { dstIp: redirect.dstIp, dstPort: redirect.dstPort } : {}),
      decrementTtl: true,
      // Clamp what the console advertises, so servers send segments this uplink can carry.
      clampMssTo: mssForMtu(mtu)
    })
    if (!rewritten.ok)
      return this.drop(rewritten.reason === 'ttl-expired' ? 'ttl-expired' : 'malformed')

    const transmit = this.fragmentFor(rewritten.packet, mtu, uplink.ifIdx)
    if (!transmit) {
      // Too big for the path and the console asked for no fragmentation: tell it the path MTU so
      // its own stack shrinks, which is what a router does and what keeps TCP working over an
      // uplink with a smaller MTU.
      // Built from the packet as the console sent it, so the quote carries the console's own
      // addresses — that is what its stack matches against its connection — and so the answer is
      // addressed to the console and appears to come from the server.
      const icmp = buildIcmpFragmentationNeeded(packet, mtu)
      this.totals.pmtuAnswers++
      return {
        transmit: icmp ? [{ packet: icmp, ifIdx: link.ifIdx }] : [],
        dropped: 'fragment-needed'
      }
    }

    this.nat.observeOutbound(
      mapping,
      { dstIp: redirect?.dstIp ?? packet.dstIp, dstPort: redirect?.dstPort ?? ports.dstPort },
      packet.totalLength,
      now
    )
    this.countersFor(uplink.id).bytesOut += packet.totalLength
    this.totals.bytesUp += packet.totalLength
    // Later fragments of this datagram have no ports, so they follow this mapping by header id.
    if (packet.moreFragments) {
      this.fragments.set(this.fragmentKey(packet), { linkId: uplink.id, at: now })
    }
    return {
      transmit: transmit.map((piece) => ({ ...piece, linkId: uplink.id })),
      linkId: uplink.id
    }
  }

  /** A fragment after the first: it carries no port, so it rides its first fragment's mapping. */
  private forwardFragment(packet: Ipv4Packet, now: number): ForwardResult {
    const key = this.fragmentKey(packet)
    const entry = this.fragments.get(key)
    if (!entry) return this.drop('fragment-orphan')
    const uplink = this.uplinks().find((candidate) => candidate.id === entry.linkId)
    if (!uplink || !uplink.usable) {
      this.fragments.delete(key)
      return this.drop('no-uplink')
    }
    const rewritten = rewritePacket(packet, { srcIp: uplink.address, decrementTtl: true })
    if (!rewritten.ok) return this.drop('malformed')
    entry.at = now
    this.countersFor(uplink.id).bytesOut += packet.totalLength
    this.totals.bytesUp += packet.totalLength
    return {
      transmit: [{ packet: rewritten.packet, ifIdx: uplink.ifIdx, linkId: uplink.id }],
      linkId: uplink.id
    }
  }

  /**
   * An ICMP error from an uplink. Two things must happen: the message is delivered to the console
   * with its outer addresses translated, and the copy of the packet it quotes — which is the packet
   * *we* sent, carrying our NAT address and port — is translated back, or the console's stack will
   * not match it to any connection it knows. A "fragmentation needed" also teaches the path MTU.
   */
  private inboundIcmpError(
    packet: Ipv4Packet,
    uplink: UplinkRuntime,
    link: DownstreamRuntime,
    now: number
  ): ForwardResult {
    const icmp = parseIcmp(packet)
    if (!icmp) return this.drop('malformed')
    const quotedOffset = packet.payloadOffset + 8
    if (packet.totalLength <= quotedOffset) return { transmit: [] }
    const quoted = parseIpv4(
      Buffer.from(
        packet.buffer.subarray(quotedOffset, Math.min(packet.totalLength, quotedOffset + 60))
      ),
      { allowTruncated: true }
    )
    if (!quoted) return { transmit: [] }
    const quotedPorts = portsOf(quoted)
    if (!quotedPorts) return { transmit: [] }
    const mapping = this.nat.lookupPublic(uplink.id, quoted.protocol, quotedPorts.srcPort)
    if (!mapping) return { transmit: [] }

    if (icmp.type === 3 && icmp.code === ICMP_FRAGMENTATION_NEEDED) {
      const mtu = icmp.rest & 0xffff
      // Never raise the path MTU from an error: only a lower value is news.
      const previous = this.pathMtu.get(uplink.id)
      if (mtu > 0 && (!previous || mtu < previous.mtu))
        this.pathMtu.set(uplink.id, { mtu, at: now })
    }

    const outer = rewritePacket(packet, { dstIp: mapping.clientIp, decrementTtl: true })
    if (!outer.ok) return this.drop('malformed')

    // The quoted datagram is the packet we sent, so its source is our NAT address: put the
    // console's own address and port back, at the same offsets (rewriting never changes lengths).
    const quoteStart = outer.packet.length - (packet.totalLength - quotedOffset)
    const clientParts = mapping.clientIp.split('.').map(Number)
    outer.packet.set(clientParts, quoteStart + 12)
    if (quotedPorts.srcPort === mapping.publicPort) {
      outer.packet.writeUInt16BE(mapping.clientPort, quoteStart + quoted.headerLength)
    }
    // The quoted header has its own checksum, and some stacks check it: repair it over the header
    // bytes that are present (an ICMP quote always carries the whole IP header, even when it cuts
    // the L4 header short).
    outer.packet.writeUInt16BE(0, quoteStart + 10)
    outer.packet.writeUInt16BE(
      internetChecksum(outer.packet, quoteStart, quoted.headerLength),
      quoteStart + 10
    )
    // The ICMP checksum covers the quote, so it has to be recomputed over the edited bytes.
    outer.packet.writeUInt16BE(0, packet.payloadOffset + 2)
    outer.packet.writeUInt16BE(
      internetChecksum(
        outer.packet,
        packet.payloadOffset,
        packet.totalLength - packet.payloadOffset
      ),
      packet.payloadOffset + 2
    )

    this.nat.observeInbound(
      mapping,
      { dstIp: quoted.dstIp, dstPort: quotedPorts.dstPort },
      packet.totalLength,
      now
    )
    this.countersFor(uplink.id).bytesIn += packet.totalLength
    this.totals.bytesDown += packet.totalLength
    return { transmit: [{ packet: outer.packet, ifIdx: link.ifIdx }], delivered: true }
  }

  /**
   * Splits a packet to fit `mtu`, or passes it through when it fits. Null means it must not be
   * fragmented and is too big — the caller answers with ICMP instead.
   */
  private fragmentFor(buffer: Buffer, mtu: number, ifIdx: number): Transmit[] | null {
    const packet = parseIpv4(buffer)
    if (!packet) return null
    if (packet.totalLength <= mtu) return [{ packet: buffer, ifIdx }]
    const pieces = fragmentIpv4(packet, mtu)
    if (!pieces) return null
    this.totals.fragments++
    return pieces.map((piece) => ({ packet: piece, ifIdx }))
  }

  private fragmentKey(packet: Ipv4Packet): string {
    return `${packet.protocol}|${packet.identification}|${packet.srcIp}`
  }

  private countersFor(id: string): UplinkCounters {
    let counters = this.counters.get(id)
    if (!counters) {
      counters = { bytesOut: 0, bytesIn: 0 }
      this.counters.set(id, counters)
    }
    return counters
  }

  private drop(reason: DropReason): ForwardResult {
    this.totals.dropped++
    return { transmit: [], dropped: reason }
  }
}
