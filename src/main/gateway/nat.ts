/**
 * The gateway's NAT: one public (address, port) per downstream socket, per uplink.
 *
 * Every packet the console sends out is rewritten to look like it came from the PC's uplink
 * address, and this table is the only record of which console socket that address belongs to — so
 * it is also what decides whether a packet arriving from the internet is delivered to the console
 * or dropped.
 *
 * Design decisions that matter for a game console:
 *
 *  - **One mapping per client socket, not per connection** (endpoint-independent mapping). A PS4
 *    opens dozens of connections from a handful of local ports; mapping per destination would make
 *    this a symmetric NAT and PSN reports that as NAT type 3, which breaks matchmaking and party
 *    chat. One mapping per socket gives type 2, the same as a home router.
 *  - **Ports are 1024+, and unique per uplink and protocol**, so return traffic is demultiplexed on
 *    (uplink, protocol, port) alone. Keeping them unique per uplink means a mapping that has to
 *    move keeps its public port number when the new uplink has it free, which is the difference
 *    between "the server may still recognise you" and "it certainly will not".
 *  - **Timeouts follow Linux conntrack's**, which is the set of values every server on the internet
 *    has been tested against: an established TCP connection survives 124 minutes of silence, a
 *    never-answered UDP port dies in 30 seconds so the console's NAT-type probe does not leave
 *    garbage behind.
 *  - **Bounded**: a flood of spoofed or new flows cannot grow this past `maxMappings`; the least
 *    recently used mapping is evicted first, which is also what protects memory on a long session.
 */

import { flowId, remoteId, type FlowRemote } from './flow'

export interface NatTimeouts {
  /** A TCP connection that has seen traffic both ways: Linux's 7440 s (5 days is wrong; it is 124 min). */
  tcpEstablishedMs: number
  /** A TCP flow still opening, or one-sided: 120 s, as Linux's nf_conntrack_tcp_timeout_syn_*. */
  tcpOpeningMs: number
  /** UDP that something has answered through: 180 s (Linux's udp_timeout_stream). */
  udpRepliedMs: number
  /** UDP that nothing has answered: 30 s (Linux's udp_timeout). */
  udpUnrepliedMs: number
  /** ICMP echo mappings: 30 s, long enough for any ping a console makes. */
  icmpMs: number
}

export const DEFAULT_NAT_TIMEOUTS: NatTimeouts = {
  tcpEstablishedMs: 7_440_000,
  tcpOpeningMs: 120_000,
  udpRepliedMs: 180_000,
  udpUnrepliedMs: 30_000,
  icmpMs: 30_000
}

/** How many mappings the table holds before evicting the coldest. */
export const DEFAULT_MAX_MAPPINGS = 8192

/**
 * The public ports the gateway hands out.
 *
 * A dedicated range rather than "anything free" is what makes the capture filter possible: return
 * traffic is recognised by its destination port, so the whole range has to be expressible as a
 * comparison in the driver's filter, and it has to be a range the PC's own sockets will not use —
 * otherwise the gateway would capture, and drop, its own traffic.
 */
export const DEFAULT_PORT_RANGE = { min: 20_000, max: 29_999 }

export interface NatRemoteState {
  dstIp: string
  dstPort: number
  bytesOut: number
  bytesIn: number
  lastSeenAt: number
  /** TCP only: a SYN-ACK or any packet from the server has been seen. */
  replied: boolean
}

export interface NatMapping {
  /** Stable within a run; what telemetry refers to. */
  id: number
  /** IANA protocol number. */
  proto: number
  clientIp: string
  /** For ICMP, the echo identifier. */
  clientPort: number
  /** The uplink it leaves through, an interface id. */
  linkId: string
  /** The uplink's address when the mapping last went out; kept for diagnosis. */
  publicIp: string
  publicPort: number
  createdAt: number
  /** Last packet from the console through this mapping. */
  outboundAt: number
  /** Last packet from the internet through this mapping (0: never). */
  inboundAt: number
  bytesOut: number
  bytesIn: number
  remotes: Map<string, NatRemoteState>
}

export interface NatTableOptions {
  timeouts?: Partial<NatTimeouts>
  maxMappings?: number
  /** Port allocation is deterministic in tests; random in production so two runs don't collide. */
  portSeed?: () => number
  /** The public ports to allocate from. Must match what the capture filter looks for. */
  range?: { min: number; max: number }
}

/** The key return traffic is demultiplexed by. */
function publicKey(linkId: string, proto: number, port: number): string {
  return `${linkId}|${proto}|${port}`
}

export class NatTable {
  private readonly byFlow = new Map<string, NatMapping>()
  private readonly byPublic = new Map<string, string>()
  /** Next port to try, per `linkId|proto`, so allocation does not rescan from the bottom each time. */
  private readonly cursors = new Map<string, number>()
  private readonly timeouts: NatTimeouts
  private readonly maxMappings: number
  private readonly portSeed: () => number
  private readonly range: { min: number; max: number }
  private nextId = 1
  private evictions = 0

  constructor(options: NatTableOptions = {}) {
    this.timeouts = { ...DEFAULT_NAT_TIMEOUTS, ...options.timeouts }
    this.maxMappings = options.maxMappings ?? DEFAULT_MAX_MAPPINGS
    this.range = options.range ?? DEFAULT_PORT_RANGE
    this.portSeed = options.portSeed ?? (() => Math.floor(Math.random() * this.range.max))
  }

  /** The ports this table allocates from, which the capture filter has to match exactly. */
  get portRange(): { min: number; max: number } {
    return { ...this.range }
  }

  get size(): number {
    return this.byFlow.size
  }

  get evicted(): number {
    return this.evictions
  }

  /** The mapping a console socket's outgoing packet belongs to, if it has one. */
  lookup(proto: number, clientIp: string, clientPort: number): NatMapping | undefined {
    return this.byFlow.get(flowId({ proto, clientIp, clientPort }))
  }

  /** The mapping return traffic on `linkId`'s public port belongs to, if any. */
  lookupPublic(linkId: string, proto: number, publicPort: number): NatMapping | undefined {
    const id = this.byPublic.get(publicKey(linkId, proto, publicPort))
    return id === undefined ? undefined : this.byFlow.get(id)
  }

  /**
   * Opens a mapping for a console socket on `linkId`, or returns the existing one if it already has
   * a mapping on that link. Null means no port was free on this uplink, which is a real (if
   * unlikely) condition the caller must fall back from by trying the other uplink.
   */
  create(input: {
    proto: number
    clientIp: string
    clientPort: number
    linkId: string
    publicIp: string
    now: number
  }): NatMapping | null {
    const existing = this.lookup(input.proto, input.clientIp, input.clientPort)
    if (existing) {
      if (existing.linkId === input.linkId) {
        existing.publicIp = input.publicIp
        return existing
      }
      // A different uplink was asked for: this is a re-pin, handled by move().
      return this.move(existing, input.linkId, input.publicIp, input.now) ? existing : null
    }

    const publicPort = this.allocatePort(input.linkId, input.proto)
    if (publicPort === null) return null
    if (this.byFlow.size >= this.maxMappings) this.evictColdest()

    const mapping: NatMapping = {
      id: this.nextId++,
      proto: input.proto,
      clientIp: input.clientIp,
      clientPort: input.clientPort,
      linkId: input.linkId,
      publicIp: input.publicIp,
      publicPort,
      createdAt: input.now,
      outboundAt: input.now,
      inboundAt: 0,
      bytesOut: 0,
      bytesIn: 0,
      remotes: new Map()
    }
    const id = flowId(mapping)
    this.byFlow.set(id, mapping)
    this.byPublic.set(publicKey(mapping.linkId, mapping.proto, mapping.publicPort), id)
    return mapping
  }

  /**
   * Moves a mapping to another uplink — what failover does for UDP, which has no connection to
   * break. The public port is kept when the new uplink has it free, so a game server that has
   * already been told the old address at least sees the same port.
   */
  move(mapping: NatMapping, linkId: string, publicIp: string, now: number): boolean {
    if (mapping.linkId === linkId) {
      mapping.publicIp = publicIp
      return true
    }
    const previousKey = publicKey(mapping.linkId, mapping.proto, mapping.publicPort)
    const nextKey = publicKey(linkId, mapping.proto, mapping.publicPort)
    const portFree = !this.byPublic.has(nextKey)
    const port = portFree ? mapping.publicPort : this.allocatePort(linkId, mapping.proto)
    if (port === null) return false

    this.byPublic.delete(previousKey)
    this.byPublic.set(publicKey(linkId, mapping.proto, port), flowId(mapping))
    mapping.linkId = linkId
    mapping.publicIp = publicIp
    mapping.publicPort = port
    // A mapping that moves starts a fresh liveness clock: the console's next packet through it is
    // what proves the new uplink works for it.
    mapping.outboundAt = Math.max(mapping.outboundAt, now - this.timeoutFor(mapping) + 1000)
    return true
  }

  remove(mapping: NatMapping): void {
    this.byFlow.delete(flowId(mapping))
    this.byPublic.delete(publicKey(mapping.linkId, mapping.proto, mapping.publicPort))
  }

  /** Records a packet from the console, and the destination it went to. */
  observeOutbound(
    mapping: NatMapping,
    remote: FlowRemote | null,
    bytes: number,
    now: number
  ): void {
    mapping.outboundAt = now
    mapping.bytesOut += bytes
    if (!remote) return
    const key = remoteId(remote)
    let state = mapping.remotes.get(key)
    if (!state) {
      state = {
        dstIp: remote.dstIp,
        dstPort: remote.dstPort,
        bytesOut: 0,
        bytesIn: 0,
        lastSeenAt: now,
        replied: false
      }
      mapping.remotes.set(key, state)
    }
    state.bytesOut += bytes
    state.lastSeenAt = now
  }

  /** Records a packet from the internet. `remote` is the sender, when it could be parsed. */
  observeInbound(mapping: NatMapping, remote: FlowRemote | null, bytes: number, now: number): void {
    mapping.inboundAt = now
    mapping.bytesIn += bytes
    if (!remote) return
    const key = remoteId(remote)
    let state = mapping.remotes.get(key)
    if (!state) {
      // Return traffic for a destination never seen outbound happens with a full-cone mapping:
      // a peer learned the address from a matchmaking server. Record it; it is legitimate.
      state = {
        dstIp: remote.dstIp,
        dstPort: remote.dstPort,
        bytesOut: 0,
        bytesIn: 0,
        lastSeenAt: now,
        replied: true
      }
      mapping.remotes.set(key, state)
    }
    state.replied = true
    state.bytesIn += bytes
    state.lastSeenAt = now
  }

  /**
   * The idle time a mapping is allowed, by protocol and by whether anything has ever answered.
   * A console's NAT-type probe sends one UDP packet and waits; holding its port for 30 seconds
   * keeps the table honest without breaking the probe.
   */
  timeoutFor(mapping: NatMapping): number {
    if (mapping.proto === 1) return this.timeouts.icmpMs
    if (mapping.proto === 17) {
      return mapping.inboundAt > 0 ? this.timeouts.udpRepliedMs : this.timeouts.udpUnrepliedMs
    }
    const answered = [...mapping.remotes.values()].some((remote) => remote.replied)
    return answered ? this.timeouts.tcpEstablishedMs : this.timeouts.tcpOpeningMs
  }

  /** Drops every mapping that has been idle past its timeout, and returns them. */
  expire(now: number): NatMapping[] {
    const expired: NatMapping[] = []
    for (const mapping of this.byFlow.values()) {
      const last = Math.max(mapping.outboundAt, mapping.inboundAt)
      if (now - last > this.timeoutFor(mapping)) expired.push(mapping)
    }
    for (const mapping of expired) this.remove(mapping)
    return expired
  }

  /** Every live mapping, for telemetry. */
  mappings(): NatMapping[] {
    return [...this.byFlow.values()]
  }

  /** Mapping count and byte totals, for the UI and for the tests' accounting. */
  stats(): {
    mappings: number
    tcp: number
    udp: number
    icmp: number
    bytesOut: number
    bytesIn: number
  } {
    let tcp = 0
    let udp = 0
    let icmp = 0
    let bytesOut = 0
    let bytesIn = 0
    for (const mapping of this.byFlow.values()) {
      if (mapping.proto === 6) tcp++
      else if (mapping.proto === 17) udp++
      else if (mapping.proto === 1) icmp++
      bytesOut += mapping.bytesOut
      bytesIn += mapping.bytesIn
    }
    return { mappings: this.byFlow.size, tcp, udp, icmp, bytesOut, bytesIn }
  }

  /**
   * A public port nothing else on this uplink and protocol is using. Allocation walks upward from a
   * per-uplink cursor, so consecutive flows get consecutive ports (which keeps the port numbers
   * plausible and the search short) and wraps once.
   */
  private allocatePort(linkId: string, proto: number): number | null {
    const { min, max } = this.range
    const cursorKey = `${linkId}|${proto}`
    let cursor = this.cursors.get(cursorKey)
    if (cursor === undefined || cursor < min || cursor > max) {
      cursor = min + (this.portSeed() % (max - min + 1))
    }
    const span = max - min + 1
    for (let step = 0; step < span; step++) {
      const port = min + ((cursor - min + step) % span)
      if (!this.byPublic.has(publicKey(linkId, proto, port))) {
        this.cursors.set(cursorKey, port + 1 > max ? min : port + 1)
        return port
      }
    }
    return null
  }

  private evictColdest(): void {
    let coldest: NatMapping | null = null
    for (const mapping of this.byFlow.values()) {
      if (!coldest) {
        coldest = mapping
        continue
      }
      const mappingLast = Math.max(mapping.outboundAt, mapping.inboundAt)
      const coldestLast = Math.max(coldest.outboundAt, coldest.inboundAt)
      if (mappingLast < coldestLast) coldest = mapping
    }
    if (coldest) {
      this.remove(coldest)
      this.evictions++
    }
  }
}
