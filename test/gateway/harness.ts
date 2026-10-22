/**
 * A small simulated network for the gateway tests: one console, two uplinks, and enough of "the
 * internet" to answer.
 *
 * The gateway's engine takes bytes and returns "send these bytes out this interface", so a test can
 * stand in for both the console and the internet without any sockets, any driver, or any
 * privileges — and can do it deterministically, with the clock under the test's control, which is
 * what makes timing-sensitive behaviour (failover, expiry, hysteresis) assertable at all.
 */

import {
  buildTcpPacket,
  buildUdpPacket,
  parseIpv4,
  parseTcp,
  IPPROTO,
  TCP_FLAG,
  type Ipv4Packet
} from '../../src/main/gateway/packet'
import {
  GatewayForwarder,
  type Transmit,
  type UplinkRuntime
} from '../../src/main/gateway/forwarder'
import { NatTable } from '../../src/main/gateway/nat'

export const CONSOLE_IP = '192.168.77.10'
export const CONSOLE_MAC = 'aa:bb:cc:dd:ee:01'
export const GATEWAY_LAN_IP = '192.168.77.1'
export const WIFI = {
  id: 'Wi-Fi',
  address: '192.168.1.42',
  ifIdx: 7,
  mtu: 1500,
  mac: '11:22:33:44:55:01'
}
export const USB = {
  id: 'Ethernet 3',
  address: '192.168.42.7',
  ifIdx: 12,
  mtu: 1500,
  mac: '11:22:33:44:55:02'
}
export const LAN_IFIDX = 3

export interface SimUplink extends UplinkRuntime {
  /** A firewall level failure: the adapter is there but nothing gets through. */
  reachable: boolean
  enabled: boolean
}

export class World {
  readonly nat = new NatTable({ portSeed: () => 20000 })
  readonly uplinks: SimUplink[]
  readonly forwarder: GatewayForwarder
  now = 1_700_000_000_000
  /** Everything any uplink was told to send, in order, for assertions. */
  readonly sent: (Transmit & { at: number })[] = []
  /** Everything delivered to the console. */
  readonly deliveredToConsole: (Transmit & { at: number })[] = []
  lanMtu = 1500
  /** Live: the forwarder reads these on every packet, as the service's settings do. */
  readonly options: { tcpFailover: 'reset' | 'hold' } = {
    tcpFailover: 'reset'
  }

  get tcpFailover(): 'reset' | 'hold' {
    return this.options.tcpFailover
  }

  set tcpFailover(value: 'reset' | 'hold') {
    this.options.tcpFailover = value
  }

  constructor(options: { uplinks?: SimUplink[]; lanMtu?: number } = {}) {
    this.uplinks =
      options.uplinks ??
      ([WIFI, USB].map((link) => ({
        ...link,
        usable: true,
        weight: 0.5,
        reachable: true,
        enabled: true
      })) as SimUplink[])
    this.lanMtu = options.lanMtu ?? 1500
    this.forwarder = new GatewayForwarder(
      this.nat,
      () => this.uplinks,
      () => ({
        id: 'Ethernet',
        address: GATEWAY_LAN_IP,
        mac: 'aa:bb:cc:dd:ee:ff',
        ifIdx: LAN_IFIDX,
        mtu: this.lanMtu,
        subnet: '192.168.77.0/24'
      }),
      () => this.now,
      this.options
    )
  }

  uplink(id: string): SimUplink {
    const found = this.uplinks.find((link) => link.id === id)
    if (!found) throw new Error(`no uplink ${id}`)
    return found
  }

  /** Takes an uplink out, the way an adapter losing its carrier does. */
  kill(id: string): void {
    const link = this.uplink(id)
    link.usable = false
    link.reachable = false
  }

  revive(id: string): void {
    const link = this.uplink(id)
    link.usable = true
    link.reachable = true
  }

  setWeights(weights: Record<string, number>): void {
    for (const link of this.uplinks) link.weight = weights[link.id] ?? 0
  }

  advance(ms: number): void {
    this.now += ms
    this.forwarder.housekeeping(this.now)
  }

  /** The console sends a packet; returns what the gateway sent out of an uplink. */
  outbound(bytes: Buffer): { transmit: Transmit[]; linkId?: string; dropped?: string } {
    const result = this.forwarder.outbound(bytes)
    for (const entry of result.transmit) {
      if (entry.linkId) this.sent.push({ ...entry, at: this.now })
      else this.deliveredToConsole.push({ ...entry, at: this.now })
    }
    return result
  }

  /** A packet arrives from `linkId`; returns what the gateway delivered to the console. */
  inbound(
    bytes: Buffer,
    linkId: string
  ): { transmit: Transmit[]; dropped?: string; delivered?: boolean } {
    const result = this.forwarder.inbound(bytes, this.uplink(linkId).ifIdx)
    for (const entry of result.transmit) this.deliveredToConsole.push({ ...entry, at: this.now })
    return result
  }

  /** The last packet an uplink was told to send, parsed. */
  lastSent(linkId?: string): Ipv4Packet {
    const candidates = linkId ? this.sent.filter((entry) => entry.linkId === linkId) : this.sent
    const entry = candidates[candidates.length - 1]
    if (!entry) throw new Error('nothing was sent')
    const packet = parseIpv4(entry.packet)
    if (!packet) throw new Error('what was sent is not a parseable IPv4 packet')
    return packet
  }
}

/** A console's TCP segment, with sane defaults. */
export function consoleTcp(options: {
  srcPort: number
  dstIp: string
  dstPort: number
  flags: number
  seq?: number
  ack?: number
  payload?: Buffer
  mss?: number
  identification?: number
  dontFragment?: boolean
}): Buffer {
  const bytes = buildTcpPacket({
    srcIp: CONSOLE_IP,
    dstIp: options.dstIp,
    srcPort: options.srcPort,
    dstPort: options.dstPort,
    flags: options.flags,
    seq: options.seq,
    ack: options.ack,
    payload: options.payload,
    mss: options.mss ?? ((options.flags & TCP_FLAG.SYN) !== 0 ? 1460 : undefined),
    dontFragment: options.dontFragment
  })
  if (!bytes) throw new Error('could not build the packet')
  return bytes
}

/** A console's UDP datagram. */
export function consoleUdp(options: {
  srcPort: number
  dstIp: string
  dstPort: number
  payload?: Buffer
  dontFragment?: boolean
}): Buffer {
  const bytes = buildUdpPacket({
    srcIp: CONSOLE_IP,
    dstIp: options.dstIp,
    srcPort: options.srcPort,
    dstPort: options.dstPort,
    payload: options.payload ?? Buffer.from('udp payload'),
    dontFragment: options.dontFragment
  })
  if (!bytes) throw new Error('could not build the packet')
  return bytes
}

/**
 * The internet's answer to a packet the gateway just sent: a TCP segment or UDP datagram from the
 * original destination to whatever public address and port the gateway used, which is exactly what
 * a server on the other side sees.
 */
export function replyTo(
  sent: Ipv4Packet,
  options: { payload?: Buffer; flags?: number; mss?: number; seq?: number; ack?: number } = {}
): Buffer {
  const tcp = sent.protocol === IPPROTO.TCP ? parseTcp(sent) : null
  if (tcp) {
    const bytes = buildTcpPacket({
      srcIp: sent.dstIp,
      dstIp: sent.srcIp,
      srcPort: tcp.dstPort,
      dstPort: tcp.srcPort,
      flags: options.flags ?? TCP_FLAG.ACK | TCP_FLAG.SYN,
      seq: options.seq ?? 5000,
      ack: options.ack ?? tcp.seq + 1,
      payload: options.payload ?? Buffer.alloc(0),
      mss: options.mss
    })
    if (!bytes) throw new Error('could not build the reply')
    return bytes
  }
  const bytes = buildUdpPacket({
    srcIp: sent.dstIp,
    dstIp: sent.srcIp,
    srcPort: sent.buffer.readUInt16BE(sent.payloadOffset + 2),
    dstPort: sent.buffer.readUInt16BE(sent.payloadOffset),
    payload: options.payload ?? Buffer.from('server payload')
  })
  if (!bytes) throw new Error('could not build the reply')
  return bytes
}

/** Whichever uplink a packet went out of, by its interface index. */
export function uplinkOf(transmit: Transmit, uplinks: SimUplink[]): SimUplink | undefined {
  return uplinks.find((link) => link.ifIdx === transmit.ifIdx)
}
