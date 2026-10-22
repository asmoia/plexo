/**
 * A minimal DHCP server for the console's own port.
 *
 * A PS4 set to "automatic" asks for an address the moment the cable is in; with nothing answering,
 * it gives up and the gateway has nothing to forward. Asking the user to type a static address into
 * a console is a bad first experience and a worse one to debug, so the gateway answers DHCP itself.
 *
 * It is deliberately small — DISCOVER/REQUEST in, OFFER/ACK out, one subnet, sticky leases — because
 * the only client is the console on the other end of one cable. Every packet is built and parsed by
 * hand, with no dependency, and the whole server is a pure function of the request plus the lease
 * table, so it is tested by feeding it bytes rather than by running a network.
 */

import { buildUdpPacket, inSubnet } from './packet'

const DHCP_SERVER_PORT = 67
const DHCP_CLIENT_PORT = 68
const MAGIC_COOKIE = Buffer.from([0x63, 0x82, 0x53, 0x63])

export const DHCP_MESSAGE = {
  DISCOVER: 1,
  OFFER: 2,
  REQUEST: 3,
  DECLINE: 4,
  ACK: 5,
  NAK: 6,
  RELEASE: 7,
  INFORM: 8
} as const

export interface DhcpRequest {
  /** 1 BOOTREQUEST, 2 BOOTREPLY. */
  op: number
  messageType: number
  xid: number
  /** Client MAC, lowercase colon-separated. */
  clientMac: string
  /** The address the client asks for or confirms, when it names one. */
  requestedIp: string | null
  /** Which server the client is answering, when it names one. */
  serverIdentifier: string | null
  hostname: string | null
  /** The client already has a valid lease and only wants configuration. */
  ciaddr: string
  flags: number
  /** Options 60/61, kept for the log. */
  vendorClass: string | null
}

export interface DhcpServerOptions {
  /** The gateway's address on the console port: the server identifier and the offered router. */
  serverAddress: string
  /** The subnet to hand out addresses from, e.g. 192.168.77.0/24. */
  subnet: string
  /** Netmask to advertise, e.g. 255.255.255.0. */
  netmask: string
  dnsServers: string[]
  /** The MTU to advertise, so the console's own stack does not send what an uplink cannot carry. */
  mtu: number
  /** First address of the pool; the pool runs to the end of the subnet. */
  firstHost?: number
  leaseSeconds?: number
}

export interface DhcpLease {
  ip: string
  mac: string
  hostname: string | null
  expiresAt: number
}

function macOf(buffer: Buffer, offset: number, length: number): string {
  const parts: string[] = []
  for (let index = 0; index < Math.min(6, length); index++) {
    parts.push(buffer[offset + index].toString(16).padStart(2, '0'))
  }
  return parts.join(':')
}

function optionValue(options: Buffer, code: number): Buffer | null {
  let index = 0
  while (index < options.length) {
    const kind = options[index]
    if (kind === 0) {
      index += 1
      continue
    }
    if (kind === 255) return null
    const length = options[index + 1]
    if (length === undefined || index + 2 + length > options.length) return null
    if (kind === code) return options.subarray(index + 2, index + 2 + length)
    index += 2 + length
  }
  return null
}

/** Reads a DHCP message out of a UDP payload, or null when it is not one. */
export function parseDhcp(payload: Buffer): DhcpRequest | null {
  if (payload.length < 240) return null
  if (!payload.subarray(236, 240).equals(MAGIC_COOKIE)) return null
  const hlen = payload[2]
  if (hlen < 1 || hlen > 16) return null
  const options = payload.subarray(240)
  const messageType = optionValue(options, 53)?.[0]
  if (messageType === undefined) return null

  const requested = optionValue(options, 50)
  const server = optionValue(options, 54)
  const hostname = optionValue(options, 12)
  const vendor = optionValue(options, 60)
  return {
    op: payload[0],
    messageType,
    xid: payload.readUInt32BE(4),
    clientMac: macOf(payload, 28, hlen),
    requestedIp: requested && requested.length === 4 ? [...requested].join('.') : null,
    serverIdentifier: server && server.length === 4 ? [...server].join('.') : null,
    hostname: hostname ? hostname.toString('utf8') : null,
    ciaddr: [payload[12], payload[13], payload[14], payload[15]].join('.'),
    flags: payload.readUInt16BE(10),
    vendorClass: vendor ? vendor.toString('utf8') : null
  }
}

function pushOption(target: number[], code: number, value: number[]): void {
  target.push(code, value.length, ...value)
}

/** A 32-bit option value (lease times) as its four bytes, big-endian. */
function u32(value: number): number[] {
  return [(value >>> 24) & 0xff, (value >>> 16) & 0xff, (value >>> 8) & 0xff, value & 0xff]
}

/**
 * The DHCP server's state: the pool, the leases, and the replies. `handle` takes the whole UDP
 * payload a console sent and returns the UDP payload to send back (or null when nothing is owed).
 */
export class DhcpServer {
  private readonly leases = new Map<string, DhcpLease>()
  private readonly byIp = new Map<string, string>()

  constructor(private readonly options: DhcpServerOptions) {}

  /** The console's lease, once it has one. */
  clientLease(): DhcpLease | null {
    for (const lease of this.leases.values()) return lease
    return null
  }

  leasesNow(now = Date.now()): DhcpLease[] {
    this.expire(now)
    return [...this.leases.values()]
  }

  expire(now: number): void {
    for (const [mac, lease] of this.leases) {
      if (lease.expiresAt <= now) {
        this.leases.delete(mac)
        this.byIp.delete(lease.ip)
      }
    }
  }

  /**
   * Answers one message. A REQUEST naming a different server is ignored (another DHCP server on the
   * cable owns it); a REQUEST for an address we cannot give is NAKed so the console retries at once
   * instead of timing out.
   */
  handle(payload: Buffer, now = Date.now()): { payload: Buffer; broadcast: boolean } | null {
    const request = parseDhcp(payload)
    if (!request) return null
    // Our own broadcast replies land back on this socket on a machine with one network; answering
    // one would be an infinite exchange.
    if (request.op !== 1) return null
    this.expire(now)

    if (request.messageType === DHCP_MESSAGE.RELEASE) {
      const lease = this.leases.get(request.clientMac)
      if (lease) {
        this.leases.delete(request.clientMac)
        this.byIp.delete(lease.ip)
      }
      return null
    }
    if (request.messageType === DHCP_MESSAGE.DECLINE) return null
    if (request.messageType === DHCP_MESSAGE.INFORM) {
      return {
        payload: this.buildReply(request, this.options.serverAddress, DHCP_MESSAGE.ACK, now),
        broadcast: false
      }
    }
    if (
      request.messageType !== DHCP_MESSAGE.DISCOVER &&
      request.messageType !== DHCP_MESSAGE.REQUEST
    ) {
      return null
    }
    if (
      request.messageType === DHCP_MESSAGE.REQUEST &&
      request.serverIdentifier !== null &&
      request.serverIdentifier !== this.options.serverAddress
    ) {
      return null
    }

    const existing = this.leases.get(request.clientMac)
    const wanted = request.requestedIp ?? existing?.ip ?? null
    const address =
      wanted && this.usable(wanted, request.clientMac)
        ? wanted
        : (existing?.ip ?? this.allocate(request.clientMac))
    if (!address) return null

    if (
      request.messageType === DHCP_MESSAGE.REQUEST &&
      wanted &&
      address !== wanted &&
      wanted !== '0.0.0.0'
    ) {
      return { payload: this.buildReply(request, null, DHCP_MESSAGE.NAK, now), broadcast: true }
    }

    const lease: DhcpLease = {
      ip: address,
      mac: request.clientMac,
      hostname: request.hostname,
      expiresAt: now + (this.options.leaseSeconds ?? 3600) * 1000
    }
    const previous = this.leases.get(request.clientMac)
    if (previous) this.byIp.delete(previous.ip)
    this.leases.set(request.clientMac, lease)
    this.byIp.set(address, request.clientMac)

    return {
      payload: this.buildReply(
        request,
        address,
        request.messageType === DHCP_MESSAGE.DISCOVER ? DHCP_MESSAGE.OFFER : DHCP_MESSAGE.ACK,
        now
      ),
      // A console with no address yet can only be reached by broadcast; one that has one gets a
      // unicast answer, which is what its own stack expects after the first exchange.
      broadcast: request.ciaddr === '0.0.0.0' || address !== request.ciaddr
    }
  }

  /** Whether `address` may be given to `mac`: in our subnet, not the gateway's, not someone else's. */
  private usable(address: string, mac: string): boolean {
    if (!inSubnet(address, this.options.subnet)) return false
    if (address === this.options.serverAddress) return false
    // The directed broadcast address of the subnet is not a host address.
    const octets = address.split('.').map(Number)
    if (octets[3] === 255) return false
    const owner = this.byIp.get(address)
    return owner === undefined || owner === mac
  }

  /** The first free address from `firstHost` upward: predictable, which makes logs readable. */
  private allocate(mac: string): string | null {
    const [network] = this.options.subnet.split('/')
    const parts = network.split('.').map(Number)
    const existing = this.leases.get(mac)
    if (existing) return existing.ip
    for (let host = this.options.firstHost ?? 100; host < 255; host++) {
      const candidate = `${parts[0]}.${parts[1]}.${parts[2]}.${host}`
      if (!this.byIp.has(candidate)) return candidate
    }
    return null
  }

  private buildReply(
    request: DhcpRequest,
    address: string | null,
    type: number,
    now: number
  ): Buffer {
    const reply = Buffer.alloc(300)
    reply[0] = 2 // BOOTREPLY
    reply[1] = 1 // ethernet
    reply[2] = 6 // address length
    reply[3] = 0
    reply.writeUInt32BE(request.xid, 4)
    reply.writeUInt16BE(request.flags, 10)
    if (address && type !== DHCP_MESSAGE.NAK) {
      const octets = address.split('.').map(Number)
      reply[12] = 0
      reply[13] = 0
      reply[14] = 0
      reply[15] = 0
      reply.set(octets, 16) // yiaddr
    }
    const serverOctets = this.options.serverAddress.split('.').map(Number)
    // siaddr: the next server to talk to, which for DHCP is the server itself.
    reply.set(serverOctets, 20)
    request.clientMac.split(':').forEach((part, index) => {
      reply[28 + index] = Number.parseInt(part, 16)
    })
    MAGIC_COOKIE.copy(reply, 236)

    const options: number[] = []
    pushOption(options, 53, [type])
    pushOption(options, 54, serverOctets)
    if (type !== DHCP_MESSAGE.NAK) {
      const lease = this.options.leaseSeconds ?? 3600
      // T1/T2 at the RFC 2131 defaults: half the lease, then seven eighths.
      pushOption(options, 51, u32(lease))
      pushOption(options, 58, u32(Math.floor(lease / 2)))
      pushOption(options, 59, u32(Math.floor((lease * 7) / 8)))
      if (address) {
        const words = address.split('.').map(Number)
        pushOption(options, 1, this.options.netmask.split('.').map(Number)) // netmask
        pushOption(options, 28, [words[0], words[1], words[2], 255]) // broadcast
      }
      pushOption(options, 3, serverOctets) // router: the gateway is the way out
      for (const dns of this.options.dnsServers) {
        pushOption(options, 6, dns.split('.').map(Number))
      }
      if (this.options.mtu > 0)
        pushOption(options, 26, [(this.options.mtu >> 8) & 0xff, this.options.mtu & 0xff])
      pushOption(options, 42, serverOctets) // NTP: the gateway's clock is good enough
    }
    options.push(255)
    let offset = 240
    for (const byte of options) {
      if (offset >= reply.length) break
      reply[offset++] = byte
    }
    void now
    return reply.subarray(0, offset)
  }
}

/**
 * Wraps a DHCP reply in the UDP/IPv4 datagram that carries it: from the gateway's port 67 to the
 * console's port 68, broadcast while the console has no address of its own.
 */
export function dhcpReplyDatagram(options: {
  payload: Buffer
  serverAddress: string
  broadcast: boolean
  clientIp?: string
}): Buffer | null {
  return buildUdpPacket({
    srcIp: options.serverAddress,
    dstIp: options.broadcast ? '255.255.255.255' : (options.clientIp ?? '255.255.255.255'),
    srcPort: DHCP_SERVER_PORT,
    dstPort: DHCP_CLIENT_PORT,
    payload: options.payload,
    ttl: 64
  })
}
