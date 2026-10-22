import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  DhcpServer,
  dhcpReplyDatagram,
  parseDhcp,
  DHCP_MESSAGE
} from '../../src/main/gateway/dhcp.ts'
import { parseIpv4, parseUdp, verifyChecksums } from '../../src/main/gateway/packet.ts'

const CONSOLE_MAC = 'aa:bb:cc:dd:ee:01'
const T0 = 1_700_000_000_000

function server(overrides = {}): DhcpServer {
  return new DhcpServer({
    serverAddress: '192.168.77.1',
    subnet: '192.168.77.0/24',
    netmask: '255.255.255.0',
    dnsServers: ['192.168.77.1'],
    mtu: 1500,
    ...overrides
  })
}

/** A DHCP message as a console sends it, with the options each step needs. */
function dhcpMessage(options: {
  type: number
  mac?: string
  xid?: number
  requestedIp?: string
  serverIdentifier?: string
  hostname?: string
  ciaddr?: string
}): Buffer {
  const buffer = Buffer.alloc(300)
  buffer[0] = 1 // BOOTREQUEST
  buffer[1] = 1
  buffer[2] = 6
  buffer.writeUInt32BE(options.xid ?? 0x1234, 4)
  if (options.ciaddr) buffer.set(options.ciaddr.split('.').map(Number), 12)
  ;(options.mac ?? CONSOLE_MAC).split(':').forEach((part, index) => {
    buffer[28 + index] = Number.parseInt(part, 16)
  })
  Buffer.from([0x63, 0x82, 0x53, 0x63]).copy(buffer, 236)
  const bytes: number[] = [53, 1, options.type]
  if (options.requestedIp) bytes.push(50, 4, ...options.requestedIp.split('.').map(Number))
  if (options.serverIdentifier) {
    bytes.push(54, 4, ...options.serverIdentifier.split('.').map(Number))
  }
  if (options.hostname) {
    const encoded = [...Buffer.from(options.hostname, 'utf8')]
    bytes.push(12, encoded.length, ...encoded)
  }
  bytes.push(55, 4, 1, 3, 6, 26, 255)
  buffer.set(bytes, 240)
  return buffer.subarray(0, 240 + bytes.length)
}

function optionsOf(payload: Buffer): Map<number, number[]> {
  const map = new Map<number, number[]>()
  let index = 240
  while (index < payload.length) {
    const code = payload[index]
    if (code === 255) break
    const length = payload[index + 1]
    map.set(code, [...payload.subarray(index + 2, index + 2 + length)])
    index += 2 + length
  }
  return map
}

test('a DISCOVER is answered with an OFFER that tells the console how to use the gateway', () => {
  const dhcp = server()
  const reply = dhcp.handle(dhcpMessage({ type: DHCP_MESSAGE.DISCOVER }), T0)
  assert.ok(reply)
  assert.equal(reply.broadcast, true, 'a console with no address can only hear a broadcast')
  const options = optionsOf(reply.payload)
  assert.deepEqual(options.get(53), [DHCP_MESSAGE.OFFER])
  assert.deepEqual(options.get(54), [192, 168, 77, 1], 'server identifier')
  assert.deepEqual(options.get(3), [192, 168, 77, 1], 'the gateway is the console’s router')
  assert.deepEqual(options.get(6), [192, 168, 77, 1], 'and its DNS server')
  assert.deepEqual(options.get(1), [255, 255, 255, 0])
  assert.deepEqual(options.get(26), [1500 >> 8, 1500 & 0xff], 'MTU, so the console matches the LAN')
  const yiaddr = [...reply.payload.subarray(16, 20)]
  assert.deepEqual(yiaddr, [192, 168, 77, 100], 'the first pool address')
  assert.equal(reply.payload.readUInt32BE(4), 0x1234, 'the transaction id is echoed')
  assert.deepEqual([...reply.payload.subarray(28, 34)], [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01])
})

test('the console’s REQUEST is ACKed, and its lease sticks to its MAC across restarts of the request', () => {
  const dhcp = server()
  const offer = dhcp.handle(dhcpMessage({ type: DHCP_MESSAGE.DISCOVER }), T0)
  assert.ok(offer)
  const offered = [...offer.payload.subarray(16, 20)].join('.')
  const ack = dhcp.handle(
    dhcpMessage({
      type: DHCP_MESSAGE.REQUEST,
      requestedIp: offered,
      serverIdentifier: '192.168.77.1'
    }),
    T0 + 1000
  )
  assert.ok(ack)
  const options = optionsOf(ack.payload)
  assert.deepEqual(options.get(53), [DHCP_MESSAGE.ACK])
  assert.equal([...ack.payload.subarray(16, 20)].join('.'), offered)

  // A second console gets a different address; the first keeps its own.
  const other = dhcp.handle(
    dhcpMessage({ type: DHCP_MESSAGE.DISCOVER, mac: 'aa:bb:cc:dd:ee:02', xid: 2 }),
    T0 + 2000
  )
  assert.ok(other)
  const otherIp = [...other.payload.subarray(16, 20)].join('.')
  assert.notEqual(otherIp, offered)
  const again = dhcp.handle(dhcpMessage({ type: DHCP_MESSAGE.DISCOVER, xid: 3 }), T0 + 3000)
  assert.ok(again)
  assert.equal(
    [...again.payload.subarray(16, 20)].join('.'),
    offered,
    'the same MAC gets the same address'
  )
})

test('a request for an address another console holds is NAKed', () => {
  const dhcp = server()
  dhcp.handle(dhcpMessage({ type: DHCP_MESSAGE.DISCOVER }), T0)
  dhcp.handle(
    dhcpMessage({
      type: DHCP_MESSAGE.REQUEST,
      requestedIp: '192.168.77.100',
      serverIdentifier: '192.168.77.1'
    }),
    T0 + 1000
  )
  const nak = dhcp.handle(
    dhcpMessage({
      type: DHCP_MESSAGE.REQUEST,
      mac: 'aa:bb:cc:dd:ee:09',
      requestedIp: '192.168.77.100',
      serverIdentifier: '192.168.77.1'
    }),
    T0 + 2000
  )
  assert.ok(nak)
  assert.deepEqual(optionsOf(nak.payload).get(53), [DHCP_MESSAGE.NAK])
  assert.equal([...nak.payload.subarray(16, 20)].join('.'), '0.0.0.0', 'a NAK carries no address')
})

test('an address outside the pool, the gateway itself, or the broadcast address is never offered', () => {
  const dhcp = server()
  for (const bad of ['192.168.78.50', '192.168.77.1', '192.168.77.255']) {
    const reply = dhcp.handle(
      dhcpMessage({
        type: DHCP_MESSAGE.REQUEST,
        requestedIp: bad,
        serverIdentifier: '192.168.77.1'
      }),
      T0
    )
    assert.ok(reply, `a request for ${bad} must be answered`)
    const offered = [...reply.payload.subarray(16, 20)].join('.')
    assert.notEqual(offered, bad, `${bad} must not be handed out`)
  }
})

test('a REQUEST addressed to another DHCP server on the cable is left alone', () => {
  const dhcp = server()
  const reply = dhcp.handle(
    dhcpMessage({
      type: DHCP_MESSAGE.REQUEST,
      requestedIp: '192.168.77.100',
      serverIdentifier: '192.168.77.254'
    }),
    T0
  )
  assert.equal(reply, null, 'two DHCP servers must not both answer')
})

test('a lease expires, and the address can be given to the next console', () => {
  const dhcp = server({ leaseSeconds: 60 })
  dhcp.handle(dhcpMessage({ type: DHCP_MESSAGE.DISCOVER }), T0)
  assert.equal(dhcp.clientLease()?.ip, '192.168.77.100')
  // Just before expiry the lease is still there; after it, the address is free again.
  assert.equal(dhcp.leasesNow(T0 + 59_000).length, 1)
  assert.equal(dhcp.leasesNow(T0 + 61_000).length, 0)
  const other = dhcp.handle(
    dhcpMessage({ type: DHCP_MESSAGE.DISCOVER, mac: 'aa:bb:cc:dd:ee:03', xid: 9 }),
    T0 + 62_000
  )
  assert.ok(other)
  assert.equal([...other.payload.subarray(16, 20)].join('.'), '192.168.77.100')
})

test('RELEASE frees the lease, and a DECLINE is not answered', () => {
  const dhcp = server()
  dhcp.handle(dhcpMessage({ type: DHCP_MESSAGE.DISCOVER }), T0)
  assert.equal(dhcp.clientLease()?.ip, '192.168.77.100')
  const released = dhcp.handle(dhcpMessage({ type: DHCP_MESSAGE.RELEASE }), T0 + 1000)
  assert.equal(released, null)
  assert.equal(dhcp.clientLease(), null)
  assert.equal(dhcp.handle(dhcpMessage({ type: DHCP_MESSAGE.DECLINE }), T0 + 2000), null)
})

test('garbage, truncated and non-DHCP payloads produce no reply and no crash', () => {
  const dhcp = server()
  assert.equal(dhcp.handle(Buffer.alloc(10), T0), null)
  const wrongCookie = dhcpMessage({ type: DHCP_MESSAGE.DISCOVER })
  wrongCookie[236] = 0
  assert.equal(dhcp.handle(wrongCookie, T0), null)
  const noType = dhcpMessage({ type: DHCP_MESSAGE.DISCOVER })
  noType[240] = 255 // cut the options off at once
  assert.equal(dhcp.handle(noType, T0), null)
  assert.equal(parseDhcp(Buffer.alloc(400)), null)
})

test('a DHCP reply becomes a valid broadcast UDP datagram', () => {
  const dhcp = server()
  const reply = dhcp.handle(dhcpMessage({ type: DHCP_MESSAGE.DISCOVER }), T0)
  assert.ok(reply)
  const datagram = dhcpReplyDatagram({
    payload: reply.payload,
    serverAddress: '192.168.77.1',
    broadcast: reply.broadcast
  })
  assert.ok(datagram)
  const packet = parseIpv4(datagram)
  assert.ok(packet)
  assert.equal(packet.srcIp, '192.168.77.1')
  assert.equal(packet.dstIp, '255.255.255.255')
  assert.equal(parseUdp(packet)?.srcPort, 67)
  assert.equal(parseUdp(packet)?.dstPort, 68)
  assert.equal(verifyChecksums(packet), true)
  // And the payload survives the envelope.
  const carried = parseDhcp(packet.buffer.subarray(packet.payloadOffset + 8))
  assert.equal(carried?.op, 2, 'it is a BOOTREPLY')
  assert.equal(carried?.messageType, DHCP_MESSAGE.OFFER)
  assert.equal(
    dhcp.handle(packet.buffer.subarray(packet.payloadOffset + 8), T0),
    null,
    'the server must never answer its own reply, or the two would trade messages forever'
  )
})
