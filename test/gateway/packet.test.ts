import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  buildIcmpFragmentationNeeded,
  buildTcpPacket,
  buildUdpPacket,
  fragmentIpv4,
  internetChecksum,
  inSubnet,
  ipv4ToNumber,
  mssForMtu,
  parseIcmp,
  parseIpv4,
  parseTcp,
  parseUdp,
  rewritePacket,
  tcpMssOption,
  verifyChecksums,
  TCP_FLAG,
  IPPROTO,
  buildTcpReset
} from '../../src/main/gateway/packet.ts'

const A = {
  client: '192.168.77.10',
  gateway: '192.168.77.1',
  wifi: '192.168.1.42',
  server: '93.184.216.34'
}

test('a built TCP SYN parses back to what it was built from, checksums included', () => {
  const bytes = buildTcpPacket({
    srcIp: A.client,
    dstIp: A.server,
    srcPort: 40000,
    dstPort: 443,
    flags: TCP_FLAG.SYN,
    seq: 1000,
    mss: 1460
  })
  assert.ok(bytes)
  const packet = parseIpv4(bytes)
  assert.ok(packet, 'the packet must parse')
  assert.equal(packet.srcIp, A.client)
  assert.equal(packet.dstIp, A.server)
  assert.equal(packet.protocol, IPPROTO.TCP)
  assert.equal(verifyChecksums(packet), true)
  const tcp = parseTcp(packet)
  assert.equal(tcp?.dstPort, 443)
  assert.equal(tcp?.flags, TCP_FLAG.SYN)
  assert.equal(tcpMssOption(packet), 1460)
})

test('NAT rewriting changes addresses and port and leaves every checksum valid', () => {
  const bytes = buildTcpPacket({
    srcIp: A.client,
    dstIp: A.server,
    srcPort: 40000,
    dstPort: 443,
    flags: TCP_FLAG.SYN,
    mss: 1460,
    payload: Buffer.from('a payload that must survive the rewrite')
  })
  assert.ok(bytes)
  const packet = parseIpv4(bytes)
  assert.ok(packet)
  const rewritten = rewritePacket(packet, {
    srcIp: A.wifi,
    srcPort: 61000,
    decrementTtl: true,
    clampMssTo: 1420
  })
  assert.equal(rewritten.ok, true)
  if (!rewritten.ok) return
  const out = parseIpv4(rewritten.packet)
  assert.ok(out)
  assert.equal(out.srcIp, A.wifi)
  assert.equal(out.dstIp, A.server, 'the destination is untouched')
  assert.equal(out.ttl, packet.ttl - 1)
  assert.equal(parseTcp(out)?.srcPort, 61000)
  assert.equal(tcpMssOption(out), 1420, 'MSS is clamped down')
  assert.equal(verifyChecksums(out), true, 'both checksums must be valid after the rewrite')
  // The payload must be byte-identical: a rewrite that shifted it would corrupt every download.
  assert.deepEqual(
    out.buffer.subarray(out.payloadOffset + (parseTcp(out)?.headerLength ?? 0)),
    packet.buffer.subarray(packet.payloadOffset + (parseTcp(packet)?.headerLength ?? 0))
  )
})

test('the original packet is not modified by a rewrite', () => {
  const bytes = buildUdpPacket({
    srcIp: A.client,
    dstIp: A.server,
    srcPort: 5000,
    dstPort: 3074,
    payload: Buffer.from('udp')
  })
  assert.ok(bytes)
  const before = Buffer.from(bytes)
  const packet = parseIpv4(bytes)
  assert.ok(packet)
  rewritePacket(packet, { srcIp: A.wifi, srcPort: 9999 })
  assert.deepEqual(bytes, before)
})

test('MSS clamping never raises a value the peer asked for', () => {
  const bytes = buildTcpPacket({
    srcIp: A.client,
    dstIp: A.server,
    srcPort: 1,
    dstPort: 2,
    flags: TCP_FLAG.SYN,
    mss: 1200
  })
  assert.ok(bytes)
  const packet = parseIpv4(bytes)
  assert.ok(packet)
  const rewritten = rewritePacket(packet, { clampMssTo: 1460 })
  assert.ok(rewritten.ok)
  const out = parseIpv4(rewritten.packet)
  assert.ok(out)
  assert.equal(tcpMssOption(out), 1200)
})

test('a UDP packet with no checksum keeps no checksum', () => {
  const bytes = buildUdpPacket({
    srcIp: A.client,
    dstIp: A.server,
    srcPort: 5000,
    dstPort: 3074,
    payload: Buffer.from('game state')
  })
  assert.ok(bytes)
  // Zero the checksum field, as a sender that does not compute it does.
  bytes.writeUInt16BE(0, IPV4_HEADER + 6)
  bytes.writeUInt16BE(0, 10)
  bytes.writeUInt16BE(internetChecksum(bytes, 0, IPV4_HEADER), 10)
  const packet = parseIpv4(bytes)
  assert.ok(packet)
  const rewritten = rewritePacket(packet, { srcIp: A.wifi, srcPort: 1234 })
  assert.ok(rewritten.ok)
  assert.equal(rewritten.packet.readUInt16BE(IPV4_HEADER + 6), 0)
  const out = parseIpv4(rewritten.packet)
  assert.ok(out)
  assert.equal(verifyChecksums(out), true)
})

const IPV4_HEADER = 20

test('a TTL of 1 is refused rather than forwarded as 0', () => {
  const bytes = buildTcpPacket({
    srcIp: A.client,
    dstIp: A.server,
    srcPort: 1,
    dstPort: 2,
    flags: TCP_FLAG.SYN,
    ttl: 1
  })
  assert.ok(bytes)
  const packet = parseIpv4(bytes)
  assert.ok(packet)
  const rewritten = rewritePacket(packet, { srcIp: A.wifi, decrementTtl: true })
  assert.equal(rewritten.ok, false)
  if (!rewritten.ok) assert.equal(rewritten.reason, 'ttl-expired')
})

test('ICMP echo identifiers are translatable, so two consoles can share a ping target', () => {
  const echo = Buffer.alloc(IPV4_HEADER + 8 + 4)
  echo.writeUInt8(0x45, 0)
  echo.writeUInt16BE(echo.length, 2)
  echo.writeUInt8(64, 8)
  echo.writeUInt8(IPPROTO.ICMP, 9)
  echo.set([192, 168, 77, 10], 12)
  echo.set([8, 8, 8, 8], 16)
  echo.writeUInt8(8, IPV4_HEADER) // echo request
  echo.writeUInt16BE(0x1234, IPV4_HEADER + 4) // identifier
  echo.writeUInt16BE(1, IPV4_HEADER + 6)
  echo.writeUInt16BE(
    internetChecksum(echo, IPV4_HEADER, echo.length - IPV4_HEADER),
    IPV4_HEADER + 2
  )
  echo.writeUInt16BE(0, 10)
  echo.writeUInt16BE(internetChecksum(echo, 0, IPV4_HEADER), 10)

  const packet = parseIpv4(echo)
  assert.ok(packet)
  const rewritten = rewritePacket(packet, { srcIp: A.wifi, srcPort: 0x7788 })
  assert.ok(rewritten.ok)
  const out = parseIpv4(rewritten.packet)
  assert.ok(out)
  assert.equal(out.buffer.readUInt16BE(IPV4_HEADER + 4), 0x7788)
  assert.equal(verifyChecksums(out), true, 'the ICMP checksum must follow the identifier')
})

test('fragmentation splits to the MTU and keeps the payload whole', () => {
  const payload = Buffer.alloc(3000, 0xab)
  const bytes = buildUdpPacket({
    srcIp: A.client,
    dstIp: A.server,
    srcPort: 5000,
    dstPort: 3074,
    payload,
    dontFragment: false
  })
  assert.ok(bytes)
  const packet = parseIpv4(bytes)
  assert.ok(packet)
  const pieces = fragmentIpv4(packet, 1200)
  assert.ok(pieces)
  assert.equal(pieces.length, 3)
  let assembled = Buffer.alloc(0)
  for (const [index, piece] of pieces.entries()) {
    const parsed = parseIpv4(piece)
    assert.ok(parsed, `fragment ${index} must be a valid datagram`)
    assert.ok(parsed.totalLength <= 1200)
    assert.equal(parsed.identification, packet.identification)
    assert.equal(parsed.fragmentOffset, index * 1176, 'offsets are 8-byte aligned')
    assert.equal(parsed.moreFragments, index < pieces.length - 1)
    if (index > 0) assert.equal(parsed.dontFragment, false, 'later fragments carry a real offset')
    assembled = Buffer.concat([assembled, piece.subarray(parsed.payloadOffset)])
  }
  // The IP payload includes the UDP header, so that is what must be identical.
  assert.deepEqual(
    assembled,
    packet.buffer.subarray(packet.payloadOffset, packet.totalLength),
    'the fragments reassemble to the original datagram payload'
  )
})

test('a DF packet that does not fit cannot be fragmented, and is answered with ICMP', () => {
  const bytes = buildUdpPacket({
    srcIp: A.wifi,
    dstIp: A.server,
    srcPort: 9,
    dstPort: 9,
    payload: Buffer.alloc(2000)
  })
  assert.ok(bytes)
  const packet = parseIpv4(bytes)
  assert.ok(packet)
  assert.equal(fragmentIpv4(packet, 1400), null)

  const answer = buildIcmpFragmentationNeeded(packet, 1400)
  assert.ok(answer)
  const parsed = parseIpv4(answer)
  assert.ok(parsed)
  const icmp = parseIcmp(parsed)
  assert.equal(icmp?.type, 3)
  assert.equal(icmp?.code, 4)
  assert.equal(icmp.rest & 0xffff, 1400, 'the next-hop MTU is in the header field')
  assert.equal(verifyChecksums(parsed), true)
  // The answer quotes the original header, so the sender can tell which packet to shrink.
  const quoted = parseIpv4(Buffer.from(answer.subarray(parsed.payloadOffset + 8)), {
    allowTruncated: true
  })
  assert.ok(quoted)
  assert.equal(quoted.dstIp, A.server)
})

test('a TCP reset is addressed from the server to the client and accepted as valid', () => {
  const bytes = buildTcpPacket({
    srcIp: A.client,
    dstIp: A.server,
    srcPort: 40000,
    dstPort: 443,
    flags: TCP_FLAG.SYN,
    seq: 9000,
    mss: 1460
  })
  assert.ok(bytes)
  const packet = parseIpv4(bytes)
  assert.ok(packet)
  const tcp = parseTcp(packet)
  assert.ok(tcp)
  const reset = buildTcpReset(packet, tcp)
  assert.ok(reset)
  const parsed = parseIpv4(reset)
  assert.ok(parsed)
  assert.equal(parsed.srcIp, A.server)
  assert.equal(parsed.dstIp, A.client)
  const resetTcp = parseTcp(parsed)
  assert.equal(resetTcp?.srcPort, 443)
  assert.equal(resetTcp?.dstPort, 40000)
  assert.ok((resetTcp?.flags ?? 0) & TCP_FLAG.RST)
  assert.equal(resetTcp?.ack, 9001, 'a SYN consumes one sequence number')
  assert.equal(verifyChecksums(parsed), true)
})

test('subnet checks and address maths', () => {
  assert.equal(inSubnet('192.168.77.10', '192.168.77.0/24'), true)
  assert.equal(inSubnet('192.168.78.10', '192.168.77.0/24'), false)
  assert.equal(inSubnet('192.168.77.10', null), true)
  assert.equal(ipv4ToNumber('255.255.255.255'), 4294967295)
  assert.equal(ipv4ToNumber('192.168.77.1'), 3232255233)
  assert.equal(mssForMtu(1500), 1460)
  assert.equal(mssForMtu(1492), 1452)
  assert.equal(mssForMtu(536), 536, 'the RFC floor')
})

test('a truncated or lying length is rejected, never half-parsed', () => {
  const bytes = buildUdpPacket({
    srcIp: A.client,
    dstIp: A.server,
    srcPort: 1,
    dstPort: 2,
    payload: Buffer.from('x')
  })
  assert.ok(bytes)
  assert.equal(parseIpv4(bytes.subarray(0, 12)), null, 'shorter than a header')
  const lying = Buffer.from(bytes)
  lying.writeUInt16BE(600, 2) // more than arrived
  assert.equal(parseIpv4(lying), null)
  const corrupt = Buffer.from(bytes)
  corrupt[12] = 10 // changes the source address without fixing the header checksum
  assert.equal(parseIpv4(corrupt), null, 'a bad header checksum is not forwarded')
  // A UDP header whose length disagrees with the datagram is not a UDP header we will parse.
  const udp = buildUdpPacket({
    srcIp: A.client,
    dstIp: A.server,
    srcPort: 1,
    dstPort: 2,
    payload: Buffer.alloc(4)
  })
  assert.ok(udp)
  udp.writeUInt16BE(200, IPV4_HEADER + 4)
  udp.writeUInt16BE(0, IPV4_HEADER + 6)
  udp.writeUInt16BE(0, 10)
  udp.writeUInt16BE(internetChecksum(udp, 0, IPV4_HEADER), 10)
  const parsed = parseIpv4(udp)
  assert.ok(parsed)
  assert.equal(parseUdp(parsed), null)
})
