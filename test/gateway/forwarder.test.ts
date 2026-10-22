import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  buildIcmpFragmentationNeeded,
  buildUdpPacket,
  fragmentIpv4,
  internetChecksum,
  parseIcmp,
  parseIpv4,
  parseTcp,
  parseUdp,
  portsOf,
  tcpMssOption,
  verifyChecksums,
  TCP_FLAG,
  IPPROTO
} from '../../src/main/gateway/packet.ts'
import {
  CONSOLE_IP,
  GATEWAY_LAN_IP,
  LAN_IFIDX,
  USB,
  WIFI,
  World,
  consoleTcp,
  consoleUdp,
  replyTo
} from './harness.ts'

const SERVER = '93.184.216.34'

function onlyWifi(world: World): World {
  world.setWeights({ 'Wi-Fi': 1, 'Ethernet 3': 0 })
  return world
}

test('a console connection is NAT’d out the chosen uplink and comes back to the console', () => {
  const world = onlyWifi(new World())
  const result = world.outbound(
    consoleTcp({ srcPort: 40000, dstIp: SERVER, dstPort: 443, flags: TCP_FLAG.SYN, seq: 1000 })
  )
  assert.equal(result.transmit.length, 1)
  assert.equal(result.linkId, 'Wi-Fi')
  const sent = world.lastSent()
  assert.equal(sent.srcIp, WIFI.address, 'the source is the uplink address')
  assert.equal(sent.dstIp, SERVER, 'the destination is untouched')
  assert.equal(sent.ttl, 63, 'a forwarded packet loses a hop')
  assert.equal(verifyChecksums(sent), true)
  const translatedPort = parseTcp(sent)?.srcPort ?? 0
  assert.notEqual(translatedPort, 40000, 'the console’s port is translated')

  // The server answers the public address it saw.
  const delivered = world.inbound(replyTo(sent), 'Wi-Fi')
  assert.equal(delivered.transmit.length, 1)
  assert.equal(delivered.delivered, true)
  const back = world.deliveredToConsole[world.deliveredToConsole.length - 1]
  const packet = parseIpv4(back.packet)
  assert.ok(packet)
  assert.equal(packet.dstIp, CONSOLE_IP, 'the reply is addressed to the console')
  assert.equal(parseTcp(packet)?.dstPort, 40000, 'and to the socket that opened it')
  assert.equal(verifyChecksums(packet), true)
  assert.equal(world.forwarder.totals.bytesUp > 0, true)
  assert.equal(world.forwarder.totals.bytesDown > 0, true)
})

test('return traffic on an uplink the mapping does not belong to is dropped, not guessed', () => {
  const world = onlyWifi(new World())
  world.outbound(consoleTcp({ srcPort: 40000, dstIp: SERVER, dstPort: 443, flags: TCP_FLAG.SYN }))
  const sent = world.lastSent()
  const reply = replyTo(sent)
  const wrongLink = world.inbound(reply, 'Ethernet 3')
  assert.equal(wrongLink.transmit.length, 0)
  const rightLink = world.inbound(reply, 'Wi-Fi')
  assert.equal(rightLink.transmit.length, 1)
})

test('a packet from outside the downstream subnet is not relayed', () => {
  const world = onlyWifi(new World())
  const bytes = consoleTcp({ srcPort: 40000, dstIp: SERVER, dstPort: 443, flags: TCP_FLAG.SYN })
  // Pretend a stranger's packet appeared on the console's port.
  bytes.set([203, 0, 113, 9], 12)
  bytes.writeUInt16BE(0, 10)
  bytes.writeUInt16BE(internetChecksum(bytes, 0, 20), 10)
  const result = world.outbound(bytes)
  assert.equal(result.transmit.length, 0)
  assert.equal(result.dropped, 'not-downstream')
})

test('the console’s own DHCP/DNS traffic to the gateway is left to the gateway', () => {
  const world = onlyWifi(new World())
  const result = world.outbound(
    consoleUdp({ srcPort: 68, dstIp: GATEWAY_LAN_IP, dstPort: 67, payload: Buffer.alloc(40) })
  )
  assert.equal(result.transmit.length, 0)
  assert.equal(world.nat.size, 0, 'the gateway does not NAT itself')
})

test('one console socket keeps one public port across destinations (PSN’s NAT type 2)', () => {
  const world = onlyWifi(new World())
  world.outbound(consoleUdp({ srcPort: 3074, dstIp: '1.1.1.1', dstPort: 3074 }))
  const first = world.lastSent()
  const publicPort = parseUdp(first)?.srcPort
  world.outbound(consoleUdp({ srcPort: 3074, dstIp: '8.8.8.8', dstPort: 53 }))
  const second = world.lastSent()
  assert.equal(parseUdp(second)?.srcPort, publicPort)
  assert.equal(world.nat.size, 1)
  // Return traffic from a host the console has never talked to still reaches it, as with any
  // full-cone mapping a game's matchmaking depends on.
  const stranger = buildUdpPacket({
    srcIp: '9.9.9.9',
    dstIp: WIFI.address,
    srcPort: 50000,
    dstPort: publicPort ?? 0,
    payload: Buffer.from('from a peer the console never met')
  })
  assert.ok(stranger)
  const delivered = world.inbound(stranger, 'Wi-Fi')
  assert.equal(
    delivered.transmit.length,
    1,
    'full-cone mapping: an unknown peer can reach the console'
  )
  const back = parseIpv4(world.deliveredToConsole[world.deliveredToConsole.length - 1].packet)
  assert.equal(back?.dstIp, CONSOLE_IP)
  assert.equal(parseUdp(back!)?.dstPort, 3074, 'and to the socket the peer was told about')
})

test('a UDP association survives its uplink dying, keeping its public port when it can', () => {
  const world = onlyWifi(new World())
  world.outbound(consoleUdp({ srcPort: 3074, dstIp: SERVER, dstPort: 3074 }))
  const first = world.lastSent()
  const publicPort = parseUdp(first)?.srcPort
  assert.equal(first.srcIp, WIFI.address)

  world.kill('Wi-Fi')
  const result = world.outbound(consoleUdp({ srcPort: 3074, dstIp: SERVER, dstPort: 3074 }))
  assert.equal(result.transmit.length, 1, 'the datagram still leaves')
  assert.equal(result.linkId, 'Ethernet 3', 'through the surviving uplink')
  const moved = world.lastSent()
  assert.equal(moved.srcIp, USB.address)
  assert.equal(parseUdp(moved)?.srcPort, publicPort, 'the port is preserved where possible')
  assert.equal(world.forwarder.totals.repins, 1)

  // And the game server's next packet, sent to the new address, still arrives.
  const delivered = world.inbound(replyTo(moved), 'Ethernet 3')
  assert.equal(delivered.transmit.length, 1)
})

test('a TCP connection whose uplink dies is reset so it reconnects at once', () => {
  const world = onlyWifi(new World())
  world.outbound(consoleTcp({ srcPort: 40000, dstIp: SERVER, dstPort: 443, flags: TCP_FLAG.SYN }))
  const sent = world.lastSent()
  world.inbound(replyTo(sent), 'Wi-Fi') // the connection is up

  world.kill('Wi-Fi')
  const result = world.outbound(
    consoleTcp({
      srcPort: 40000,
      dstIp: SERVER,
      dstPort: 443,
      flags: TCP_FLAG.ACK,
      seq: 1500,
      ack: 6000
    })
  )
  assert.equal(result.dropped, 'no-uplink')
  assert.equal(result.transmit.length, 1, 'a reset goes to the console instead of silence')
  assert.equal(result.transmit[0].ifIdx, LAN_IFIDX, 'it is delivered on the LAN port')
  const reset = parseIpv4(result.transmit[0].packet)
  assert.ok(reset)
  assert.equal(reset.dstIp, CONSOLE_IP)
  assert.equal(parseTcp(reset)?.dstPort, 40000)
  assert.ok((parseTcp(reset)?.flags ?? 0) & TCP_FLAG.RST)
  assert.equal(verifyChecksums(reset), true)
  assert.equal(world.forwarder.totals.resets, 1)
  assert.equal(world.nat.size, 0, 'the dead mapping is gone, so the retry gets a working one')

  // The console reconnects, on the surviving uplink.
  world.revive('Wi-Fi')
  world.kill('Wi-Fi')
  const reconnect = world.outbound(
    consoleTcp({ srcPort: 40001, dstIp: SERVER, dstPort: 443, flags: TCP_FLAG.SYN, seq: 1 })
  )
  assert.equal(reconnect.linkId, 'Ethernet 3')
})

test('with tcpFailover “hold” the mapping waits for the uplink to come back', () => {
  const world = onlyWifi(new World())
  world.tcpFailover = 'hold'
  const forwarder = new World()
  forwarder.tcpFailover = 'hold'
  const held = forwarder
  held.setWeights({ 'Wi-Fi': 1, 'Ethernet 3': 0 })
  held.outbound(consoleTcp({ srcPort: 40000, dstIp: SERVER, dstPort: 443, flags: TCP_FLAG.SYN }))
  held.kill('Wi-Fi')
  const result = held.outbound(
    consoleTcp({ srcPort: 40000, dstIp: SERVER, dstPort: 443, flags: TCP_FLAG.ACK })
  )
  assert.equal(result.transmit.length, 0, 'nothing is sent, and nothing is reset')
  assert.equal(result.dropped, 'no-uplink')
  assert.equal(held.nat.size, 1, 'the mapping is kept for when the uplink returns')
  assert.equal(held.forwarder.totals.resets, 0)
  void world
})

test('no working uplink at all drops the packet and says so', () => {
  const world = onlyWifi(new World())
  world.kill('Wi-Fi')
  world.kill('Ethernet 3')
  const result = world.outbound(consoleUdp({ srcPort: 3074, dstIp: SERVER, dstPort: 3074 }))
  assert.equal(result.transmit.length, 0)
  assert.equal(result.dropped, 'no-uplink')
  assert.equal(world.forwarder.totals.dropped, 1)
})

test('the MSS the console advertises is clamped to the uplink’s MTU', () => {
  const world = onlyWifi(new World())
  world.uplink('Wi-Fi').mtu = 1400
  world.outbound(
    consoleTcp({ srcPort: 40000, dstIp: SERVER, dstPort: 443, flags: TCP_FLAG.SYN, mss: 1460 })
  )
  const sent = world.lastSent()
  assert.equal(tcpMssOption(sent), 1360, '1400 minus the IPv4 and TCP headers')
  assert.equal(verifyChecksums(sent), true)
})

test('a datagram too big for the uplink is fragmented, not dropped', () => {
  const world = onlyWifi(new World())
  world.uplink('Wi-Fi').mtu = 1200
  const payload = Buffer.alloc(2000, 0x5a)
  const result = world.outbound(
    consoleUdp({ srcPort: 5000, dstIp: SERVER, dstPort: 3074, payload, dontFragment: false })
  )
  assert.ok(result.transmit.length >= 2, 'it is split into pieces the uplink can carry')
  let bytes = Buffer.alloc(0)
  for (const entry of result.transmit) {
    const piece = parseIpv4(entry.packet)
    assert.ok(piece)
    assert.ok(piece.totalLength <= 1200)
    assert.equal(piece.srcIp, WIFI.address)
    assert.equal(piece.fragmentOffset === 0, bytes.length === 0)
    bytes = Buffer.concat([bytes, entry.packet.subarray(piece.payloadOffset)])
  }
  assert.equal(world.forwarder.totals.fragments > 0, true)
})

test('a DF datagram too big for the uplink earns an ICMP “fragmentation needed”', () => {
  const world = onlyWifi(new World())
  world.uplink('Wi-Fi').mtu = 1200
  const result = world.outbound(
    consoleUdp({ srcPort: 5000, dstIp: SERVER, dstPort: 3074, payload: Buffer.alloc(2000) })
  )
  assert.equal(result.dropped, 'fragment-needed')
  assert.equal(result.transmit.length, 1)
  const answer = parseIpv4(result.transmit[0].packet)
  assert.ok(answer)
  assert.equal(answer.dstIp, CONSOLE_IP, 'the answer goes back to the console')
  const icmp = parseIcmp(answer)
  assert.equal(icmp?.type, 3)
  assert.equal(icmp?.code, 4)
  assert.equal(icmp.rest & 0xffff, 1200, 'and tells it the MTU to use')
  assert.equal(verifyChecksums(answer), true)
  assert.equal(world.forwarder.totals.pmtuAnswers, 1)
})

test('an uplink’s “packet too big” is learned as the path MTU, and its quote is translated', () => {
  const world = onlyWifi(new World())
  world.outbound(
    consoleTcp({ srcPort: 40000, dstIp: SERVER, dstPort: 443, flags: TCP_FLAG.SYN, mss: 1460 })
  )
  const sent = world.lastSent()
  // The uplink's own router answers "too big, use 1280" — quoting the packet we sent.
  const icmpError = buildIcmpFragmentationNeeded(sent, 1280)
  assert.ok(icmpError)
  const delivered = world.inbound(icmpError, 'Wi-Fi')
  assert.equal(delivered.transmit.length, 1, 'the error is passed to the console')

  const translated = parseIpv4(world.deliveredToConsole[world.deliveredToConsole.length - 1].packet)
  assert.ok(translated)
  assert.equal(translated.dstIp, CONSOLE_IP, 'the outer header is translated')
  assert.equal(verifyChecksums(translated), true, 'the ICMP checksum follows the edit')
  // The quoted datagram must show the console's own address, or its stack cannot match it.
  const quoted = parseIpv4(Buffer.from(translated.buffer.subarray(translated.payloadOffset + 8)), {
    allowTruncated: true
  })
  assert.ok(quoted)
  assert.equal(quoted.srcIp, CONSOLE_IP, 'the quote is translated back to the console')
  assert.equal(portsOf(quoted)?.srcPort, 40000, 'and the port in it, too')

  assert.equal(world.forwarder.effectiveMtu(world.uplink('Wi-Fi')), 1280)
  // A later handshake uses the smaller MSS.
  world.outbound(
    consoleTcp({ srcPort: 40002, dstIp: SERVER, dstPort: 443, flags: TCP_FLAG.SYN, mss: 1460 })
  )
  assert.equal(tcpMssOption(world.lastSent()), 1240)
})

test('ICMP echo identifiers are translated both ways', () => {
  const world = onlyWifi(new World())
  const echo = Buffer.alloc(28)
  echo.writeUInt8(0x45, 0)
  echo.writeUInt16BE(28, 2)
  echo.writeUInt8(64, 8)
  echo.writeUInt8(IPPROTO.ICMP, 9)
  echo.set([192, 168, 77, 10], 12)
  echo.set([8, 8, 8, 8], 16)
  echo.writeUInt8(8, 20)
  echo.writeUInt16BE(0x1234, 24)
  echo.writeUInt16BE(1, 26)
  echo.writeUInt16BE(internetChecksum(echo, 20, 8), 22)
  echo.writeUInt16BE(0, 10)
  echo.writeUInt16BE(internetChecksum(echo, 0, 20), 10)

  world.outbound(echo)
  const sent = world.lastSent()
  const translatedId = sent.buffer.readUInt16BE(24)
  assert.notEqual(translatedId, 0x1234)
  assert.equal(verifyChecksums(sent), true)

  // The echo reply, addressed to the public address, carrying the translated identifier.
  const reply = Buffer.from(echo)
  reply.set([192, 168, 1, 42], 12)
  reply.set([8, 8, 8, 8], 16)
  reply.writeUInt8(0, 20)
  reply.writeUInt16BE(translatedId, 24)
  reply.writeUInt16BE(0, 22)
  reply.writeUInt16BE(internetChecksum(reply, 20, 8), 22)
  reply.writeUInt16BE(0, 10)
  reply.writeUInt16BE(internetChecksum(reply, 0, 20), 10)

  const delivered = world.inbound(reply, 'Wi-Fi')
  assert.equal(delivered.transmit.length, 1)
  const back = parseIpv4(world.deliveredToConsole[world.deliveredToConsole.length - 1].packet)
  assert.ok(back)
  assert.equal(back.dstIp, CONSOLE_IP)
  assert.equal(back.buffer.readUInt16BE(24), 0x1234, 'the console’s own identifier is restored')
})

test('a later fragment follows its first fragment’s uplink', () => {
  const world = onlyWifi(new World())
  world.uplink('Wi-Fi').mtu = 1200
  const big = consoleUdp({
    srcPort: 5000,
    dstIp: SERVER,
    dstPort: 3074,
    payload: Buffer.alloc(2000),
    dontFragment: false
  })
  const parsed = parseIpv4(big)
  assert.ok(parsed)
  // Feed a datagram that is already fragmented, as it would arrive from the console's own stack.
  const pieces = fragmentIpv4(parsed, 1000)
  assert.ok(pieces && pieces.length > 1)
  const first = world.outbound(pieces[0])
  assert.equal(first.linkId, 'Wi-Fi')
  for (const piece of pieces.slice(1)) {
    const result = world.outbound(piece)
    assert.equal(result.linkId, 'Wi-Fi', 'no ports in a later fragment: it must follow the first')
    assert.equal(result.transmit.length, 1)
  }
})

test('an orphan fragment is dropped rather than sent untranslated', () => {
  const world = onlyWifi(new World())
  const big = consoleUdp({
    srcPort: 5000,
    dstIp: SERVER,
    dstPort: 3074,
    payload: Buffer.alloc(2000),
    dontFragment: false
  })
  const parsed = parseIpv4(big)
  assert.ok(parsed)
  const pieces = fragmentIpv4(parsed, 1000)
  assert.ok(pieces && pieces.length > 1)
  const result = world.outbound(pieces[1]) // the tail without its head
  assert.equal(result.transmit.length, 0)
  assert.equal(result.dropped, 'fragment-orphan')
})

test('mappings expire, and an expired one stops attracting a stranger’s traffic', () => {
  const world = onlyWifi(new World())
  world.outbound(consoleUdp({ srcPort: 3074, dstIp: SERVER, dstPort: 3074 }))
  const sent = world.lastSent()
  assert.equal(world.nat.size, 1)
  world.advance(31_000)
  world.nat.expire(world.now)
  assert.equal(world.nat.size, 0, 'a UDP mapping nothing answered expires in 30 seconds')
  assert.equal(world.inbound(replyTo(sent), 'Wi-Fi').transmit.length, 0)
})

test('traffic is counted per uplink and per direction', () => {
  const world = new World()
  world.setWeights({ 'Wi-Fi': 1, 'Ethernet 3': 1 })
  const seen = { 'Wi-Fi': 0, 'Ethernet 3': 0 }
  for (let index = 0; index < 40; index++) {
    const result = world.outbound(
      consoleUdp({ srcPort: 30000 + index, dstIp: SERVER, dstPort: 3074 })
    )
    const link = result.linkId
    assert.ok(link)
    seen[link as 'Wi-Fi' | 'Ethernet 3']++
    world.inbound(replyTo(world.lastSent()), link as string)
  }
  const wifi = world.forwarder.uplinkCounters('Wi-Fi')
  const usb = world.forwarder.uplinkCounters('Ethernet 3')
  assert.equal(wifi.bytesOut > 0 && wifi.bytesIn > 0, true)
  assert.equal(usb.bytesOut > 0 && usb.bytesIn > 0, true)
  assert.equal(wifi.bytesOut + usb.bytesOut, world.forwarder.totals.bytesUp)
  assert.equal(wifi.bytesIn + usb.bytesIn, world.forwarder.totals.bytesDown)
  assert.ok(seen['Wi-Fi'] > 5 && seen['Ethernet 3'] > 5, 'both uplinks carried traffic')
})
