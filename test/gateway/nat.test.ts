import assert from 'node:assert/strict'
import { test } from 'node:test'
import { NatTable, DEFAULT_NAT_TIMEOUTS } from '../../src/main/gateway/nat.ts'

const T0 = 1_700_000_000_000

function table(overrides = {}): NatTable {
  return new NatTable({ portSeed: () => 20000, ...overrides })
}

test('a mapping is reachable both ways: by the console socket, and by its public port', () => {
  const nat = table()
  const mapping = nat.create({
    proto: 6,
    clientIp: '192.168.77.10',
    clientPort: 40000,
    linkId: 'Wi-Fi',
    publicIp: '192.168.1.42',
    now: T0
  })
  assert.ok(mapping)
  assert.equal(nat.lookup(6, '192.168.77.10', 40000), mapping)
  assert.equal(nat.lookupPublic('Wi-Fi', 6, mapping.publicPort), mapping)
  assert.equal(
    nat.lookupPublic('Ethernet 3', 6, mapping.publicPort),
    undefined,
    'ports are per uplink'
  )
  assert.ok(mapping.publicPort >= 1024, 'never a privileged port')
})

test('one mapping per console socket: a second destination reuses it (endpoint-independent)', () => {
  const nat = table()
  const first = nat.create({
    proto: 17,
    clientIp: '192.168.77.10',
    clientPort: 3074,
    linkId: 'Wi-Fi',
    publicIp: '192.168.1.42',
    now: T0
  })
  assert.ok(first)
  const second = nat.create({
    proto: 17,
    clientIp: '192.168.77.10',
    clientPort: 3074,
    linkId: 'Wi-Fi',
    publicIp: '192.168.1.42',
    now: T0 + 10
  })
  assert.equal(second, first, 'the same socket keeps the same public port, whatever it talks to')
  assert.equal(nat.size, 1)
})

test('two sockets never share a public port on the same uplink and protocol', () => {
  const nat = table()
  const ports = new Set<number>()
  for (let clientPort = 1000; clientPort < 1400; clientPort++) {
    const mapping = nat.create({
      proto: 6,
      clientIp: '192.168.77.10',
      clientPort,
      linkId: 'Wi-Fi',
      publicIp: '192.168.1.42',
      now: T0
    })
    assert.ok(mapping)
    assert.equal(
      ports.has(mapping.publicPort),
      false,
      'a duplicate public port would deliver the wrong flow'
    )
    ports.add(mapping.publicPort)
  }
  // A different uplink may reuse the same numbers: return traffic is disambiguated by uplink.
  const onUsb = nat.create({
    proto: 6,
    clientIp: '192.168.77.10',
    clientPort: 1000,
    linkId: 'Ethernet 3',
    publicIp: '192.168.42.7',
    now: T0
  })
  assert.ok(onUsb)
  assert.equal(nat.lookupPublic('Ethernet 3', 6, onUsb.publicPort), onUsb)
})

test('moving a mapping keeps its public port when the new uplink has it free', () => {
  const nat = table()
  const mapping = nat.create({
    proto: 17,
    clientIp: '192.168.77.10',
    clientPort: 3074,
    linkId: 'Wi-Fi',
    publicIp: '192.168.1.42',
    now: T0
  })
  assert.ok(mapping)
  const originalPort = mapping.publicPort
  assert.equal(nat.move(mapping, 'Ethernet 3', '192.168.42.7', T0 + 1000), true)
  assert.equal(mapping.linkId, 'Ethernet 3')
  assert.equal(
    mapping.publicPort,
    originalPort,
    'the port survives the move, so peers may still find it'
  )
  assert.equal(
    nat.lookupPublic('Wi-Fi', 17, originalPort),
    undefined,
    'the old uplink no longer answers for it'
  )
  assert.equal(nat.lookupPublic('Ethernet 3', 17, originalPort), mapping)
})

test('moving a mapping whose port is taken gets a new one rather than clobbering it', () => {
  const nat = table({ portSeed: () => 20000 })
  const squatter = nat.create({
    proto: 17,
    clientIp: '192.168.77.11',
    clientPort: 5000,
    linkId: 'Ethernet 3',
    publicIp: '192.168.42.7',
    now: T0
  })
  assert.ok(squatter)
  const mapping = nat.create({
    proto: 17,
    clientIp: '192.168.77.10',
    clientPort: 3074,
    linkId: 'Wi-Fi',
    publicIp: '192.168.1.42',
    now: T0
  })
  assert.ok(mapping)
  // Force the collision: pretend the moving mapping already owns the squatter's port.
  mapping.publicPort = squatter.publicPort
  nat.move(mapping, 'Ethernet 3', '192.168.42.7', T0 + 1)
  assert.notEqual(mapping.publicPort, squatter.publicPort)
  assert.equal(nat.lookupPublic('Ethernet 3', 17, squatter.publicPort), squatter)
})

test('timeouts follow the protocol and whether anything answered', () => {
  const nat = table()
  const tcpUnanswered = nat.create({
    proto: 6,
    clientIp: '192.168.77.10',
    clientPort: 40001,
    linkId: 'Wi-Fi',
    publicIp: '192.168.1.42',
    now: T0
  })
  const tcpAnswered = nat.create({
    proto: 6,
    clientIp: '192.168.77.10',
    clientPort: 40002,
    linkId: 'Wi-Fi',
    publicIp: '192.168.1.42',
    now: T0
  })
  const udpUnanswered = nat.create({
    proto: 17,
    clientIp: '192.168.77.10',
    clientPort: 40003,
    linkId: 'Wi-Fi',
    publicIp: '192.168.1.42',
    now: T0
  })
  const udpAnswered = nat.create({
    proto: 17,
    clientIp: '192.168.77.10',
    clientPort: 40004,
    linkId: 'Wi-Fi',
    publicIp: '192.168.1.42',
    now: T0
  })
  const icmp = nat.create({
    proto: 1,
    clientIp: '192.168.77.10',
    clientPort: 40005,
    linkId: 'Wi-Fi',
    publicIp: '192.168.1.42',
    now: T0
  })
  assert.ok(tcpUnanswered && tcpAnswered && udpUnanswered && udpAnswered && icmp)
  nat.observeInbound(tcpAnswered, { dstIp: '1.1.1.1', dstPort: 443 }, 100, T0)
  nat.observeInbound(udpAnswered, { dstIp: '1.1.1.1', dstPort: 3074 }, 100, T0)

  // Just past the shortest timeout (30 s for a UDP flow nothing answered and for ICMP): those go,
  // everything that has had an answer stays.
  const expiredAt30s = nat.expire(T0 + DEFAULT_NAT_TIMEOUTS.udpUnrepliedMs + 1)
  assert.deepEqual(new Set(expiredAt30s), new Set([udpUnanswered, icmp]))
  assert.ok(nat.lookup(17, '192.168.77.10', 40004), 'an answered UDP flow lives longer')

  // Two minutes: the unanswered TCP flow and ICMP go; the answered ones stay.
  const expiredAt2m = nat.expire(T0 + DEFAULT_NAT_TIMEOUTS.tcpOpeningMs + 1)
  assert.deepEqual(expiredAt2m, [tcpUnanswered])
  assert.ok(
    nat.lookup(6, '192.168.77.10', 40002),
    'an established TCP connection survives minutes of silence'
  )
  assert.ok(nat.lookup(17, '192.168.77.10', 40004))
})

test('the table is bounded: a flood of flows evicts the coldest, not the hottest', () => {
  const nat = table({ maxMappings: 4 })
  const made = []
  for (let index = 0; index < 4; index++) {
    const mapping = nat.create({
      proto: 17,
      clientIp: '192.168.77.10',
      clientPort: 30000 + index,
      linkId: 'Wi-Fi',
      publicIp: '192.168.1.42',
      now: T0 + index * 1000
    })
    assert.ok(mapping)
    made.push(mapping)
  }
  // Keep the first one warm, then add one more.
  nat.observeOutbound(made[0], { dstIp: '8.8.8.8', dstPort: 53 }, 10, T0 + 3500)
  const overflow = nat.create({
    proto: 17,
    clientIp: '192.168.77.10',
    clientPort: 30099,
    linkId: 'Wi-Fi',
    publicIp: '192.168.1.42',
    now: T0 + 4000
  })
  assert.ok(overflow)
  assert.equal(nat.size, 4)
  assert.ok(nat.lookup(17, '192.168.77.10', 30000), 'the busiest mapping was kept')
  assert.equal(nat.lookup(17, '192.168.77.10', 30001), undefined, 'the coldest went')
  assert.equal(nat.evicted, 1)
})

test('byte accounting adds up per mapping and in total', () => {
  const nat = table()
  const tcp = nat.create({
    proto: 6,
    clientIp: '192.168.77.10',
    clientPort: 40000,
    linkId: 'Wi-Fi',
    publicIp: '192.168.1.42',
    now: T0
  })
  assert.ok(tcp)
  nat.observeOutbound(tcp, { dstIp: '93.184.216.34', dstPort: 443 }, 1000, T0)
  nat.observeInbound(tcp, { dstIp: '93.184.216.34', dstPort: 443 }, 50_000, T0 + 1)
  nat.observeOutbound(tcp, { dstIp: '93.184.216.34', dstPort: 443 }, 200, T0 + 2)
  const stats = nat.stats()
  assert.equal(stats.tcp, 1)
  assert.equal(stats.bytesOut, 1200)
  assert.equal(stats.bytesIn, 50_000)
  assert.equal(stats.mappings, 1)
})

test('an uplink whose ports are exhausted is reported, not silently reused', () => {
  const nat = new NatTable({ portSeed: () => 65535 })
  // Two flows only: with a 2-port window there is nothing left for the third.
  const original = (nat as unknown as { cursors: Map<string, number> }).cursors
  const first = nat.create({
    proto: 6,
    clientIp: '192.168.77.10',
    clientPort: 1,
    linkId: 'Wi-Fi',
    publicIp: '192.168.1.42',
    now: T0
  })
  assert.ok(first)
  // Simulate exhaustion by filling every port except one: cheaper than 64k creations.
  const state = nat as unknown as { byPublic: Map<string, string> }
  for (let port = 1024; port <= 65535; port++) {
    if (port === first.publicPort) continue
    state.byPublic.set(`Wi-Fi|6|${port}`, 'placeholder')
  }
  original.clear()
  const exhausted = nat.create({
    proto: 6,
    clientIp: '192.168.77.10',
    clientPort: 2,
    linkId: 'Wi-Fi',
    publicIp: '192.168.1.42',
    now: T0
  })
  assert.equal(exhausted, null, 'no port means no mapping, which the caller must handle')
})
