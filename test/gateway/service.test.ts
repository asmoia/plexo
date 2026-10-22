/**
 * The service as the app actually runs it: settings in, packets through the real engine, snapshots
 * out — with the two platform pieces (packet capture and Windows' adapter settings) replaced by
 * fakes. This is the test that proves the wiring, which is where a feature like this really breaks:
 * a handler not attached, a snapshot field never filled, a stop that leaves the host changed.
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { GatewayService } from '../../src/main/gateway/service.ts'
import type {
  CaptureBackend,
  CaptureBackendConfig,
  CaptureBackendHandlers
} from '../../src/main/gateway/backends/capture.ts'
import type { HostInterface } from '../../src/main/gateway/hostInterfaces.ts'
import type { GatewayCapability, GatewayConfig } from '../../src/shared/gateway.ts'
import type { ProbeSample } from '../../src/main/gateway/health.ts'
import {
  parseIpv4,
  parseUdp,
  parseIcmp,
  verifyChecksums,
  buildUdpPacket,
  TCP_FLAG
} from '../../src/main/gateway/packet.ts'
import { consoleTcp, consoleUdp, replyTo } from './harness.ts'

const DOWNSTREAM: HostInterface = {
  id: 'Ethernet 2',
  ifIdx: 3,
  description: 'Realtek PCIe GbE Family Controller',
  mac: 'aa:bb:cc:dd:ee:ff',
  addresses: ['192.168.77.1'],
  mtu: 1500,
  gateway: null,
  linkSpeedBps: 1_000_000_000,
  up: true
}
const WIFI: HostInterface = {
  id: 'Wi-Fi',
  ifIdx: 7,
  description: 'Intel(R) Wi-Fi 6 AX201 160MHz',
  mac: '11:22:33:44:55:01',
  addresses: ['192.168.1.42'],
  mtu: 1500,
  gateway: '192.168.1.1',
  linkSpeedBps: 866_000_000,
  up: true
}
const TETHER: HostInterface = {
  id: 'Ethernet 3',
  ifIdx: 12,
  description: 'Remote NDIS Compatible Device',
  mac: '11:22:33:44:55:02',
  addresses: ['192.168.42.7'],
  mtu: 1400,
  gateway: '192.168.42.1',
  linkSpeedBps: 150_000_000,
  up: true
}

class FakeBackend implements CaptureBackend {
  readonly name = 'fake'
  config: CaptureBackendConfig | null = null
  handlers: CaptureBackendHandlers | null = null
  readonly sent: { packet: Buffer; ifIdx: number }[] = []
  running = false
  error: string | null = null
  selfTestResult = { ok: true, detail: 'ok' }

  async start(config: CaptureBackendConfig, handlers: CaptureBackendHandlers): Promise<void> {
    this.config = config
    this.handlers = handlers
    this.running = true
  }

  async stop(): Promise<void> {
    this.running = false
    this.handlers = null
  }

  send(packets: readonly { packet: Buffer; ifIdx: number }[]): void {
    for (const entry of packets) this.sent.push({ packet: entry.packet, ifIdx: entry.ifIdx })
  }

  status(): {
    running: boolean
    error: string | null
    received: number
    sent: number
    dropped: number
  } {
    return {
      running: this.running,
      error: this.error,
      received: 0,
      sent: this.sent.length,
      dropped: 0
    }
  }

  async selfTest(): Promise<{ ok: boolean; detail: string }> {
    return this.selfTestResult
  }
}

const CAPABLE: GatewayCapability = {
  supported: true,
  platform: 'win32',
  admin: true,
  driverInstalled: true,
  canInstallDriver: false,
  reason: null
}

function config(overrides: Partial<GatewayConfig> = {}): GatewayConfig {
  return {
    enabled: true,
    downstreamId: 'Ethernet 2',
    uplinkIds: ['Wi-Fi', 'Ethernet 3'],
    uplinkWeights: {},
    balancing: 'auto',
    tcpFailover: 'reset',
    dhcp: true,
    dnsRelay: true,
    downstreamAddress: '192.168.77.1',
    downstreamSubnet: '192.168.77.1/24',
    manageHost: true,
    ...overrides
  }
}

interface Rig {
  service: GatewayService
  backend: FakeBackend
  hosts: Map<string, HostInterface>
  hostChanges: { prepared: unknown[]; reverted: number }
  probes: ProbeSample[]
  setNow: (value: number) => void
  advance: (ms: number) => Promise<void>
}

function rig(
  options: {
    capability?: GatewayCapability
    hosts?: Map<string, HostInterface>
    prober?: () => ProbeSample[]
    config?: Partial<GatewayConfig>
  } = {}
): Rig {
  const backend = new FakeBackend()
  const hosts =
    options.hosts ?? new Map([DOWNSTREAM, WIFI, TETHER].map((entry) => [entry.id, entry]))
  const hostChanges = { prepared: [] as unknown[], reverted: 0 }
  let now = 1_700_000_000_000
  const probes = options.prober?.() ?? []
  const service = new GatewayService({
    now: () => now,
    backend,
    host: async () => hosts,
    capability: async () => options.capability ?? CAPABLE,
    prepareHost: async (request) => {
      hostChanges.prepared.push(request)
      return [{ kind: 'ip', interfaceAlias: request.interfaceAlias, address: request.address }]
    },
    revertHost: async () => {
      hostChanges.reverted++
    },
    prober: {
      // One sample per target, in order: the tests give Wi-Fi and the tether deliberately different
      // numbers, and each must land on the right link.
      round: async (targets: { id: string; address: string }[]) => {
        const samples =
          probes.length > 0
            ? probes
            : targets.map(() => ({ ok: true, at: now, rttMs: 20, bytes: 0, durationMs: 20 }))
        return targets.map((_, index) => samples[index % samples.length])
      }
    }
  })
  return {
    service,
    backend,
    hosts,
    hostChanges,
    probes,
    setNow: (value) => {
      now = value
    },
    advance: async (ms) => {
      now += ms
      await service.pump()
    }
  }
}

test('starting needs Windows, an administrator and the driver — and says which is missing', async () => {
  const rigged = rig({
    capability: {
      ...CAPABLE,
      supported: false,
      reason: 'The console gateway needs Windows.'
    }
  })
  await rigged.service.configure(config())
  const snapshot = rigged.service.snapshot()
  assert.equal(snapshot.status, 'error')
  assert.equal(snapshot.error, 'The console gateway needs Windows.')
  assert.equal(rigged.backend.running, false)
  assert.equal(rigged.hostChanges.prepared.length, 0, 'a failed start must not change the machine')
})

test('a normal start prepares the console’s port, opens the capture and reports what it is doing', async () => {
  const rigged = rig()
  await rigged.service.configure(config())
  const snapshot = rigged.service.snapshot()

  assert.equal(snapshot.status, 'running')
  assert.equal(snapshot.intercepting, true)
  assert.equal(rigged.backend.config?.downstreamIfIdx, 3)
  assert.deepEqual(
    rigged.backend.config?.publicPorts,
    { min: 20_000, max: 29_999 },
    'the capture only takes return traffic for the ports the NAT allocates'
  )
  assert.deepEqual(
    rigged.backend.config?.uplinks.map((uplink) => uplink.ifIdx),
    [7, 12],
    'both uplinks are captured'
  )
  assert.deepEqual(rigged.hostChanges.prepared[0], {
    interfaceAlias: 'Ethernet 2',
    address: '192.168.77.1',
    prefixLength: 24,
    dhcp: true
  })
  assert.equal(snapshot.downstream?.address, '192.168.77.1')
  assert.equal(snapshot.downstream?.subnet, '192.168.77.0/24')
  assert.equal(snapshot.uplinks.length, 2)
  assert.equal(snapshot.uplinks[0].address, '192.168.1.42')
  assert.equal(snapshot.uplinks[0].mtu, 1500)
  assert.equal(snapshot.uplinks[1].mtu, 1400)
  assert.equal(snapshot.capability.admin, true)
})

test('the console’s DHCP is answered from the capture, before any uplink is involved', async () => {
  const rigged = rig()
  await rigged.service.configure(config())
  const discover = Buffer.alloc(300)
  discover[0] = 1
  discover[1] = 1
  discover[2] = 6
  discover.writeUInt32BE(0x4321, 4)
  discover.set([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01], 28)
  Buffer.from([0x63, 0x82, 0x53, 0x63]).copy(discover, 236)
  discover.set([53, 1, 1, 255], 240)
  const frame = buildUdpPacket({
    srcIp: '0.0.0.0',
    dstIp: '255.255.255.255',
    srcPort: 68,
    dstPort: 67,
    payload: discover.subarray(0, 244)
  })
  assert.ok(frame)
  rigged.backend.handlers?.outbound(frame)
  assert.equal(rigged.backend.sent.length, 1, 'the OFFER is injected back onto the console’s port')
  const sent = parseIpv4(rigged.backend.sent[0].packet)
  assert.ok(sent)
  assert.equal(
    sent.dstIp,
    '255.255.255.255',
    'the console has no address yet, so it is a broadcast'
  )
  assert.equal(rigged.backend.sent[0].ifIdx, 3, 'out of the console’s own port')
  assert.equal(parseUdp(sent)?.srcPort, 67)
  assert.equal(verifyChecksums(sent), true)

  // And the gateway now knows who the console is.
  await rigged.advance(1000)
  assert.equal(rigged.service.snapshot().downstream?.client?.ip, '192.168.77.100')
})

test('console traffic is NAT’d out an uplink and the reply comes back on the console’s port', async () => {
  const rigged = rig()
  await rigged.service.configure(config())
  await rigged.advance(1000)

  rigged.backend.handlers?.outbound(
    consoleUdp({ srcPort: 3074, dstIp: '1.1.1.1', dstPort: 3074, payload: Buffer.from('game') })
  )
  assert.equal(rigged.backend.sent.length, 1)
  const sent = parseIpv4(rigged.backend.sent[0].packet)
  assert.ok(sent)
  const uplink = [WIFI, TETHER].find(
    (candidate) => candidate.ifIdx === rigged.backend.sent[0].ifIdx
  )
  assert.ok(uplink, 'it left through one of the configured uplinks')
  assert.equal(sent.srcIp, uplink.addresses[0], 'with that uplink’s address as its source')
  assert.equal(rigged.backend.sent[0].ifIdx, uplink.ifIdx)

  rigged.backend.handlers?.inbound(replyTo(sent), uplink.ifIdx)
  assert.equal(rigged.backend.sent.length, 2)
  const back = parseIpv4(rigged.backend.sent[1].packet)
  assert.ok(back)
  assert.equal(back.dstIp, '192.168.77.10', 'the reply is for the console')
  assert.equal(parseUdp(back)?.dstPort, 3074)
  assert.equal(rigged.backend.sent[1].ifIdx, 3, 'and it is delivered on the console’s port')
})

test('DNS aimed at the gateway is relayed to a real resolver through the same balancing', async () => {
  const rigged = rig()
  await rigged.service.configure(config())
  await rigged.advance(1000)

  const query = buildUdpPacket({
    srcIp: '192.168.77.10',
    dstIp: '192.168.77.1',
    srcPort: 40000,
    dstPort: 53,
    payload: Buffer.from([
      0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 101, 120, 97, 109, 112, 108, 101
    ])
  })
  assert.ok(query)
  rigged.backend.handlers?.outbound(query)
  assert.equal(rigged.backend.sent.length, 1, 'the query is forwarded, not swallowed')
  const sent = parseIpv4(rigged.backend.sent[0].packet)
  assert.ok(sent)
  assert.equal(sent.dstIp, '1.1.1.1', 'it was redirected to the resolver')
  assert.equal(parseUdp(sent)?.dstPort, 53)

  // And the answer comes back addressed to the console, as any NAT'd reply would.
  rigged.backend.handlers?.inbound(
    replyTo(sent, { payload: Buffer.from([0x12, 0x34, 0x81, 0x80]) }),
    rigged.backend.sent[0].ifIdx
  )
  const back = parseIpv4(rigged.backend.sent[1].packet)
  assert.ok(back)
  assert.equal(back.dstIp, '192.168.77.10')
  assert.equal(parseUdp(back)?.dstPort, 40000)
})

test('probes feed the weights, and a dead uplink stops taking new flows', async () => {
  const rigged = rig({
    prober: () => [
      // Wi-Fi: fast and clean. Tether: slow, with a poor RTT.
      { ok: true, at: 0, rttMs: 18, bytes: 2_500_000, durationMs: 200 },
      { ok: true, at: 0, rttMs: 90, bytes: 400_000, durationMs: 200 }
    ]
  })
  await rigged.service.configure(config())
  for (let second = 0; second < 6; second++) await rigged.advance(1000)
  const busy = rigged.service.snapshot()
  const wifi = busy.uplinks.find((uplink) => uplink.id === 'Wi-Fi')
  const tether = busy.uplinks.find((uplink) => uplink.id === 'Ethernet 3')
  assert.ok(wifi && tether)
  assert.equal(wifi.phase, 'up')
  assert.ok(wifi.capacityBps > tether.capacityBps, 'the faster uplink is measured as faster')
  assert.ok(wifi.share > tether.share, 'and gets the larger share')

  // The tether's adapter vanishes. The OS is polled every few seconds, so it takes a moment to be
  // noticed — and then the link must stop taking traffic immediately.
  rigged.hosts.delete('Ethernet 3')
  for (let second = 0; second < 6; second++) await rigged.advance(1000)
  const after = rigged.service.snapshot()
  const gone = after.uplinks.find((uplink) => uplink.id === 'Ethernet 3')
  assert.ok(gone)
  assert.equal(gone.phase, 'down')
  assert.equal(gone.downReason, 'disconnected')
  assert.equal(gone.share, 0, 'a gone uplink takes no new flows')
})

test('stopping closes the capture and puts the host back as it was', async () => {
  const rigged = rig()
  await rigged.service.configure(config())
  assert.equal(rigged.backend.running, true)

  await rigged.service.configure(config({ enabled: false }))
  assert.equal(rigged.backend.running, false)
  assert.equal(rigged.hostChanges.reverted, 1, 'the address and firewall rule it added are removed')
  const snapshot = rigged.service.snapshot()
  assert.equal(snapshot.status, 'stopped')
  assert.equal(snapshot.intercepting, false)
})

test('the port the console is on is not captured from itself: the gateway’s own traffic is ignored', async () => {
  const rigged = rig()
  await rigged.service.configure(config())
  await rigged.advance(1000)
  // A packet to the gateway's own address on a port it does not serve.
  const packet = buildUdpPacket({
    srcIp: '192.168.77.10',
    dstIp: '192.168.77.1',
    srcPort: 50000,
    dstPort: 9999,
    payload: Buffer.from('not for us')
  })
  assert.ok(packet)
  rigged.backend.handlers?.outbound(packet)
  assert.equal(rigged.backend.sent.length, 0)
})

test('a TCP connection on an uplink that dies is reset so the console reconnects at once', async () => {
  const rigged = rig()
  await rigged.service.configure(config())
  await rigged.advance(1000)

  rigged.backend.handlers?.outbound(
    consoleTcp({
      srcPort: 40000,
      dstIp: '93.184.216.34',
      dstPort: 443,
      flags: TCP_FLAG.SYN,
      seq: 1
    })
  )
  const first = parsed(rigged.backend.sent.at(-1))
  const usedIfIdx = rigged.backend.sent.at(-1)?.ifIdx ?? 0
  rigged.backend.handlers?.inbound(replyTo(first), usedIfIdx)

  // That uplink disappears.
  const dead = [WIFI, TETHER].find((candidate) => candidate.ifIdx === usedIfIdx)
  assert.ok(dead)
  rigged.hosts.delete(dead.id)
  await rigged.advance(1000)

  rigged.backend.handlers?.outbound(
    consoleTcp({
      srcPort: 40000,
      dstIp: '93.184.216.34',
      dstPort: 443,
      flags: TCP_FLAG.ACK,
      seq: 100
    })
  )
  const reset = parsed(rigged.backend.sent.at(-1))
  assert.equal(reset.dstIp, '192.168.77.10')
  assert.equal(rigged.backend.sent.at(-1)?.ifIdx, 3, 'the reset goes to the console')
  assert.ok(rigged.service.snapshot().totals.resets >= 1)
})

test('the self-test explains a missing driver instead of failing silently', async () => {
  const rigged = rig({
    capability: {
      ...CAPABLE,
      driverInstalled: false,
      reason: 'WinDivert was not found.'
    }
  })
  await rigged.service.configure(config({ enabled: false }))
  const result = await rigged.service.selfTest()
  assert.equal(result.ok, false)
  assert.match(result.detail, /WinDivert/)
})

function parsed(entry: { packet: Buffer } | undefined): ReturnType<typeof parseIpv4> & object {
  assert.ok(entry)
  const packet = parseIpv4(entry.packet)
  assert.ok(packet)
  return packet
}

/** Keeps the ICMP import honest: a DHCP reply is not an ICMP message. */
test('the DHCP path and the ICMP path do not collide', async () => {
  const rigged = rig()
  await rigged.service.configure(config())
  await rigged.advance(1000)
  const ping = Buffer.alloc(28)
  ping.writeUInt8(0x45, 0)
  ping.writeUInt16BE(28, 2)
  ping.writeUInt8(64, 8)
  ping.writeUInt8(1, 9)
  ping.set([192, 168, 77, 10], 12)
  ping.set([8, 8, 8, 8], 16)
  ping.writeUInt8(8, 20)
  ping.writeUInt16BE(0x11, 24)
  ping.writeUInt16BE(1, 26)
  ping.writeUInt16BE(0, 22)
  const { internetChecksum } = await import('../../src/main/gateway/packet.ts')
  ping.writeUInt16BE(internetChecksum(ping, 20, 8), 22)
  ping.writeUInt16BE(0, 10)
  ping.writeUInt16BE(internetChecksum(ping, 0, 20), 10)

  rigged.backend.handlers?.outbound(ping)
  assert.equal(rigged.backend.sent.length, 1, 'an echo request is NAT’d like any other flow')
  const sent = parsed(rigged.backend.sent[0])
  assert.equal(parseIcmp(sent)?.type, 8)
  assert.notEqual(sent.buffer.readUInt16BE(24), 0x11, 'its identifier was translated')
})
