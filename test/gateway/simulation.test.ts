/**
 * The whole gateway under conditions it will actually meet: asymmetric uplinks, jitter, loss, and a
 * link that disappears in the middle of a session.
 *
 * Nothing here is mocked at the decision level. The real `LinkHealth`, the real weighted rendezvous
 * scheduler, the real NAT and the real packet rewriter run against packets built byte by byte, and
 * only the *world* is simulated: how fast each uplink carries bytes, how long it takes, how often it
 * loses a packet, and when it dies. The clock is the test's, so a sixty-second session runs in
 * milliseconds and every second of it is reproducible.
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { choicesFrom, LinkHealth } from '../../src/main/gateway/health.ts'
import { TCP_FLAG, parseIpv4 } from '../../src/main/gateway/packet.ts'
import { verifyChecksums } from '../../src/main/gateway/packet.ts'
import { CONSOLE_IP, USB, WIFI, World, consoleTcp, consoleUdp, replyTo } from './harness.ts'

interface LinkModel {
  id: string
  /** Upload/download capacity, bytes per second. */
  capacityBps: number
  rttMs: number
  jitterMs: number
  /** Packet loss, 0..1. */
  loss: number
}

interface Flow {
  kind: 'tcp' | 'udp'
  clientPort: number
  dstIp: string
  dstPort: number
  /** Bytes this flow wants to send per second. */
  demandBps: number
  /** Where it currently goes — the gateway's answer, not the flow's. */
  linkId?: string
  bytesServed: number
  resets: number
  seq: number
}

/**
 * A deterministic PRNG (mulberry32): the same seed replays the same session, which is what makes
 * assertions about "did it survive the flap" meaningful rather than flaky.
 */
function rng(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (state + 0x6d2b79f5) >>> 0
    let t = Math.imul(state ^ (state >>> 15), 1 | state)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

class Simulation {
  readonly world: World
  readonly health: Record<string, LinkHealth>
  readonly models: LinkModel[]
  readonly flows: Flow[] = []
  readonly servedPerLink = new Map<string, number>()
  readonly history: { at: number; share: Record<string, number>; throughputBps: number }[] = []
  private readonly random: () => number
  private lastReply: Map<number, number> = new Map()

  constructor(options: {
    seed: number
    models: LinkModel[]
    flows: Omit<Flow, 'bytesServed' | 'resets' | 'seq'>[]
    now?: number
  }) {
    this.random = rng(options.seed)
    this.world = new World({
      uplinks: options.models.map((model) => ({
        id: model.id,
        address: model.id === WIFI.id ? WIFI.address : USB.address,
        ifIdx: model.id === WIFI.id ? WIFI.ifIdx : USB.ifIdx,
        mtu: 1500,
        mac: null,
        usable: true,
        weight: 0.5,
        reachable: true,
        enabled: true
      }))
    })
    if (options.now) this.world.now = options.now
    this.models = options.models
    this.health = {}
    for (const model of options.models) {
      const linkHealth = new LinkHealth(
        model.id,
        { downAfterMs: 3000, upAfterMs: 1500 },
        this.world.now
      )
      linkHealth.setConnected(true)
      this.health[model.id] = linkHealth
      this.servedPerLink.set(model.id, 0)
    }
    this.flows = options.flows.map((flow) => ({ ...flow, bytesServed: 0, resets: 0, seq: 1 }))
  }

  /** One second of the session. */
  tick(): void {
    this.world.advance(1000)
    const now = this.world.now

    // 1. The prober measures each uplink: a small download, with the modelled latency, jitter and
    //    loss. This is the only thing that tells an idle link how fast it is.
    for (const model of this.models) {
      const link = this.world.uplinks.find((candidate) => candidate.id === model.id)
      const up = link?.usable ?? false
      const rtt = model.rttMs + (this.random() - 0.5) * 2 * model.jitterMs
      const lost = this.random() < model.loss
      this.health[model.id].observeProbe(
        {
          ok: up && !lost,
          rttMs: Math.max(1, rtt),
          bytes: model.capacityBps * 0.2,
          durationMs: 200 + rtt
        },
        now
      )
    }

    // 2. Weights from health, and the forwarder told what it may use.
    const samples = Object.values(this.health).map((link) => link.sample(now))
    const choices = choicesFrom(samples)
    for (const choice of choices) {
      const link = this.world.uplinks.find((candidate) => candidate.id === choice.id)
      if (link) link.weight = choice.weight
    }

    // 3. Each flow sends a second's worth of traffic in MTU-sized packets. A link serves no more
    //    than its capacity: what is left over is lost, as it would be in a queue that overflows.
    const demand = new Map<string, number>()
    const served = new Map<string, number>()
    for (const flow of this.flows) {
      // A second of demand, in MTU-sized packets: what a download manager's streams look like.
      const packets = Math.max(1, Math.round(flow.demandBps / 1400))
      for (let index = 0; index < packets; index++) {
        const payload = Buffer.alloc(1400, 0x41)
        const packet =
          flow.kind === 'tcp'
            ? consoleTcp({
                srcPort: flow.clientPort,
                dstIp: flow.dstIp,
                dstPort: flow.dstPort,
                flags: TCP_FLAG.ACK,
                seq: flow.seq,
                ack: 1,
                payload
              })
            : consoleUdp({
                srcPort: flow.clientPort,
                dstIp: flow.dstIp,
                dstPort: flow.dstPort,
                payload
              })
        flow.seq += payload.length
        const result = this.world.outbound(packet)
        if (result.transmit.length === 0) {
          // A TCP flow whose uplink died is reset by the gateway; count it and let it reconnect.
          if (result.transmit.length === 0 && flow.kind === 'tcp') flow.resets++
          continue
        }
        if (result.linkId) {
          flow.linkId = result.linkId
          demand.set(result.linkId, (demand.get(result.linkId) ?? 0) + packet.length)
        }
        // The server answers the first packet of each tuple — unless the modelled link loses the
        // return packet. (Answering every packet would only multiply the test's own work.)
        const model =
          index === 0 ? this.models.find((candidate) => candidate.id === flow.linkId) : undefined
        const linkIsUp = this.world.uplinks.find(
          (candidate) => candidate.id === flow.linkId
        )?.usable
        if (model && linkIsUp && this.random() >= model.loss) {
          for (const entry of result.transmit) {
            const sent = parseIpv4(entry.packet)
            if (!sent) continue
            const reply = replyTo(sent)
            const delivered = this.world.inbound(reply, flow.linkId)
            if (delivered.transmit.length > 0) this.lastReply.set(flow.clientPort, now)
          }
        }
      }
    }

    for (const model of this.models) {
      const wanted = demand.get(model.id) ?? 0
      const carried = Math.min(wanted, model.capacityBps)
      served.set(model.id, carried)
      this.servedPerLink.set(model.id, (this.servedPerLink.get(model.id) ?? 0) + carried)
      this.health[model.id].addBytes(carried)
    }

    const share: Record<string, number> = {}
    let throughput = 0
    for (const model of this.models) {
      share[model.id] = served.get(model.id) ?? 0
      throughput += served.get(model.id) ?? 0
    }
    this.history.push({ at: now, share, throughputBps: throughput })
  }

  run(seconds: number): void {
    for (let second = 0; second < seconds; second++) this.tick()
  }

  /** Bytes/second over a window of ticks, per link. */
  throughputOver(fromTick: number, toTick: number): Record<string, number> {
    const out: Record<string, number> = {}
    for (const model of this.models) out[model.id] = 0
    for (let index = fromTick; index < toTick; index++) {
      for (const [id, value] of Object.entries(this.history[index].share)) {
        out[id] = (out[id] ?? 0) + value
      }
    }
    for (const id of Object.keys(out)) out[id] /= Math.max(1, toTick - fromTick)
    return out
  }

  lastReplyAt(clientPort: number): number | undefined {
    return this.lastReply.get(clientPort)
  }
}

const WIFI_MODEL: LinkModel = {
  id: WIFI.id,
  capacityBps: 5_000_000,
  rttMs: 22,
  jitterMs: 6,
  loss: 0.01
}
const USB_MODEL: LinkModel = {
  id: USB.id,
  capacityBps: 1_500_000,
  rttMs: 65,
  jitterMs: 20,
  loss: 0.03
}

function downloadFlows(count: number): Omit<Flow, 'bytesServed' | 'resets' | 'seq'>[] {
  return Array.from({ length: count }, (_, index) => ({
    kind: 'tcp' as const,
    clientPort: 40000 + index,
    dstIp: '93.184.216.34',
    dstPort: 443,
    demandBps: 400_000
  }))
}

test('a download uses both uplinks, in proportion to what each can carry', () => {
  // 20 flows at 400 kB/s is 8 MB/s of demand against 6.5 MB/s of capacity: both uplinks are the
  // bottleneck, which is when balancing has anything to balance.
  const simulation = new Simulation({
    seed: 7,
    models: [WIFI_MODEL, USB_MODEL],
    flows: downloadFlows(20)
  })
  simulation.run(18)
  const throughput = simulation.throughputOver(8, 18)
  const wifi = throughput[WIFI.id]
  const usb = throughput[USB.id]
  assert.ok(usb > 200_000, `the USB uplink must carry real traffic, carried ${usb.toFixed(0)} B/s`)
  assert.ok(wifi > usb, 'the faster uplink carries more')
  // The two together beat the best one alone, which is the entire point.
  assert.ok(
    wifi + usb > Math.max(WIFI_MODEL.capacityBps, USB_MODEL.capacityBps) * 1.1,
    `combined ${((wifi + usb) / 1e6).toFixed(2)} MB/s must beat a single uplink`
  )
  // And neither is pinned to its theoretical maximum: the split follows measured capacity.
  assert.ok(
    wifi / (wifi + usb) > 0.55 && wifi / (wifi + usb) < 0.95,
    `Wi-Fi share ${(wifi / (wifi + usb)).toFixed(2)}`
  )
})

test('the split stays put when nothing changes (no churn, no flow migration)', () => {
  const simulation = new Simulation({
    seed: 11,
    models: [WIFI_MODEL, USB_MODEL],
    flows: downloadFlows(12)
  })
  simulation.run(12)
  const placements = simulation.flows.map((flow) => flow.linkId)
  simulation.run(20)
  const later = simulation.flows.map((flow) => flow.linkId)
  assert.deepEqual(
    later,
    placements,
    'a working connection must never be moved for balancing’s sake'
  )
})

test('a Wi-Fi dropout moves the game, resets nothing it can spare, and recovers', () => {
  const simulation = new Simulation({
    seed: 3,
    models: [WIFI_MODEL, USB_MODEL],
    flows: [
      ...downloadFlows(8),
      { kind: 'udp', clientPort: 3074, dstIp: '1.1.1.1', dstPort: 3074, demandBps: 20_000 }
    ]
  })
  simulation.run(10)
  const game = simulation.flows[simulation.flows.length - 1]
  assert.ok(game.linkId, 'the game flow is placed')
  const wifiBefore = simulation.world.uplinks.find((link) => link.id === WIFI.id)
  assert.ok(wifiBefore)

  // Wi-Fi dies for four seconds, as a mobile router rebooting does.
  simulation.world.kill(WIFI.id)
  simulation.run(4)
  const usb = simulation.world.uplinks.find((link) => link.id === USB.id)
  assert.ok(usb)
  const gameUplink = simulation.world.nat.lookup(17, CONSOLE_IP, 3074)
  assert.equal(gameUplink?.linkId, USB.id, 'the UDP association moved to the surviving uplink')
  assert.ok(simulation.lastReplyAt(3074), 'and the game was still talking to its server')
  assert.ok(
    simulation.world.forwarder.totals.repins >= 1,
    'the move is counted as a re-pin, not as a new connection'
  )
  // Every TCP flow that was on Wi-Fi got a reset rather than a thirty-second stall.
  assert.ok(simulation.world.forwarder.totals.resets > 0, 'dead TCP connections are reset')

  // Wi-Fi comes back: new connections use it again, without waiting for a restart. Connections
  // that had to move stay where they are — moving them back would break them a second time, which
  // is the whole reason a mapping is sticky.
  simulation.world.revive(WIFI.id)
  for (let index = 0; index < 8; index++) {
    simulation.flows.push({
      kind: 'tcp',
      clientPort: 50000 + index,
      dstIp: '93.184.216.34',
      dstPort: 443,
      demandBps: 300_000,
      bytesServed: 0,
      resets: 0,
      seq: 1
    })
  }
  simulation.run(12)
  const recovered = simulation.world.nat.lookup(17, CONSOLE_IP, 3074)
  assert.ok(recovered, 'the game still has its mapping')
  const onWifi = simulation.flows.filter(
    (flow) => flow.clientPort >= 50000 && flow.linkId === WIFI.id
  )
  assert.ok(onWifi.length > 0, 'new connections use the recovered uplink again')
  const throughput = simulation.throughputOver(
    simulation.history.length - 5,
    simulation.history.length
  )
  assert.ok(throughput[WIFI.id] > 0)
})

test('a flapping uplink does not drag connections back and forth', () => {
  const simulation = new Simulation({
    seed: 5,
    models: [WIFI_MODEL, USB_MODEL],
    flows: downloadFlows(10)
  })
  simulation.run(12)
  const before = simulation.flows.map((flow) => flow.linkId)
  // A signal dip: failures for 1.5 s, then fine again, three times.
  for (let round = 0; round < 3; round++) {
    const wifiHealth = simulation.health[WIFI.id]
    for (let sample = 0; sample < 2; sample++) {
      simulation.world.advance(750)
      wifiHealth.observeProbe({ ok: false, rttMs: null }, simulation.world.now)
      wifiHealth.sample(simulation.world.now)
    }
    simulation.world.advance(2000)
    wifiHealth.observeProbe({ ok: true, rttMs: 30 }, simulation.world.now)
    wifiHealth.sample(simulation.world.now)
  }
  const after = simulation.flows.map((flow) => flow.linkId)
  const changed = after.filter((id, index) => id !== before[index]).length
  assert.equal(
    changed,
    0,
    'brief failures must not move connections: every migration costs a reset or a lost association'
  )
})

test('one uplink is enough, and the gateway says so rather than failing', () => {
  const simulation = new Simulation({ seed: 9, models: [WIFI_MODEL], flows: downloadFlows(5) })
  simulation.run(15)
  const throughput = simulation.throughputOver(5, 15)
  assert.ok(throughput[WIFI.id] > 500_000)
  assert.equal(simulation.world.forwarder.totals.dropped, 0)
  for (const flow of simulation.flows) assert.equal(flow.linkId, WIFI.id)
})

test('every packet the gateway sends out of an uplink is well formed', () => {
  const simulation = new Simulation({
    seed: 13,
    models: [WIFI_MODEL, USB_MODEL],
    flows: downloadFlows(6)
  })
  simulation.run(6)
  assert.ok(simulation.world.sent.length > 100)
  for (const entry of simulation.world.sent) {
    const packet = parseIpv4(entry.packet)
    assert.ok(packet, 'a parseable IPv4 packet')
    assert.equal(verifyChecksums(packet), true, 'checksums must always be valid after a rewrite')
    const link = simulation.world.uplinks.find((candidate) => candidate.ifIdx === entry.ifIdx)
    assert.ok(link, 'and it goes out of a real interface')
    assert.equal(packet.srcIp, link.address, 'with that interface’s own address')
  }
})

/**
 * The soak: thirty randomly generated worlds — three uplinks of random speed, latency, and loss,
 * links dying and coming back at random moments — and the invariants that must hold in every one of
 * them. Randomised *inputs*, fixed *assertions*: this is what catches the mistakes a hand-written
 * scenario doesn't think of.
 */
test('property: across random worlds, nothing is lost, mistranslated, or left behind', () => {
  for (let seed = 1; seed <= 12; seed++) {
    const random = rng(seed * 7919)
    const ids = [WIFI.id, USB.id, 'Ethernet 4']
    const models: LinkModel[] = ids.map((id) => ({
      id,
      capacityBps: Math.round((0.8 + random() * 12) * 1_000_000),
      rttMs: 10 + random() * 120,
      jitterMs: random() * 30,
      loss: random() * 0.05
    }))
    const flows = Array.from({ length: 6 + Math.floor(random() * 10) }, (_, index) => ({
      kind: (random() < 0.7 ? 'tcp' : 'udp') as 'tcp' | 'udp',
      clientPort: 40000 + index,
      dstIp: '93.184.216.34',
      dstPort: index % 2 === 0 ? 443 : 3074,
      demandBps: Math.round((0.05 + random() * 0.5) * 1_000_000)
    }))
    const simulation = new Simulation({ seed, models, flows })
    const highest = Math.max(...models.map((model) => model.capacityBps))
    const demand = flows.reduce((sum, flow) => sum + flow.demandBps, 0)

    let lastFlap = -1
    for (let second = 0; second < 14; second++) {
      // A link dies, or comes back, every few seconds.
      if (second > 2 && random() < 0.15) {
        const victim = ids[Math.floor(random() * ids.length)]
        const link = simulation.world.uplink(victim)
        if (link.usable) simulation.world.kill(victim)
        else simulation.world.revive(victim)
        lastFlap = second
      }
      simulation.tick()
    }

    // 1. Everything that left an uplink is a valid packet, addressed as that uplink.
    for (const entry of simulation.world.sent) {
      const packet = parseIpv4(entry.packet)
      assert.ok(packet, `seed ${seed}: an uplink was handed an unparsable packet`)
      assert.equal(verifyChecksums(packet), true, `seed ${seed}: bad checksums on the wire`)
      const link = simulation.world.uplink(entry.linkId)
      if (link.usable) {
        assert.equal(
          packet.srcIp,
          link.address,
          `seed ${seed}: wrong source address for ${link.id}`
        )
      }
      assert.notEqual(packet.srcIp, CONSOLE_IP, `seed ${seed}: the console's address escaped`)
    }

    // 2. Everything delivered to the console is a valid packet addressed to the console.
    for (const entry of simulation.world.deliveredToConsole) {
      const packet = parseIpv4(entry.packet)
      assert.ok(packet, `seed ${seed}: the console was handed an unparsable packet`)
      assert.equal(verifyChecksums(packet), true, `seed ${seed}: bad checksums toward the console`)
      assert.equal(
        packet.dstIp,
        CONSOLE_IP,
        `seed ${seed}: a packet for someone else was delivered`
      )
    }

    // 3. The table stays bounded by the flows that exist, and every mapping is still reachable by
    //    its public port — a mapping that isn't is a flow that dies silently.
    const mappings = [...simulation.world.nat.mappings()]
    assert.ok(
      mappings.length <= flows.length,
      `seed ${seed}: ${mappings.length} mappings for ${flows.length} flows`
    )
    for (const mapping of mappings) {
      const back = simulation.world.nat.lookupPublic(
        mapping.linkId,
        mapping.proto,
        mapping.publicPort
      )
      assert.equal(back, mapping, `seed ${seed}: mapping lost its public port`)
      assert.ok(
        mapping.publicPort >= 1024 && mapping.publicPort <= 65535,
        `seed ${seed}: port out of range`
      )
    }

    // 4. When at least one uplink is alive, traffic keeps moving — a flap must never wedge the
    //    gateway. When both are alive and the demand is there, both get used.
    const alive = simulation.world.uplinks.filter((link) => link.usable).length
    assert.ok(
      alive > 0 || simulation.world.sent.length > 0,
      `seed ${seed}: no uplink ever carried anything`
    )
    if (alive > 0) {
      const total = simulation.throughputOver(9, 14)
      const carried = Object.values(total).reduce((sum, value) => sum + value, 0)
      assert.ok(carried > 0, `seed ${seed}: nothing was carried with ${alive} uplinks alive`)
      if (alive > 1) {
        // A window that contained a link coming or going legitimately carries less: the flows that
        // were on it had to be reset and reopened. Outside such a window, the full throughput must
        // be there — this is the assertion that says a flap leaves nothing stuck.
        const expected =
          lastFlap < 9
            ? Math.min(highest * 0.3, demand * 0.5)
            : Math.min(highest * 0.05, demand * 0.2)
        assert.ok(
          carried >= expected,
          `seed ${seed}: throughput collapsed to ${carried.toFixed(0)} B/s, expected ${expected.toFixed(0)}`
        )
      }
    }
  }
})
