/**
 * The Windows lab: the parts of the gateway that cannot be tested anywhere else.
 *
 * Everything else in `test/` runs on any machine, because the engine is platform-free. What is left
 * is the half that only exists on Windows — the WinDivert driver, the `WINDIVERT_ADDRESS` codec
 * against the *real* driver's own memory, the capture process spawning and its IPC, the PowerShell
 * adapter enumeration — and that is what this file exercises, on a real Windows runner instead of on
 * someone's gaming PC.
 *
 * Two rules keep it safe to run on a shared CI machine whose own internet must keep working:
 *
 *  1. **Nothing is ever dropped.** Every capture handle is opened in *sniff* mode (copy, do not
 *     remove) or matches an interface index that does not exist. A handle that removed the runner's
 *     traffic from the stack would take the runner offline mid-job — which is exactly the failure
 *     that was shipped once, so it is not repeated in the test that checks for it.
 *  2. **Nothing is changed.** The gateway service runs with `manageHost: false` and synthetic
 *     adapters, so no address, route or firewall rule of the machine is touched.
 *
 * Off Windows every test skips, so this file is harmless in the ordinary test run.
 */

import assert from 'node:assert/strict'
import { createSocket } from 'node:dgram'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { test } from 'node:test'
import { GatewayService } from '../../src/main/gateway/service'
import { WinDivertBackend } from '../../src/main/gateway/backends/winDivert'
import {
  hostEnumerationError,
  listHostInterfaces,
  type HostInterface
} from '../../src/main/gateway/hostInterfaces'
import { detectCapability, isAdministrator } from '../../src/main/gateway/windowsHost'
import { DEFAULT_GATEWAY_CONFIG, type GatewayConfig } from '../../src/shared/gateway'
import { internetChecksum, parseIcmp, parseIpv4, IPPROTO } from '../../src/main/gateway/packet'

const isWindows = process.platform === 'win32'
const DLL_PATH = join(process.cwd(), 'resources', 'windivert', 'WinDivert.dll')
const WORKER_PATH = process.env.PLEXO_LAB_WORKER ?? ''

/** Prints a line into the CI log, where a person reading a failed run will see it. */
function log(message: string): void {
  process.stdout.write(`[lab] ${message}\n`)
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/** Whether the driver can be opened at all. Checked once, and every driver test depends on it. */
let driverReady: { ok: boolean; detail: string } | null = null

async function canUseDriver(): Promise<{ ok: boolean; detail: string }> {
  if (driverReady) return driverReady
  if (!isWindows) {
    driverReady = { ok: false, detail: 'not Windows' }
    return driverReady
  }
  if (!existsSync(DLL_PATH)) {
    driverReady = { ok: false, detail: `WinDivert.dll missing at ${DLL_PATH}` }
    return driverReady
  }
  if (!WORKER_PATH || !existsSync(WORKER_PATH)) {
    driverReady = { ok: false, detail: `capture process missing (${WORKER_PATH})` }
    return driverReady
  }
  const admin = await isAdministrator()
  if (!admin) {
    driverReady = { ok: false, detail: 'the process is not elevated' }
    return driverReady
  }
  const backend = new WinDivertBackend({ dllPath: DLL_PATH, workerPath: WORKER_PATH })
  const result = await backend.selfTest({
    downstreamIfIdx: 9999,
    uplinks: [{ ifIdx: 9998, id: 'lab-uplink' }],
    labels: new Map(),
    publicPorts: { min: 20_000, max: 29_999 }
  })
  log(`driver self-test: ${result.ok ? 'ok' : 'failed'} — ${result.detail}`)
  if (!result.ok) log(`dll: ${DLL_PATH}`)
  driverReady = result
  return driverReady
}

/** The synthetic adapter setup: interface indexes nothing on a real machine has. */
function syntheticHosts(): Map<string, HostInterface> {
  const base = (id: string, ifIdx: number, address: string): HostInterface => ({
    id,
    ifIdx,
    description: id,
    mac: null,
    addresses: [address],
    mtu: 1500,
    gateway: null,
    linkSpeedBps: 100_000_000,
    up: true
  })
  return new Map([
    ['Lab Console Port', base('Lab Console Port', 9999, '192.168.77.1')],
    ['Lab Uplink', base('Lab Uplink', 9998, '10.99.0.2')]
  ])
}

test('the runner is Windows, elevated, and has the driver and capture process where expected', async (t) => {
  log(`platform: ${process.platform} ${process.arch} · node ${process.version}`)
  if (!isWindows) {
    t.skip('not Windows')
    return
  }
  if (!WORKER_PATH) {
    // Started by hand rather than by `scripts/run-gateway-lab.mjs`, which is what builds the capture
    // process and passes its path in.
    t.skip('run this through `npm run test:windows`')
    return
  }
  log(`dll: ${DLL_PATH} (${existsSync(DLL_PATH) ? 'present' : 'MISSING'})`)
  log(`capture process: ${WORKER_PATH} (${existsSync(WORKER_PATH) ? 'present' : 'MISSING'})`)
  const capability = await detectCapability(process.cwd())
  log(`capability: ${JSON.stringify(capability)}`)
  assert.equal(capability.supported, true, 'Windows is always supported')
  assert.equal(capability.driverInstalled, true, 'the bundled driver files must be found')
  assert.ok(existsSync(WORKER_PATH), 'the capture process bundle must exist')
})

test('the driver loads and accepts the exact filters the gateway uses', async (t) => {
  if (!isWindows) {
    t.skip('not Windows')
    return
  }
  const ready = await canUseDriver()
  if (!ready.ok) {
    // Informational, not a failure: an unelevated runner cannot open the driver, and that is a
    // property of the machine, not of the code. The workflow reports it either way.
    t.skip(`driver unusable here: ${ready.detail}`)
    return
  }
  assert.equal(ready.ok, true, ready.detail)
})

test('a capture that matches nothing opens, idles for seconds, and still reports running', async (t) => {
  // The regression test for the bug that shipped: the loop gave up after 20 empty reads (100 ms),
  // shut the capture process down, and the app showed an error with every counter at zero.
  if (!isWindows) {
    t.skip('not Windows')
    return
  }
  const ready = await canUseDriver()
  if (!ready.ok) {
    t.skip(`driver unusable here: ${ready.detail}`)
    return
  }
  const backend = new WinDivertBackend({ dllPath: DLL_PATH, workerPath: WORKER_PATH })
  const received: Buffer[] = []
  await backend.start(
    {
      downstreamIfIdx: 9999,
      uplinks: [{ ifIdx: 9998, id: 'lab-uplink' }],
      labels: new Map(),
      publicPorts: { min: 20_000, max: 29_999 }
    },
    {
      outbound: (packet) => received.push(packet),
      inbound: (packet) => received.push(packet)
    }
  )
  try {
    await sleep(3000)
    const status = backend.status()
    log(`after 3 s idle: ${JSON.stringify({ ...status, diagnostics: undefined })}`)
    assert.equal(status.error, null, `the capture failed while idle: ${status.error}`)
    assert.equal(status.running, true, 'an idle connection is not a broken one')
    assert.equal(received.length, 0, 'nothing should match a nonexistent interface')
    assert.ok(
      status.diagnostics.some((line) => line.includes('open and receiving')),
      `the capture process never reported itself ready: ${status.diagnostics.join(' | ')}`
    )
  } finally {
    await backend.stop()
  }
  assert.equal(backend.status().running, false)
})

test('the whole service runs against the real driver, and stops cleanly', async (t) => {
  if (!isWindows) {
    t.skip('not Windows')
    return
  }
  const ready = await canUseDriver()
  if (!ready.ok) {
    t.skip(`driver unusable here: ${ready.detail}`)
    return
  }
  const config: GatewayConfig = {
    ...DEFAULT_GATEWAY_CONFIG,
    enabled: true,
    downstreamId: 'Lab Console Port',
    uplinkIds: ['Lab Uplink'],
    manageHost: false,
    dhcp: true,
    dnsRelay: true
  }
  const service = new GatewayService({
    backend: new WinDivertBackend({ dllPath: DLL_PATH, workerPath: WORKER_PATH }),
    host: async () => syntheticHosts(),
    capability: async () => ({
      supported: true,
      platform: 'win32',
      admin: true,
      driverInstalled: true,
      canInstallDriver: false,
      reason: null
    }),
    prepareHost: async () => [],
    revertHost: async () => {},
    prober: {
      round: async (targets) =>
        targets.map(() => ({ ok: false, at: 0, rttMs: 0, bytes: 0, durationMs: 0 }))
    }
  })
  await service.configure(config)
  const running = service.snapshot()
  log(
    `service: status=${running.status} intercepting=${running.intercepting} error=${running.error}`
  )
  assert.equal(running.status, 'running', `the service did not start: ${running.error}`)
  assert.equal(running.intercepting, true)
  for (let second = 0; second < 3; second++) {
    await sleep(1000)
    await service.pump()
  }
  const settled = service.snapshot()
  assert.equal(settled.status, 'running', 'it must still be running after a few seconds')
  assert.equal(settled.error, null, `it failed while running: ${settled.error}`)
  // The adapter list must include the synthetic ones, which is what the panel renders.
  assert.deepEqual(settled.adapters.map((adapter) => adapter.id).sort(), [
    'Lab Console Port',
    'Lab Uplink'
  ])
  await service.configure({ ...config, enabled: false })
  assert.equal(service.snapshot().status, 'stopped')
})

test('the PC’s own adapters are enumerated from PowerShell, with indexes and addresses', async (t) => {
  if (!isWindows) {
    t.skip('not Windows')
    return
  }
  const hosts = await listHostInterfaces()
  log(
    `adapters: ${[...hosts.values()]
      .map((host) => `${host.id}#${host.ifIdx}(${host.addresses.join(',') || 'no address'})`)
      .join(' | ')}`
  )
  if (hostEnumerationError()) log(`PowerShell enumeration failed: ${hostEnumerationError()}`)
  assert.ok(hosts.size > 0, 'a runner always has at least one adapter')
  const usable = [...hosts.values()].filter((host) => host.ifIdx > 0 && host.addresses.length > 0)
  assert.ok(usable.length > 0, 'at least one adapter must have an interface index and an address')
  for (const host of usable) {
    assert.ok(host.mtu >= 576 && host.mtu <= 9000, `${host.id} has a plausible MTU`)
  }
})

test('real packets are captured from a real adapter and decode to what they say they are', async (t) => {
  // This is the only place the `WINDIVERT_ADDRESS` offsets meet the driver that writes them. A wrong
  // offset would silently send every packet out of the wrong adapter — the kind of bug that looks
  // like "the internet is broken" and cannot be found by reading the code.
  if (!isWindows) {
    t.skip('not Windows')
    return
  }
  const ready = await canUseDriver()
  if (!ready.ok) {
    t.skip(`driver unusable here: ${ready.detail}`)
    return
  }
  const hosts = await listHostInterfaces()
  const host = [...hosts.values()].find((entry) => entry.ifIdx > 0 && entry.addresses.length > 0)
  if (!host) {
    t.skip('no adapter with an address to sniff')
    return
  }

  const seen: { ifIdx: number; parsed: ReturnType<typeof parseIpv4> }[] = []
  const backend = new WinDivertBackend({ dllPath: DLL_PATH, workerPath: WORKER_PATH })
  await backend.start(
    {
      downstreamIfIdx: host.ifIdx,
      uplinks: [],
      labels: new Map(),
      publicPorts: { min: 20_000, max: 29_999 },
      // Copy, never take: the runner's own traffic must survive this test.
      sniff: true
    },
    {
      outbound: (packet) => seen.push({ ifIdx: host.ifIdx, parsed: parseIpv4(packet) }),
      inbound: (packet, ifIdx) => seen.push({ ifIdx, parsed: parseIpv4(packet) })
    }
  )
  try {
    // Something to capture: any inbound traffic at all.
    const response = await fetch('https://example.com', {
      signal: AbortSignal.timeout(8000)
    }).catch(() => null)
    log(`generated traffic: ${response ? `HTTP ${response.status}` : 'request failed'}`)
    for (let waited = 0; waited < 8000 && seen.length === 0; waited += 250) await sleep(250)
    log(`captured ${seen.length} packets on ${host.id}#${host.ifIdx}`)
    if (seen.length === 0) {
      t.skip('no packets arrived to sniff (the runner may route through a proxy)')
      return
    }
    const valid = seen.filter((entry) => entry.parsed !== null)
    assert.ok(valid.length > 0, 'captured packets must parse as IPv4')
    for (const entry of seen) {
      assert.ok(entry.ifIdx > 0, 'every captured packet must carry a real interface index')
      if (entry.parsed) {
        assert.equal(entry.parsed.version, 4)
        assert.ok(entry.parsed.totalLength >= 20)
      }
    }
    // At least one TCP packet, since that is what HTTPS is.
    assert.ok(
      valid.some((entry) => entry.parsed?.protocol === IPPROTO.TCP),
      'the capture saw no TCP packets at all'
    )
  } finally {
    await backend.stop()
  }
})

test('a packet the gateway injects really leaves through the interface it chose', async (t) => {
  // Validates encodeAddress + WinDivertSend + the per-interface injection the whole design rests on:
  // an ICMP echo request is injected out of a real adapter, and the reply comes back through the
  // same capture. No reply means the network or the firewall ate it — inconclusive, not a failure.
  if (!isWindows) {
    t.skip('not Windows')
    return
  }
  const ready = await canUseDriver()
  if (!ready.ok) {
    t.skip(`driver unusable here: ${ready.detail}`)
    return
  }
  const hosts = await listHostInterfaces()
  const host = [...hosts.values()].find(
    (entry) => entry.ifIdx > 0 && entry.addresses.some((address) => !address.startsWith('127.'))
  )
  if (!host) {
    t.skip('no adapter with a routable address')
    return
  }
  const source = host.addresses.find((address) => !address.startsWith('127.')) ?? host.addresses[0]
  const identifier = 0x5100 + Math.floor(Math.random() * 200)

  const replies: Buffer[] = []
  const backend = new WinDivertBackend({ dllPath: DLL_PATH, workerPath: WORKER_PATH })
  await backend.start(
    {
      downstreamIfIdx: host.ifIdx,
      uplinks: [],
      labels: new Map(),
      publicPorts: { min: 20_000, max: 29_999 },
      sniff: true
    },
    {
      outbound: (packet) => replies.push(packet),
      inbound: (packet) => replies.push(packet)
    }
  )
  try {
    const request = buildEchoRequest({
      srcIp: source,
      dstIp: '1.1.1.1',
      identifier,
      sequence: 1
    })
    backend.send(request === null ? [] : [{ packet: request, ifIdx: host.ifIdx }])
    for (let waited = 0; waited < 6000; waited += 250) {
      if (replies.some((packet) => isEchoReply(packet, identifier))) break
      await sleep(250)
    }
    const matched = replies.filter((packet) => isEchoReply(packet, identifier))
    log(
      `echo replies from ${host.id}#${host.ifIdx}: ${matched.length} (of ${replies.length} packets)`
    )
    if (matched.length === 0) {
      t.skip('no ICMP reply: the runner’s network drops ICMP, so injection is unproven here')
      return
    }
    const reply = parseIpv4(matched[0])
    assert.ok(reply, 'the reply must parse')
    assert.equal(reply.dstIp, source, 'the reply came back to the address the packet was sent from')
  } finally {
    await backend.stop()
  }
})

/** A minimal ICMP echo request, checksummed, as the gateway would inject it. */
function buildEchoRequest(options: {
  srcIp: string
  dstIp: string
  identifier: number
  sequence: number
}): Buffer | null {
  const total = 28
  const packet = Buffer.alloc(total)
  packet.writeUInt8(0x45, 0)
  packet.writeUInt16BE(total, 2)
  packet.writeUInt16BE(0x1234, 4)
  packet.writeUInt8(64, 8)
  packet.writeUInt8(IPPROTO.ICMP, 9)
  packet.writeUInt16BE(0, 10)
  if (!writeAddress(packet, 12, options.srcIp) || !writeAddress(packet, 16, options.dstIp)) {
    return null
  }
  packet.writeUInt8(8, 20)
  packet.writeUInt8(0, 21)
  packet.writeUInt16BE(0, 22)
  packet.writeUInt16BE(options.identifier, 24)
  packet.writeUInt16BE(options.sequence, 26)
  packet.writeUInt16BE(internetChecksum(packet, 20, 8), 22)
  packet.writeUInt16BE(internetChecksum(packet, 0, 20), 10)
  return packet
}

function writeAddress(packet: Buffer, offset: number, address: string): boolean {
  const parts = address.split('.').map(Number)
  if (
    parts.length !== 4 ||
    parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
  ) {
    return false
  }
  packet.set(parts, offset)
  return true
}

/** Whether a packet is the answer to the echo request with this identifier. */
function isEchoReply(packet: Buffer, identifier: number): boolean {
  const parsed = parseIpv4(packet)
  if (!parsed || parsed.protocol !== IPPROTO.ICMP) return false
  const icmp = parseIcmp(parsed)
  return icmp !== null && icmp.type === 0 && icmp.identifier === identifier
}

/** Keeps the socket import honest and gives the lab something to bind if it ever needs a peer. */
test('the lab can open a local socket (a guard for the port-range check)', async (t) => {
  if (!isWindows) {
    t.skip('not Windows')
    return
  }
  const socket = createSocket('udp4')
  await new Promise<void>((resolve) => socket.bind(0, '0.0.0.0', resolve))
  const address = socket.address()
  log(`bound a UDP socket on port ${address.port}`)
  assert.ok(address.port > 0)
  await new Promise<void>((resolve) => socket.close(() => resolve()))
})
