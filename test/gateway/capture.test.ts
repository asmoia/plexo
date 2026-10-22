import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  buildFilter,
  buildUplinkFilter,
  decodeAddress,
  encodeAddress,
  WINDIVERT_ADDRESS_SIZE,
  WINDIVERT_EVENT_NETWORK_PACKET,
  WINDIVERT_LAYER
} from '../../src/main/gateway/backends/windivertAddress.ts'
import { CaptureLoop, type LoopConfig } from '../../src/main/gateway/backends/winDivertLoop.ts'
import type {
  ReceivedPacket,
  RecvResult,
  WinDivertDriver
} from '../../src/main/gateway/backends/winDivertDriver.ts'
import { openTransport } from '../../src/main/gateway/backends/winDivertTransport.ts'

test('a send address puts the interface index where WinDivert reads it', () => {
  const encoded = encodeAddress({ ifIdx: 12 })
  assert.equal(encoded.length, WINDIVERT_ADDRESS_SIZE)
  const decoded = decodeAddress(encoded)
  assert.equal(decoded.ifIdx, 12, 'this field is what pins a flow to an uplink')
  assert.equal(decoded.outbound, true, 'forwarding is always an outbound injection')
  assert.equal(decoded.ipv6, false)
  assert.equal(decoded.layer, WINDIVERT_LAYER.NETWORK)
  assert.equal(decoded.event, WINDIVERT_EVENT_NETWORK_PACKET)
})

test('the address layout is WinDivert 2.2.2’s, which is the version this app ships', () => {
  // Pinned field by field, because the layout changed between WinDivert 1.4 and 2.x and getting it
  // wrong is invisible: the earlier 1.4 layout made every captured packet decode with interface
  // index 0, and a 64-byte buffer was 16 bytes too small for the driver to write into.
  assert.equal(WINDIVERT_ADDRESS_SIZE, 80, 'sizeof(WINDIVERT_ADDRESS) in 2.2.2')
  const encoded = encodeAddress({ ifIdx: 14 })
  assert.equal(encoded.length, 80)
  assert.equal(encoded.readUInt32LE(8) & 0xff, WINDIVERT_LAYER.NETWORK, 'Layer at offset 8')
  assert.equal(encoded.readUInt32LE(12), 0, 'Reserved2 at offset 12 stays zero')
  assert.equal(encoded.readUInt32LE(16), 14, 'IfIdx at offset 16, inside the union')
  assert.equal(encoded.readUInt32LE(20), 0, 'SubIfIdx at offset 20')
  // A network-layer address as the driver would fill it: timestamp, flags, reserved, then the union.
  const filled = Buffer.alloc(80)
  filled.writeBigInt64LE(1_700_000_000_000_000n, 0)
  filled.writeUInt32LE(0 | (1 << 17), 8)
  filled.writeUInt32LE(0, 12)
  filled.writeUInt32LE(7, 16)
  filled.writeUInt32LE(0, 20)
  assert.equal(decodeAddress(filled).ifIdx, 7)
  assert.equal(decodeAddress(filled).outbound, true)
})

test('flags come back out of an address as they went in', () => {
  const encoded = encodeAddress({ ifIdx: 3, outbound: false, ipv6: true, checksumsValid: true })
  const decoded = decodeAddress(encoded)
  assert.equal(decoded.outbound, false)
  assert.equal(decoded.ipv6, true)
  assert.equal(decoded.ipChecksum, true)
  assert.equal(decoded.tcpChecksum, true)
  assert.equal(decoded.udpChecksum, true)
  assert.equal(decoded.ifIdx, 3)
})

test('an address filled by a driver parses, including its timestamp and layer', () => {
  const buffer = Buffer.alloc(WINDIVERT_ADDRESS_SIZE)
  buffer.writeBigInt64LE(1_700_000_000_123n, 0)
  // layer 0, event 0, sniffed, outbound and ipv6 set
  buffer.writeUInt32LE(0 | (1 << 16) | (1 << 17) | (1 << 20), 8)
  buffer.writeUInt32LE(0, 12)
  buffer.writeUInt32LE(9, 16)
  const decoded = decodeAddress(buffer)
  assert.equal(decoded.timestamp, 1_700_000_000_123n)
  assert.equal(decoded.sniffed, true)
  assert.equal(decoded.outbound, true)
  assert.equal(decoded.ipv6, true)
  assert.equal(decoded.ifIdx, 9)
})

test('filters are per interface and per direction, IPv4 only, loopback excluded', () => {
  assert.equal(
    buildFilter({ ifIdx: 7, direction: 'inbound' }),
    'inbound and ifIdx == 7 and ip and not loopback'
  )
  assert.equal(
    buildFilter({ ifIdx: 7, direction: 'outbound' }),
    'outbound and ifIdx == 7 and ip and not loopback'
  )
  assert.equal(buildFilter({ ifIdx: 7, direction: 'both' }), 'ifIdx == 7 and ip and not loopback')
})

/** A driver that hands over a scripted list of packets and then reports "stopped". */
class FakeDriver implements WinDivertDriver {
  readonly opened: { filter: string; flags: number }[] = []
  readonly sent: { packet: Buffer; ifIdx: number }[] = []
  closed = 0
  shutdowns = 0
  private queue: ReceivedPacket[]
  private stopped = false
  private error = 'no error'
  /** How many idle reads to report before the script runs out and it aborts. */
  private idleBudget: number

  constructor(packets: ReceivedPacket[] = [], idleReads = 0) {
    this.queue = [...packets]
    this.idleBudget = idleReads
  }

  open(filter: string, flags: number): number {
    this.opened.push({ filter, flags })
    return this.opened.length
  }

  recv(handle: number): RecvResult {
    void handle
    if (this.stopped) return { kind: 'aborted' }
    const next = this.queue.shift()
    if (next) return { kind: 'packet', received: next }
    if (this.idleBudget > 0) {
      // Behave like the real driver on an idle connection: nothing to deliver, and that is all.
      this.idleBudget--
      return { kind: 'idle' }
    }
    // The script is exhausted: end the loop the way a shutdown does, not by failing.
    this.stopped = true
    return { kind: 'aborted' }
  }

  send(handle: number, packet: Buffer, ifIdx: number): boolean {
    void handle
    this.sent.push({ packet: Buffer.from(packet), ifIdx })
    return true
  }

  setQueue(): void {
    // Queue sizing is a driver detail; nothing to record.
  }

  shutdown(): void {
    this.shutdowns++
    this.stopped = true
  }

  close(): void {
    this.closed++
  }

  lastError(): string {
    return this.error
  }
}

const CONFIG: LoopConfig = {
  downstreamIfIdx: 3,
  uplinks: [
    { ifIdx: 7, id: 'Wi-Fi' },
    { ifIdx: 12, id: 'Ethernet 3' }
  ],
  publicPorts: { min: 20_000, max: 29_999 }
}

function packet(ifIdx: number, body = 'x'): ReceivedPacket {
  return { packet: Buffer.from(body), ifIdx, ipv6: false, checksumsValid: false }
}

test('the loop opens the filters it was configured for, and a send-only handle for injection', () => {
  const driver = new FakeDriver([])
  const loop = new CaptureLoop(driver, CONFIG, { outbound: () => {}, inbound: () => {} })
  loop.open()
  assert.equal(driver.opened.length, 2, 'one receive handle and one send handle')
  assert.equal(driver.opened[0].filter, loop.filter())
  assert.match(driver.opened[0].filter, /ifIdx == 3/)
  assert.match(driver.opened[0].filter, /ifIdx == 7/)
  assert.match(driver.opened[0].filter, /ifIdx == 12/)
  assert.equal(driver.opened[1].filter, 'false', 'the send handle must match nothing')
  loop.close()
  assert.equal(driver.closed, 2)
})

test('an uplink is captured only for the gateway’s own ports, never for the PC’s traffic', () => {
  // This is the difference between a gateway and a machine that has lost its internet: a capture
  // handle that matched the whole adapter would take the PC's own traffic off the stack.
  const filter = buildUplinkFilter({ ifIdx: 7, minPort: 20_000, maxPort: 29_999 })
  assert.match(filter, /tcp\.DstPort >= 20000/)
  assert.match(filter, /tcp\.DstPort <= 29999/)
  assert.match(filter, /udp\.DstPort >= 20000/)
  assert.match(filter, /ifIdx == 7/)
  assert.match(filter, /inbound/)

  // The console's own port is taken whole: that cable carries nothing but the console.
  const downstream = buildFilter({ ifIdx: 3, direction: 'inbound' })
  assert.equal(downstream, 'inbound and ifIdx == 3 and ip and not loopback')

  // And the assembled filter keeps the two apart per interface.
  const loop = new CaptureLoop(new FakeDriver([]), CONFIG, {
    outbound: () => {},
    inbound: () => {}
  })
  const assembled = loop.filter()
  assert.ok(
    assembled.startsWith('inbound and ifIdx == 3 and ip and not loopback or '),
    `the console clause comes first and has no port restriction: ${assembled}`
  )
  // The port alternatives contain "or" of their own, so count interfaces rather than clauses.
  for (const ifIdx of [7, 12]) {
    assert.equal(
      assembled.split(`ifIdx == ${ifIdx}`).length - 1,
      1,
      `uplink ${ifIdx} must appear exactly once`
    )
  }
  for (const segment of assembled.split('ifIdx').slice(1)) {
    if (segment.startsWith(' == 3')) {
      assert.doesNotMatch(
        segment.split(' or ifIdx')[0],
        /DstPort/,
        'the console is not port-limited'
      )
    } else {
      assert.match(
        segment.split(' or ifIdx')[0],
        /DstPort >= 20000/,
        'every uplink is port-limited'
      )
    }
  }
  assert.equal(assembled.split('DstPort >= 20000').length - 1, 4, 'tcp and udp, on both uplinks')
})

test('an idle connection never stops the capture, however long it stays idle', () => {
  // A console on the dashboard sends nothing for minutes. Giving up after a few empty reads — as
  // the first version did after 100 ms — shut the gateway down exactly when it was working.
  const handled: string[] = []
  const driver = new FakeDriver([packet(3, 'late')], 200)
  const loop = new CaptureLoop(driver, CONFIG, {
    outbound: (bytes) => handled.push(bytes.toString()),
    inbound: () => {}
  })
  loop.run()
  assert.deepEqual(handled, ['late'], 'the packet after 200 idle reads still arrives')
  assert.ok(
    loop.report().idleReads >= 200,
    'ten times the old give-up threshold, and it kept going'
  )
})

test('a read that fails five times in a row ends the loop with the driver’s reason', () => {
  const driver = new FakeDriver([])
  let reads = 0
  driver.recv = () => {
    reads++
    return { kind: 'error', message: 'The handle is invalid' } as RecvResult
  }
  const loop = new CaptureLoop(driver, CONFIG, { outbound: () => {}, inbound: () => {} })
  loop.run()
  assert.equal(reads, 5, 'a transient error is retried, a permanent one is not')
  assert.match(loop.report().lastError ?? '', /handle is invalid/)
  assert.equal(driver.closed, 2, 'the handles are closed even when the driver misbehaves')
})

test('packets are dispatched by the interface they arrived on', () => {
  const outbound: Buffer[] = []
  const inbound: { ifIdx: number; body: string }[] = []
  const driver = new FakeDriver([packet(3, 'console'), packet(7, 'wifi'), packet(12, 'usb')])
  const loop = new CaptureLoop(driver, CONFIG, {
    outbound: (bytes) => outbound.push(bytes),
    inbound: (bytes, ifIdx) => inbound.push({ ifIdx, body: bytes.toString() })
  })
  loop.run()
  assert.deepEqual(
    outbound.map((bytes) => bytes.toString()),
    ['console'],
    'only the console’s port is the downstream'
  )
  assert.deepEqual(inbound, [
    { ifIdx: 7, body: 'wifi' },
    { ifIdx: 12, body: 'usb' }
  ])
  assert.equal(loop.report().received, 3)
})

test('an IPv6 packet is never forwarded, and is counted as dropped', () => {
  const handled: string[] = []
  const driver = new FakeDriver([
    { packet: Buffer.from('v6'), ifIdx: 3, ipv6: true, checksumsValid: false }
  ])
  const loop = new CaptureLoop(driver, CONFIG, {
    outbound: (bytes) => handled.push(bytes.toString()),
    inbound: () => {}
  })
  loop.run()
  assert.deepEqual(handled, [], 'IPv6 is not translated, so it must not be relayed untranslated')
  assert.equal(loop.report().dropped, 1)
})

test('sending goes out of the interface the engine chose', () => {
  const driver = new FakeDriver([])
  const loop = new CaptureLoop(driver, CONFIG, { outbound: () => {}, inbound: () => {} })
  loop.open()
  loop.send([
    { packet: Buffer.from('one'), ifIdx: 7 },
    { packet: Buffer.from('two'), ifIdx: 12 },
    { packet: Buffer.from('three'), ifIdx: 3 }
  ])
  assert.deepEqual(
    driver.sent.map((entry) => [entry.packet.toString(), entry.ifIdx]),
    [
      ['one', 7],
      ['two', 12],
      ['three', 3]
    ]
  )
  assert.equal(loop.report().sent, 3)
})

test('stop() unblocks the receive, closes the handles, and the loop ends', () => {
  const driver = new FakeDriver([packet(3, 'a'), packet(3, 'b')])
  const handled: string[] = []
  const loop = new CaptureLoop(driver, CONFIG, {
    outbound: (bytes) => {
      handled.push(bytes.toString())
      loop.stop()
    },
    inbound: () => {}
  })
  loop.run()
  assert.deepEqual(handled, ['a'], 'no packet is processed after stop')
  assert.equal(driver.shutdowns, 1)
  assert.equal(driver.closed, 2, 'both handles are closed')
})

test('a driver that fails is reported, not crashed on', () => {
  const driver = new FakeDriver([])
  driver.recv = () => {
    throw new Error('The handle is invalid')
  }
  const loop = new CaptureLoop(driver, CONFIG, { outbound: () => {}, inbound: () => {} })
  loop.run()
  assert.equal(loop.report().lastError, 'The handle is invalid')
  assert.equal(driver.closed, 2, 'the handles are closed even when the driver misbehaves')
})

/**
 * The transport: how the capture process reaches the app.
 *
 * This is the bug that shipped in the first Windows build. The process was written for Electron's
 * `utilityProcess` (`process.parentPort`) while being spawned with `child_process` (`process.send`).
 * `parentPort` was undefined, the first post threw, and the process exited with code 1 before it
 * could say anything — so the app reported "the driver may have been stopped" and every counter sat
 * at zero, with a driver that was perfectly healthy.
 */
test('the capture process uses child_process IPC when that is the channel it was given', () => {
  const sent: unknown[] = []
  let listener: ((message: unknown) => void) | null = null
  const transport = openTransport({
    send: (message) => sent.push(message),
    on: (event, callback) => {
      assert.equal(event, 'message')
      listener = callback
    }
  })
  transport.send({ type: 'ready', filter: 'x' })
  assert.deepEqual(sent, [{ type: 'ready', filter: 'x' }])
  const received: unknown[] = []
  transport.receive((message) => received.push(message))
  listener?.({ type: 'stop' })
  assert.deepEqual(received, [{ type: 'stop' }])
})

test('Electron’s parentPort is used when present, unwrapping its event object', () => {
  const sent: unknown[] = []
  let listener: ((event: { data: unknown }) => void) | null = null
  const transport = openTransport({
    parentPort: {
      postMessage: (message) => sent.push(message),
      on: (event, callback) => {
        assert.equal(event, 'message')
        listener = callback
      }
    }
  })
  transport.send({ type: 'ready', filter: 'x' })
  assert.deepEqual(sent, [{ type: 'ready', filter: 'x' }])
  const received: unknown[] = []
  transport.receive((message) => received.push(message))
  listener?.({ data: { type: 'stop' } })
  assert.deepEqual(received, [{ type: 'stop' }], 'the payload, not the wrapper')
})

test('a process with no channel fails loudly instead of dying silently', () => {
  assert.throws(() => openTransport({}), /without an IPC channel/)
  // `send` without `on` is not a channel either: half of one would drop every inbound message and
  // leave the gateway unable to be stopped.
  assert.throws(() => openTransport({ send: () => {} }), /without an IPC channel/)
})
