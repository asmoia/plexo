import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  choicesFrom,
  LinkHealth,
  pickUplink,
  type LinkHealthSample
} from '../../src/main/gateway/health.ts'

const T0 = 1_700_000_000_000
const SECOND = 1000

/** Runs `seconds` of 1 Hz sampling with `each` applied first, as the service's ticker does. */
function run(
  links: Record<string, LinkHealth>,
  seconds: number,
  each: (now: number) => void,
  start = T0
): { samples: Record<string, LinkHealthSample>; at: number } {
  let samples: Record<string, LinkHealthSample> = {}
  let now = start
  for (let second = 0; second < seconds; second++) {
    now += SECOND
    each(now)
    samples = {}
    for (const [id, health] of Object.entries(links)) samples[id] = health.sample(now)
  }
  return { samples, at: now }
}

test('a link earns its weight from the throughput it carries, and a slow one gets a smaller share', () => {
  const wifi = new LinkHealth('Wi-Fi', {}, T0)
  const usb = new LinkHealth('Ethernet 3', {}, T0)
  wifi.setConnected(true)
  usb.setConnected(true)

  // Wi-Fi carries 8 MB/s, USB 2 MB/s, while both answer their probes.
  const { samples } = run({ wifi, usb }, 40, (now) => {
    wifi.addBytes(8_000_000)
    usb.addBytes(2_000_000)
    wifi.observeProbe({ ok: true, rttMs: 20 }, now)
    usb.observeProbe({ ok: true, rttMs: 60 }, now)
  })
  assert.equal(samples.wifi.phase, 'up')
  assert.equal(samples.usb.phase, 'up')
  const choices = choicesFrom([samples.wifi, samples.usb])
  const wifiShare = choices.find((choice) => choice.id === 'Wi-Fi')?.weight ?? 0
  const usbShare = choices.find((choice) => choice.id === 'Ethernet 3')?.weight ?? 0
  assert.ok(wifiShare > 0.65 && wifiShare < 0.9, `Wi-Fi share was ${wifiShare.toFixed(2)}`)
  assert.ok(usbShare > 0.1, 'the slow link still carries some flows')
  assert.ok(Math.abs(wifiShare + usbShare - 1) < 1e-9, 'shares are normalised')
})

test('an idle link does not collapse: capacity has a long memory', () => {
  const wifi = new LinkHealth('Wi-Fi', {}, T0)
  wifi.setConnected(true)
  const busy = run({ wifi }, 30, (now) => {
    wifi.addBytes(10_000_000)
    wifi.observeProbe({ ok: true, rttMs: 15 }, now)
  })
  assert.equal(busy.samples.wifi.phase, 'up')
  const capacityWhenBusy = busy.samples.wifi.capacityBps
  // Now nothing arrives for 20 seconds — the console is idle, not the link dead.
  const idle = run({ wifi }, 20, (now) => wifi.observeProbe({ ok: true, rttMs: 15 }, now), busy.at)
  assert.equal(idle.samples.wifi.phase, 'up')
  assert.ok(
    idle.samples.wifi.capacityBps > capacityWhenBusy * 0.8,
    'a few idle seconds must not make a link look slow'
  )
  assert.ok(idle.samples.wifi.weight > 0, 'an idle but healthy link stays usable')
})

test('a two-second probe failure does not move any flows', () => {
  const wifi = new LinkHealth('Wi-Fi', { downAfterMs: 4000, upAfterMs: 2000 }, T0)
  wifi.setConnected(true)
  const warm = run({ wifi }, 10, (now) => {
    wifi.addBytes(5_000_000)
    wifi.observeProbe({ ok: true, rttMs: 20 }, now)
  })
  assert.equal(warm.samples.wifi.phase, 'up')
  const weightBefore = warm.samples.wifi.weight
  const blip = run(
    { wifi },
    2,
    (now) => wifi.observeProbe({ ok: false, rttMs: null }, now),
    warm.at
  )
  assert.notEqual(blip.samples.wifi.phase, 'down', 'a short dip is not an outage')
  assert.ok(
    blip.samples.wifi.weight >= weightBefore * 0.5,
    'nor a reason to shed most of its flows'
  )
})

test('sustained failure demotes the link and stops new flows going to it', () => {
  const wifi = new LinkHealth('Wi-Fi', { downAfterMs: 4000, upAfterMs: 2000 }, T0)
  wifi.setConnected(true)
  const warm = run({ wifi }, 10, (now) => {
    wifi.addBytes(5_000_000)
    wifi.observeProbe({ ok: true, rttMs: 20 }, now)
  })
  const down = run(
    { wifi },
    8,
    (now) => wifi.observeProbe({ ok: false, rttMs: null }, now),
    warm.at
  )
  assert.equal(down.samples.wifi.phase, 'down')
  assert.equal(down.samples.wifi.weight, 0)
  assert.equal(down.samples.wifi.downReason, 'unreachable')
})

test('a recovered link is probed before it takes traffic again', () => {
  const wifi = new LinkHealth('Wi-Fi', { downAfterMs: 4000, upAfterMs: 2000 }, T0)
  wifi.setConnected(true)
  const warm = run({ wifi }, 10, (now) => wifi.observeProbe({ ok: true, rttMs: 20 }, now))
  const down = run(
    { wifi },
    8,
    (now) => wifi.observeProbe({ ok: false, rttMs: null }, now),
    warm.at
  )
  assert.equal(down.samples.wifi.phase, 'down')
  // One good probe is not enough; a couple of seconds of them are.
  const recovering = run(
    { wifi },
    1,
    (now) => wifi.observeProbe({ ok: true, rttMs: 25 }, now),
    down.at
  )
  assert.notEqual(recovering.samples.wifi.phase, 'up')
  const recovered = run(
    { wifi },
    5,
    (now) => wifi.observeProbe({ ok: true, rttMs: 25 }, now),
    recovering.at
  )
  assert.equal(recovered.samples.wifi.phase, 'up')
  assert.ok(recovered.samples.wifi.weight > 0)
})

test('an unplugged adapter is out at once, whatever the probes said', () => {
  const usb = new LinkHealth('Ethernet 3', {}, T0)
  usb.setConnected(true)
  const warm = run({ usb }, 10, (now) => {
    usb.addBytes(4_000_000)
    usb.observeProbe({ ok: true, rttMs: 30 }, now)
  })
  assert.ok(warm.samples.usb.weight > 0)
  usb.setConnected(false)
  const sample = usb.sample(warm.at + SECOND)
  assert.equal(sample.phase, 'down')
  assert.equal(sample.weight, 0)
  assert.equal(sample.downReason, 'disconnected')
})

test('disabling an uplink takes it out without pretending it is broken', () => {
  const usb = new LinkHealth('Ethernet 3', {}, T0)
  usb.setConnected(true)
  run({ usb }, 10, (now) => {
    usb.addBytes(4_000_000)
    usb.observeProbe({ ok: true, rttMs: 30 }, now)
  })
  usb.setEnabled(false)
  const sample = usb.sample(T0 + 60_000)
  assert.equal(sample.phase, 'disabled')
  assert.equal(sample.weight, 0)
  assert.equal(sample.downReason, 'disabled')
  usb.setEnabled(true)
  const reenabled = usb.sample(T0 + 61_000)
  assert.equal(reenabled.phase, 'probing', 're-enabling starts it probing, not trusted')
  const confirmed = run(
    { usb },
    4,
    (now) => usb.observeProbe({ ok: true, rttMs: 30 }, now),
    T0 + 61_000
  )
  assert.equal(confirmed.samples.usb.phase, 'up')
  assert.ok(confirmed.samples.usb.weight > 0)
})

test('a lossy link keeps a smaller share than a clean one of the same speed', () => {
  const clean = new LinkHealth('Wi-Fi', {}, T0)
  const lossy = new LinkHealth('Ethernet 3', {}, T0)
  clean.setConnected(true)
  lossy.setConnected(true)
  const { samples } = run({ clean, lossy }, 60, (now) => {
    clean.addBytes(4_000_000)
    lossy.addBytes(4_000_000)
    clean.observeProbe({ ok: true, rttMs: 25 }, now)
    // Two in five probes fail: a link that is up but unreliable.
    lossy.observeProbe({ ok: now % 5000 > 2000, rttMs: 25 }, now)
  })
  assert.ok(
    samples.clean.weight > samples.lossy.weight,
    'loss must shrink a link’s share even at equal throughput'
  )
  assert.equal(samples.lossy.phase === 'degraded' || samples.lossy.phase === 'up', true)
})

test('a timed download measures capacity, which is what gives an idle link a fair weight', () => {
  const wifi = new LinkHealth('Wi-Fi', {}, T0)
  const usb = new LinkHealth('Ethernet 3', {}, T0)
  wifi.setConnected(true)
  usb.setConnected(true)
  const { samples } = run({ wifi, usb }, 10, (now) => {
    // Nothing forwarded yet: the only evidence is what the prober measured.
    wifi.observeProbe({ ok: true, rttMs: 18, bytes: 2_000_000, durationMs: 160 }, now) // 12.5 MB/s
    usb.observeProbe({ ok: true, rttMs: 40, bytes: 500_000, durationMs: 250 }, now) // 2 MB/s
  })
  assert.ok(samples.wifi.capacityBps > samples.usb.capacityBps)
  const picked = pickUplink('6:192.168.77.10:40000', [samples.wifi, samples.usb])
  assert.ok(picked === 'Wi-Fi' || picked === 'Ethernet 3')
})

test('a manual weight overrides the measured share, but cannot resurrect a dead link', () => {
  const wifi = new LinkHealth('Wi-Fi', {}, T0)
  const usb = new LinkHealth('Ethernet 3', { downAfterMs: 2000 }, T0)
  wifi.setConnected(true)
  usb.setConnected(true)
  const warm = run({ wifi, usb }, 10, (now) => {
    wifi.addBytes(9_000_000)
    usb.addBytes(1_000_000)
    wifi.observeProbe({ ok: true, rttMs: 20 }, now)
    usb.observeProbe({ ok: true, rttMs: 90 }, now)
  })
  const overridden = pickUplink('6:192.168.77.10:40001', Object.values(warm.samples), {
    'Ethernet 3': 0
  })
  assert.equal(overridden, 'Wi-Fi', 'a zero override takes the link out of new-flow balancing')

  const dead = run(
    { wifi, usb },
    6,
    (now) => {
      wifi.observeProbe({ ok: true, rttMs: 20 }, now)
      usb.observeProbe({ ok: false, rttMs: null }, now)
    },
    warm.at
  )
  assert.equal(dead.samples.usb.weight, 0)
  for (let index = 0; index < 200; index++) {
    assert.notEqual(
      pickUplink(`6:192.168.77.10:${index}`, Object.values(dead.samples), { 'Ethernet 3': 100 }),
      'Ethernet 3'
    )
  }
})
