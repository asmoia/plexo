import assert from 'node:assert/strict'
import { test } from 'node:test'
import fc from 'fast-check'
import {
  expectedShares,
  fairnessGap,
  selectUplink,
  type UplinkChoice
} from '../../src/main/gateway/scheduler.ts'

const links: UplinkChoice[] = [
  { id: 'Wi-Fi', weight: 0.75 },
  { id: 'Ethernet 3', weight: 0.25 }
]

function distribute(count: number, choices: readonly UplinkChoice[]): Map<string, number> {
  const counts = new Map<string, number>()
  for (let index = 0; index < count; index++) {
    const chosen = selectUplink(`6:192.168.77.10:${30000 + index}`, choices)
    assert.ok(chosen, 'every flow must be placed while an uplink is usable')
    counts.set(chosen, (counts.get(chosen) ?? 0) + 1)
  }
  return counts
}

test('the same flow and the same weights always choose the same uplink', () => {
  const first = selectUplink('6:192.168.77.10:40000', links)
  for (let attempt = 0; attempt < 100; attempt++) {
    assert.equal(selectUplink('6:192.168.77.10:40000', links), first)
  }
  // Order of the list must not matter either, or a UI reorder would migrate every connection.
  assert.equal(selectUplink('6:192.168.77.10:40000', [...links].reverse()), first)
})

test('flows are split in proportion to the weights', () => {
  const counts = distribute(20_000, links)
  const shares = expectedShares(links)
  for (const [id, share] of shares) {
    const observed = (counts.get(id) ?? 0) / 20_000
    assert.ok(
      Math.abs(observed - share) < 0.015,
      `${id}: observed ${(observed * 100).toFixed(1)}% vs ${(share * 100).toFixed(1)}%`
    )
  }
  assert.ok(fairnessGap(counts, links) < 0.015)
})

test('a 3:1 split really is three to one, and an even split really is even', () => {
  const threeToOne = distribute(10_000, [
    { id: 'Wi-Fi', weight: 3 },
    { id: 'Ethernet 3', weight: 1 }
  ])
  const ratio = (threeToOne.get('Wi-Fi') ?? 0) / (threeToOne.get('Ethernet 3') ?? 1)
  assert.ok(ratio > 2.8 && ratio < 3.2, `ratio was ${ratio.toFixed(2)}`)

  const even = distribute(10_000, [
    { id: 'Wi-Fi', weight: 1 },
    { id: 'Ethernet 3', weight: 1 }
  ])
  assert.ok(Math.abs((even.get('Wi-Fi') ?? 0) - (even.get('Ethernet 3') ?? 0)) < 300)
})

test('losing an uplink moves only the flows that were on it', () => {
  const counts = distribute(5000, links)
  const before = new Map<string, string>()
  for (let index = 0; index < 5000; index++) {
    const key = `6:192.168.77.10:${30000 + index}`
    before.set(key, selectUplink(key, links) as string)
  }
  const survived: UplinkChoice[] = [{ id: 'Wi-Fi', weight: 1 }]
  let moved = 0
  let stayed = 0
  for (const [key, was] of before) {
    const now = selectUplink(key, survived)
    if (now === was) stayed++
    else moved++
  }
  // Every flow that was on the surviving link keeps it; only the dead link's share moves.
  assert.equal(stayed, counts.get('Wi-Fi'))
  assert.equal(moved, counts.get('Ethernet 3'))
  assert.ok(moved > 0 && stayed > 0)
})

test('a weight of zero is never chosen, and no usable uplink means no answer', () => {
  const disabled: UplinkChoice[] = [
    { id: 'Wi-Fi', weight: 1 },
    { id: 'Ethernet 3', weight: 0 }
  ]
  const counts = distribute(2000, disabled)
  assert.equal(counts.get('Ethernet 3'), undefined)
  assert.equal(selectUplink('6:1.2.3.4:1', [{ id: 'Wi-Fi', weight: 0 }]), null)
  assert.equal(selectUplink('6:1.2.3.4:1', []), null)
  assert.equal(expectedShares([{ id: 'Wi-Fi', weight: 0 }]).size, 0)
})

test('property: any set of weights places every flow, and the split follows the weights', () => {
  fc.assert(
    fc.property(
      fc.array(fc.double({ min: 0.01, max: 100, noNaN: true }), { minLength: 1, maxLength: 4 }),
      fc.integer({ min: 1, max: 60_000 }),
      (weights, seed) => {
        const choices = weights.map((weight, index) => ({ id: `link-${index}`, weight }))
        const total = weights.reduce((sum, weight) => sum + weight, 0)
        const counts = new Map<string, number>()
        const samples = 4000
        for (let index = 0; index < samples; index++) {
          const chosen = selectUplink(`flow-${seed}-${index}`, choices)
          assert.ok(chosen !== null, 'a flow must always land somewhere')
          counts.set(chosen, (counts.get(chosen) ?? 0) + 1)
        }
        for (const choice of choices) {
          const expected = choice.weight / total
          const observed = (counts.get(choice.id) ?? 0) / samples
          // 4000 samples of a well-spread hash: a hard bound of 5 percentage points is generous
          // but still catches a real bias.
          assert.ok(
            Math.abs(observed - expected) < 0.05,
            `${choice.id}: ${observed.toFixed(3)} vs ${expected.toFixed(3)}`
          )
        }
      }
    ),
    { numRuns: 40 }
  )
})

test('property: removing one uplink leaves every other flow where it was', () => {
  fc.assert(
    fc.property(
      fc.integer({ min: 0, max: 3 }),
      fc.integer({ min: 1, max: 9999 }),
      (removeIndex, seed) => {
        const choices: UplinkChoice[] = ['a', 'b', 'c', 'd'].map((id) => ({ id, weight: 1 }))
        const fewer = choices.filter((_, index) => index !== removeIndex)
        for (let index = 0; index < 200; index++) {
          const key = `flow-${seed}-${index}`
          const before = selectUplink(key, choices)
          const after = selectUplink(key, fewer)
          if (before !== choices[removeIndex].id) assert.equal(after, before)
          else assert.notEqual(after, null)
        }
      }
    ),
    { numRuns: 30 }
  )
})
