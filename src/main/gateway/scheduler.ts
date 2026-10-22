/**
 * Choosing which uplink a new flow leaves through.
 *
 * The requirement is "maximise download speed and stability", and those pull in opposite
 * directions:
 *
 *  - Speed comes from sending each new flow to the uplink with the most headroom, so a fast link
 *    carries more of the console's connections than a slow one.
 *  - Stability comes from never moving a flow that is already working. Moving a TCP connection
 *    breaks it; moving a UDP association changes the public address the game server is sending
 *    to. So the choice must depend only on the flow's identity and the current weights — never on
 *    how many flows each link already has, whether they were opened a second ago, or the order in
 *    which the gateway saw them.
 *
 * Weighted rendezvous hashing ("highest random weight") gives exactly that. Each (link, flow) pair
 * gets a pseudo-random score derived from both, and the highest score wins. Consequences a load
 * balancer would want anyway fall out of it:
 *
 *  - A link's share of flows follows its weight: with weights 3:1, roughly 75% of new flows go to
 *    the fast link. That share is measured in flows, and each flow is then free to saturate its own
 *    link, so the aggregate follows the capacity ratio.
 *  - When a link's weight drops to zero (it went down, or lost its address) exactly the flows that
 *    were on it move. Every other flow keeps its link, and therefore its NAT mapping and its
 *    connection. Moving a weight from 0.7 to 0.5 moves a proportionate slice, not everything.
 *  - No shared state: two gateway instances with the same weights make the same choices, so a
 *    restart does not reshuffle live connections.
 */

import { unitInterval } from './flow'

export interface UplinkChoice {
  /** Interface id, which is also what the NAT stores on a mapping. */
  id: string
  /**
   * Relative share of new flows, ≥ 0. 0 means "do not use". The caller gets these from link
   * health (measured capacity, loss, RTT) or from the user's manual override.
   */
  weight: number
}

/**
 * The uplink a flow should leave through, or null when no uplink may be used at all.
 *
 * `flowKey` is any stable string for the flow (see flow.ts's flowId): the same flow and the same
 * weights always give the same answer.
 */
export function selectUplink(flowKey: string, links: readonly UplinkChoice[]): string | null {
  let best: string | null = null
  let bestScore = -Infinity
  for (const link of links) {
    if (!(link.weight > 0)) continue
    // -w / ln(u): the classic weighted rendezvous score. u → 0 pushes the score to +∞, so no link
    // can be starved entirely by an unlucky hash, and P(link wins) ∝ its weight.
    const score = -link.weight / Math.log(unitInterval(link.id, flowKey))
    if (score > bestScore) {
      bestScore = score
      best = link.id
    }
  }
  return best
}

/**
 * The share of new flows each link should take, for display and for judging the balancer: the
 * weights normalised to sum to 1. Links that may not be used are absent.
 */
export function expectedShares(links: readonly UplinkChoice[]): Map<string, number> {
  const usable = links.filter((link) => link.weight > 0)
  const total = usable.reduce((sum, link) => sum + link.weight, 0)
  const shares = new Map<string, number>()
  if (total <= 0) return shares
  for (const link of usable) shares.set(link.id, link.weight / total)
  return shares
}

/**
 * How well a set of choices matches the intended shares, as the largest absolute difference
 * between an observed share and an expected one. The tests use it to assert the balancer is fair;
 * on a live gateway it is a useful health number ("is the 3:1 split actually happening?").
 */
export function fairnessGap(
  counts: ReadonlyMap<string, number>,
  links: readonly UplinkChoice[]
): number {
  const expected = expectedShares(links)
  const total = [...counts.values()].reduce((sum, count) => sum + count, 0)
  if (total === 0 || expected.size === 0) return 0
  let gap = 0
  for (const [id, share] of expected) {
    const observed = (counts.get(id) ?? 0) / total
    gap = Math.max(gap, Math.abs(observed - share))
  }
  // A share that landed on a link which should have had none is a full miss.
  for (const id of counts.keys()) {
    if (!expected.has(id) && (counts.get(id) ?? 0) > 0) gap = Math.max(gap, 1)
  }
  return gap
}
