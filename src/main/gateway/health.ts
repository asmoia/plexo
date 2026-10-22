/**
 * How good each uplink is right now, and therefore how much of the console's traffic it should get.
 *
 * Two failure modes this has to avoid, because both are visible as "the connection feels broken"
 * rather than as a number in a chart:
 *
 *  - **Flapping.** A mobile link whose signal dips for two seconds must not lose all its flows and
 *    get them back a second later: every TCP connection on it would break twice. So a link is only
 *    demoted after `downAfterMs` of continuous failure, promoted again only after `upAfterMs` of
 *    continuous success, and its weight moves toward its target by at most a few percent per
 *    second. Weights are a slow, damped signal; packet loss is a fast one.
 *  - **Collapse.** A link that is idle (nothing to carry) must not look like a link that is dead,
 *    or the balancer migrates every flow off it and back. Capacity is therefore a long-memory
 *    estimate — what this link has been observed to do — not the instantaneous byte rate, and it
 *    decays over minutes rather than seconds.
 *
 * The score is `capacity × quality × availability`:
 *  - capacity: the best throughput this link has recently shown, from forwarded bytes and from
 *    the prober's timed downloads (which is what gives an idle link a capacity at all);
 *  - quality: `(1 − loss) × (referenceRtt / max(referenceRtt, rtt))^0.35`. Loss is punished hard
 *    because it costs more than it looks: a lost packet costs a retransmit timeout, not just the
 *    packet. Latency only mildly — a 40 ms link and a 20 ms link carry a download about equally
 *    well, and over-weighting RTT would push every flow onto the mobile link's instability.
 *  - availability: how much of the recent past the link answered its probes.
 */

import { selectUplink, type UplinkChoice } from './scheduler'
import type { LinkPhase } from '../../shared/gateway'

/** Bytes per second, floored at 1 Mbit/s: an unmeasured link starts as a plausible slow link. */
const MIN_CAPACITY_BPS = 125_000
/** A link that has never carried anything is still worth trying; this is its starting capacity. */
const INITIAL_CAPACITY_BPS = 5_000_000
const REFERENCE_RTT_MS = 25
const RTT_EXPONENT = 0.35
/** Per second, toward the newest measurement. */
const THROUGHPUT_SMOOTHING = 0.25
/** Capacity keeps the best of the last few minutes rather than the newest sample. */
const CAPACITY_DECAY_PER_SECOND = 0.997
const LOSS_SMOOTHING = 0.15
/** Largest change of the weight per second, as a fraction of the full 0..1 range. */
const MAX_WEIGHT_STEP_PER_SECOND = 0.08

/** One probe's result, as the prober reports it (see prober.ts) and health consumes it. */
export interface ProbeSample {
  ok: boolean
  /** The instant the probe started. */
  at: number
  /** Time to the first byte, null when nothing came back. */
  rttMs: number | null
  /** Bytes received, for a throughput sample. */
  bytes: number
  /** How long the whole probe took. */
  durationMs: number
  detail?: string
}

export interface LinkHealthOptions {
  downAfterMs?: number
  upAfterMs?: number
  referenceRttMs?: number
}

export interface LinkHealthSample {
  id: string
  phase: LinkPhase
  connected: boolean
  enabled: boolean
  /** Bytes/s over the last sampling interval, both directions. */
  throughputBps: number
  /** What this link has been measured to sustain. */
  capacityBps: number
  rttMs: number | null
  /** 0..1 over the recent past. */
  loss: number
  /** Share of new flows this link should take; 0 when it must not be used. */
  weight: number
  /** Why it is not being used, when it is not. */
  downReason: 'disabled' | 'disconnected' | 'unreachable' | null
  probes: number
  probeFailures: number
}

export class LinkHealth {
  private enabled = true
  private connected = false
  private lastSampleAt: number
  private bytesSinceSample = 0
  private throughputBps = 0
  private capacityBps = INITIAL_CAPACITY_BPS
  private rttMs: number | null = null
  private loss = 0
  private consecutiveFailures = 0
  private consecutiveSuccesses = 0
  /** When the current run of successes began, which is what `upAfterMs` is measured from. */
  private firstSuccessAt = 0
  private lastFailureAt = 0
  private lastSuccessAt = 0
  private phase: LinkPhase = 'down'
  private weight = 0
  private probes = 0
  private probeFailures = 0
  private readonly downAfterMs: number
  private readonly upAfterMs: number
  private readonly referenceRttMs: number

  constructor(
    readonly id: string,
    options: LinkHealthOptions = {},
    now = Date.now()
  ) {
    this.downAfterMs = options.downAfterMs ?? 4000
    this.upAfterMs = options.upAfterMs ?? 2000
    this.referenceRttMs = options.referenceRttMs ?? REFERENCE_RTT_MS
    this.lastSampleAt = now
  }

  /** The adapter's own state: present, up, and holding an address. */
  setConnected(connected: boolean): void {
    if (connected === this.connected) return
    this.connected = connected
    if (!connected) {
      // An adapter that vanished is a hard failure: no amount of probing makes it usable.
      this.phase = 'down'
      this.weight = 0
      this.consecutiveFailures = 0
      this.consecutiveSuccesses = 0
    } else {
      // Coming back up is a soft event: it must earn its weight back through probes.
      this.phase = 'probing'
      this.consecutiveSuccesses = 0
      this.firstSuccessAt = 0
    }
  }

  /** The user switched this uplink off (or on) for the gateway. */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled
    if (!enabled) {
      this.phase = 'disabled'
      this.weight = 0
    } else if (this.phase === 'disabled') {
      // Back on: usable at once (the user asked for it), but only a fresh probe run makes it 'up'.
      this.phase = this.connected ? 'probing' : 'down'
      this.consecutiveSuccesses = 0
      this.firstSuccessAt = 0
    }
  }

  get isEnabled(): boolean {
    return this.enabled
  }

  get currentPhase(): LinkPhase {
    return this.phase
  }

  get currentWeight(): number {
    return this.weight
  }

  /** Forwarded traffic, so an unmeasured link gets a capacity from real use rather than probes. */
  addBytes(bytes: number): void {
    this.bytesSinceSample += bytes
  }

  /**
   * A probe result. `bytes`/`durationMs` come from a timed download through this link and are what
   * give an idle link a capacity measurement; a bare reachability check passes 0 and is scored for
   * loss and RTT only.
   */
  observeProbe(
    result: { ok: boolean; rttMs: number | null; bytes?: number; durationMs?: number },
    now: number
  ): void {
    this.probes++
    if (!result.ok) {
      this.probeFailures++
      this.consecutiveFailures++
      this.consecutiveSuccesses = 0
      this.lastFailureAt = now
      this.loss = this.loss * (1 - LOSS_SMOOTHING) + LOSS_SMOOTHING
      return
    }
    if (this.consecutiveSuccesses === 0) this.firstSuccessAt = now
    this.consecutiveSuccesses++
    this.consecutiveFailures = 0
    this.lastSuccessAt = now
    this.loss = this.loss * (1 - LOSS_SMOOTHING)
    if (result.rttMs !== null) {
      // Latency is smoothed with a fast attack / slow release: a spike should be visible at once,
      // but one good sample should not hide a link that is consistently slow.
      const smoothed =
        this.rttMs === null ? result.rttMs : this.rttMs + (result.rttMs - this.rttMs) * 0.35
      this.rttMs = Math.max(this.referenceRttMs, smoothed)
    }
    if (result.bytes !== undefined && result.durationMs !== undefined && result.durationMs > 0) {
      const sample = (result.bytes * 1000) / result.durationMs
      // A timed download measures what the link actually did, so it is trusted more than bytes
      // counted from the console's own traffic, which is limited by the remote server too.
      this.capacityBps = Math.max(this.capacityBps, sample)
    }
  }

  /**
   * Folds in the seconds since the last sample and returns the link's current standing. Called on
   * a fixed cadence (the service's ticker), which is what makes the smoothing rates mean seconds.
   */
  sample(now: number): LinkHealthSample {
    const elapsed = Math.max(0, (now - this.lastSampleAt) / 1000)
    this.lastSampleAt = now

    const instantBytes = this.bytesSinceSample
    if (elapsed > 0) {
      const instantBps = instantBytes / elapsed
      this.bytesSinceSample = 0
      this.throughputBps =
        this.throughputBps + (instantBps - this.throughputBps) * THROUGHPUT_SMOOTHING
      // Forwarded traffic is a lower bound on capacity: the console got that much through, so the
      // link can do at least that. Damped, because a burst from a server's send buffer is not a
      // sustained rate.
      this.capacityBps = Math.max(
        MIN_CAPACITY_BPS,
        Math.max(
          this.capacityBps * Math.pow(CAPACITY_DECAY_PER_SECOND, elapsed),
          this.throughputBps
        )
      )
    }

    this.updatePhase(now, instantBytes)
    this.updateWeight(elapsed)

    return {
      id: this.id,
      phase: this.phase,
      connected: this.connected,
      enabled: this.enabled,
      throughputBps: this.throughputBps,
      capacityBps: this.capacityBps,
      rttMs: this.rttMs,
      loss: this.loss,
      weight: this.weight,
      downReason: this.downReason,
      probes: this.probes,
      probeFailures: this.probeFailures
    }
  }

  /** The state the phase transitions describe, exposed for the UI's "why is this link unused?". */
  get downReason(): 'disabled' | 'disconnected' | 'unreachable' | null {
    if (!this.enabled) return 'disabled'
    if (!this.connected) return 'disconnected'
    if (this.phase === 'down') return 'unreachable'
    return null
  }

  /**
   * The link's state, from streaks of probe results rather than from single ones:
   *
   *   down      — the adapter is gone, or nothing has answered for `downAfterMs`.
   *   probing   — it is recovering: something answered, but not for long enough to trust.
   *   degraded  — it answers, but recently failed: usable, at a reduced share.
   *   up        — it has answered continuously for `upAfterMs`.
   *
   * A `probing` link is still *usable*: it is what a gateway shows for the seconds after launch, and
   * holding traffic back until probes succeed would stall the console for no reason.
   */
  private updatePhase(now: number, instantBytes: number): void {
    if (!this.enabled) {
      this.phase = 'disabled'
      return
    }
    if (!this.connected) {
      this.phase = 'down'
      return
    }

    if (this.consecutiveFailures > 0) {
      // Time since the last proof that this link works, which is what an outage is measured in.
      const failingSince = this.lastSuccessAt === 0 ? this.lastFailureAt : this.lastSuccessAt
      if (now - failingSince >= this.downAfterMs) this.phase = 'down'
      else if (this.consecutiveFailures >= 2) this.phase = 'degraded'
      return
    }

    if (this.phase === 'down' || this.phase === 'degraded' || this.phase === 'probing') {
      // Carrying real traffic right now is proof enough, even with no probes configured.
      if (instantBytes > 0) {
        this.phase = 'up'
        return
      }
      // Otherwise a run of successes, spanning `upAfterMs`, earns the link back.
      if (this.consecutiveSuccesses > 0 && now - this.firstSuccessAt >= this.upAfterMs) {
        this.phase = 'up'
      } else if (this.phase !== 'down' || this.probes > 0) {
        this.phase = 'probing'
      }
      return
    }
    this.phase = 'up'
  }

  private updateWeight(elapsed: number): void {
    let target = 0
    // `probing` counts: a link that has not been measured yet is not a link that has failed.
    if (
      this.enabled &&
      this.connected &&
      (this.phase === 'up' || this.phase === 'degraded' || this.phase === 'probing')
    ) {
      const capacityScore = Math.max(MIN_CAPACITY_BPS, this.capacityBps)
      const latencyPenalty =
        this.rttMs === null
          ? 1
          : Math.pow(this.referenceRttMs / Math.max(this.referenceRttMs, this.rttMs), RTT_EXPONENT)
      // availability is folded in twice on purpose: once as loss, once as the phase already
      // requiring recent success. A degraded link keeps a share, a dead one gets none.
      const quality = (1 - Math.min(0.95, this.loss)) * latencyPenalty
      target = capacityScore * quality
      // Normalising happens across links (see below); this keeps a floor so a very slow link is
      // still chosen sometimes, which is what keeps it measured and usable as a fallback.
      target = Math.max(target, MIN_CAPACITY_BPS)
    }

    if (target === 0) {
      this.weight = 0
      return
    }
    // Weights are compared against other links' capacities, so the absolute number is meaningless
    // until normalised; step toward it in relative terms instead.
    if (this.weight === 0) {
      this.weight = target
      return
    }
    const maxStep =
      Math.max(1, this.weight) * (MAX_WEIGHT_STEP_PER_SECOND * Math.max(elapsed, 0.001))
    const delta = target - this.weight
    this.weight += Math.sign(delta) * Math.min(Math.abs(delta), maxStep)
  }
}

/**
 * Normalises a set of links' weights into the `UplinkChoice`s the scheduler takes, so the balancer
 * works on shares rather than on raw capacities (which would overflow the rendezvous score math).
 */
export function choicesFrom(samples: readonly LinkHealthSample[]): UplinkChoice[] {
  const total = samples.reduce((sum, sample) => sum + (sample.weight > 0 ? sample.weight : 0), 0)
  if (total <= 0) return samples.map((sample) => ({ id: sample.id, weight: 0 }))
  return samples.map((sample) => ({
    id: sample.id,
    weight: sample.weight > 0 ? sample.weight / total : 0
  }))
}

/** Why a sample says the link must not be used, or null when it may be. */
export function downReasonOf(
  sample: Pick<LinkHealthSample, 'enabled' | 'connected' | 'phase'>
): 'disabled' | 'disconnected' | 'unreachable' | null {
  if (!sample.enabled) return 'disabled'
  if (!sample.connected) return 'disconnected'
  if (sample.phase === 'down') return 'unreachable'
  return null
}

/** The link a flow should use, given the health samples — the one call the forwarder makes. */
export function pickUplink(
  flowKey: string,
  samples: readonly LinkHealthSample[],
  overrides: Readonly<Record<string, number>> = {}
): string | null {
  const choices = choicesFrom(samples)
  // A manual weight (the user's "use this more" slider) replaces the measured share, but only for
  // links the health layer considers usable: an override must not resurrect a dead uplink.
  const merged = choices.map((choice) => ({
    id: choice.id,
    // An override re-weights a link; it cannot bring back one the health layer has taken out
    // (weight 0 means disabled, disconnected or unreachable), so a stale override from a previous
    // session cannot route traffic into a dead adapter.
    weight:
      choice.weight > 0 && overrides[choice.id] !== undefined
        ? Math.max(0, overrides[choice.id])
        : choice.weight
  }))
  return selectUplink(flowKey, merged)
}
