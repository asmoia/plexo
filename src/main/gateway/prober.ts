/**
 * Measuring each uplink from this PC, which is what turns "two connections" into "two connections
 * of which the Wi-Fi is worth three times the phone".
 *
 * The prober makes a tiny HTTP request *bound to one uplink's address*. On Windows (and macOS)
 * binding the local address is what selects the adapter, so each request genuinely exercises that
 * path — through the router, the mobile network's NAT, and back.
 *
 * It reports three things, and each one is used differently:
 *
 *  - **Reachability**: whether the request worked at all. A link that cannot reach the internet is
 *    not an uplink, however "connected" its adapter says it is.
 *  - **RTT**: time to the first byte. Weighted only mildly — a 20 ms and a 60 ms link download at
 *    about the same rate, and the 60 ms link's stability matters more than its latency.
 *  - **Throughput**: bytes over time for a small ranged download. This is the only way an *idle*
 *    uplink is ever measured, and idle is the normal state of a link that has just been added.
 *
 * Probes are deliberately small (a few hundred kilobytes at most, and a single 204-style request
 * when throughput is not being sampled), because on a phone tethering they cost the user money.
 */

import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import type { ProbeSample } from './health'

export interface ProberOptions {
  /** A URL that answers quickly and cheaply over plain HTTP (204 no content is ideal). */
  url?: string
  /** How long the whole probe may take. */
  timeoutMs?: number
  /** Bytes to pull for a throughput sample; 0 measures RTT only. */
  sampleBytes?: number
  /** Injected by the tests, so probing can be exercised without the internet. */
  fetchSample?: (options: {
    address: string
    url: string
    timeoutMs: number
    sampleBytes: number
  }) => Promise<ProbeSample>
}

export interface ProbeTarget {
  /** Interface id, for attribution. */
  id: string
  /** The uplink's IPv4 address, which is what binds the probe to that uplink. */
  address: string
}

/**
 * `http://cp.cloudflare.com/generate_204` answers with an empty 204 and is served from anycast
 * nodes, so the RTT it measures is the network's, not a server's. Plain HTTP keeps the measurement
 * about the network: a TLS handshake would add noise that varies with the server's load.
 */
export const DEFAULT_PROBE_URL = 'http://cp.cloudflare.com/generate_204'
const DEFAULT_TIMEOUT_MS = 4000
const DEFAULT_SAMPLE_BYTES = 256 * 1024

/**
 * Fetches as much of `url` as `sampleBytes` allows through `address`, and reports what it measured.
 * Redirects are not followed: a redirect would measure a different host than the one chosen, and
 * its latency would be about the redirecting server.
 */
export async function fetchSample(options: {
  address: string
  url: string
  timeoutMs: number
  sampleBytes: number
}): Promise<ProbeSample> {
  return new Promise<ProbeSample>((resolve) => {
    const started = Date.now()
    let firstByteAt = 0
    let received = 0
    let settled = false
    const finish = (ok: boolean, detail?: string): void => {
      if (settled) return
      settled = true
      const durationMs = Date.now() - started
      resolve({
        ok,
        at: started,
        rttMs: firstByteAt > 0 ? firstByteAt - started : null,
        bytes: received,
        durationMs,
        detail
      })
    }

    let request: ReturnType<typeof httpRequest>
    try {
      const parsed = new URL(options.url)
      const send = parsed.protocol === 'https:' ? httpsRequest : httpRequest
      request = send(
        {
          protocol: parsed.protocol,
          hostname: parsed.hostname,
          port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
          path: `${parsed.pathname}${parsed.search}`,
          method: 'GET',
          // The whole point: the request leaves through this uplink and no other.
          localAddress: options.address,
          headers: { 'user-agent': 'Plexo gateway probe', connection: 'close', accept: '*/*' },
          timeout: options.timeoutMs
        },
        (response) => {
          if (!firstByteAt) firstByteAt = Date.now()
          const status = response.statusCode ?? 0
          if (status >= 400) {
            response.resume()
            finish(false, `HTTP ${status}`)
            return
          }
          response.on('data', (chunk: Buffer) => {
            received += chunk.length
            if (options.sampleBytes > 0 && received >= options.sampleBytes) {
              request.destroy()
              finish(true)
            }
          })
          response.on('end', () => finish(true))
          response.on('error', (error: Error) => finish(received > 0, error.message))
        }
      )
    } catch (error) {
      finish(false, (error as Error).message)
      return
    }
    request.on('timeout', () => {
      request.destroy()
      finish(false, 'timed out')
    })
    request.on('error', (error: Error) => finish(false, error.message))
    request.end()
  })
}

/**
 * Probes the uplinks, one round at a time. Rounds are sequential and spaced out so two links on the
 * same physical router are not measured while competing with each other — which would report the
 * sum of both as if it were each.
 */
export class LinkProber {
  private readonly url: string
  private readonly timeoutMs: number
  private readonly sampleBytes: number
  private readonly fetch: NonNullable<ProberOptions['fetchSample']>
  private running = false

  constructor(options: ProberOptions = {}) {
    this.url = options.url ?? DEFAULT_PROBE_URL
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
    this.sampleBytes = options.sampleBytes ?? DEFAULT_SAMPLE_BYTES
    this.fetch = options.fetchSample ?? fetchSample
  }

  get probing(): boolean {
    return this.running
  }

  /**
   * One round over every uplink given. `full` also pulls bytes to measure throughput; a light round
   * (the usual one, every few seconds) only measures reachability and RTT, which is what keeps a
   * tethered phone's data use to a few kilobytes a minute.
   */
  async round(targets: readonly ProbeTarget[], full = false): Promise<ProbeSample[]> {
    if (this.running) return []
    this.running = true
    const samples: ProbeSample[] = []
    try {
      for (const target of targets) {
        if (!target.address) continue
        samples.push(
          await this.fetch({
            address: target.address,
            url: this.url,
            timeoutMs: this.timeoutMs,
            sampleBytes: full ? this.sampleBytes : 0
          })
        )
      }
    } finally {
      this.running = false
    }
    return samples
  }
}

/** When to measure what: a light round every `lightMs`, a throughput round every `fullMs`. */
export interface ProbeSchedule {
  lightMs: number
  fullMs: number
}

export const DEFAULT_PROBE_SCHEDULE: ProbeSchedule = { lightMs: 5000, fullMs: 120_000 }
