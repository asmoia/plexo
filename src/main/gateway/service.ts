/**
 * The gateway's conductor: it owns the lifecycle, the clock, the measurements and the numbers the
 * window shows, and wires the parts that each do one thing.
 *
 *   capture backend ──► forwarder ──► backend.send
 *        ▲                 │
 *        │                 ├── NAT table (mappings, timeouts)
 *   DHCP server ◄──────────┘   (intercepted before the forwarder: the console has no address yet)
 *        │
 *   health (per uplink) ──► weights ──► forwarder's uplink list
 *        ▲
 *   prober (bound to each uplink's address)
 *
 * Everything platform-specific is injected: `backend` for packet capture, `host` for adapter
 * discovery, `capability`/`prepareHost` for Windows' settings. That is what lets the whole service
 * run — and be tested — on a machine that cannot intercept anything, reporting honestly instead of
 * pretending, and it is what the Windows build plugs the real driver into.
 */

import { DhcpServer, dhcpReplyDatagram } from './dhcp'
import { flowId } from './flow'
import { GatewayForwarder, type DownstreamRuntime, type UplinkRuntime } from './forwarder'
import { choicesFrom, downReasonOf, LinkHealth, type LinkHealthSample } from './health'
import { listHostInterfaces, parseLinkSpeed, type HostInterface } from './hostInterfaces'
import { NatTable } from './nat'
import { portsOf, parseIpv4, inSubnet, IPPROTO } from './packet'
import { DEFAULT_PROBE_SCHEDULE, LinkProber, type ProbeSchedule } from './prober'
import type { CaptureBackend } from './backends/capture'
import { WinDivertBackend } from './backends/winDivert'
import {
  detectCapability,
  parseSubnet,
  prepareDownstream,
  revertHost,
  type HostChange
} from './windowsHost'
import type { NetworkInterfaceKind } from '../../shared/types'
import {
  DEFAULT_GATEWAY_CONFIG,
  type GatewayCapability,
  type GatewayConfig,
  type GatewaySnapshot,
  type GatewayStatus,
  type GatewayUplink,
  type GatewayTotals
} from '../../shared/gateway'

const TICK_MS = 1000
const HOST_REFRESH_MS = 4000
const DHCP_PORT = 67

export interface GatewayServiceDeps {
  now?: () => number
  prober?: Pick<LinkProber, 'round'>
  probeSchedule?: ProbeSchedule
  backend?: CaptureBackend
  /** Adapter discovery. Injected so the tests do not need PowerShell. */
  host?: () => Promise<Map<string, HostInterface>>
  capability?: (config: GatewayConfig) => Promise<GatewayCapability>
  prepareHost?: (request: {
    interfaceAlias: string
    address: string
    prefixLength: number
    dhcp: boolean
  }) => Promise<HostChange[]>
  revertHost?: (changes: readonly HostChange[]) => Promise<void>
  /** Where the app is installed, for finding a bundled WinDivert. */
  resourcesPath?: string
  /** A file to keep the capture process's log in. */
  logPath?: string
}

export class GatewayService {
  private readonly now: () => number
  private readonly prober: Pick<LinkProber, 'round'>
  private readonly probeSchedule: ProbeSchedule
  private readonly backend: CaptureBackend
  private readonly discoverHost: () => Promise<Map<string, HostInterface>>
  private readonly capabilityCheck: (config: GatewayConfig) => Promise<GatewayCapability>
  private readonly prepare: NonNullable<GatewayServiceDeps['prepareHost']>
  private readonly revert: NonNullable<GatewayServiceDeps['revertHost']>

  private readonly nat = new NatTable()
  private readonly forwarder: GatewayForwarder
  private readonly health = new Map<string, LinkHealth>()
  private readonly probeTimes = new Map<string, { light: number; full: number }>()
  private dhcpServer: DhcpServer | null = null

  private config: GatewayConfig = { ...DEFAULT_GATEWAY_CONFIG }
  private status: GatewayStatus = 'stopped'
  private error: string | null = null
  private startedAt: number | null = null
  private capability: GatewayCapability = {
    supported: false,
    platform: process.platform,
    admin: false,
    driverInstalled: false,
    canInstallDriver: false,
    reason: 'Not checked yet.'
  }
  private hosts = new Map<string, HostInterface>()
  private hostRefreshedAt = 0
  private changes: HostChange[] = []
  private ticker: NodeJS.Timeout | null = null
  private listener: ((snapshot: GatewaySnapshot) => void) | null = null
  private client: {
    ip: string
    mac: string | null
    firstSeenAt: number
    lastSeenAt: number
  } | null = null
  private downstreamThroughputBps = 0
  private previousBytes = { up: 0, down: 0, at: 0 }
  /** The samples for the current instant: `LinkHealth.sample` advances its averaging, so every
   * caller in one tick must see the same one. */
  private samplesCache: LinkHealthSample[] = []
  private samplesAt = -1

  constructor(deps: GatewayServiceDeps = {}) {
    this.now = deps.now ?? (() => Date.now())
    this.prober = deps.prober ?? new LinkProber()
    this.probeSchedule = deps.probeSchedule ?? DEFAULT_PROBE_SCHEDULE
    this.backend =
      deps.backend ??
      new WinDivertBackend({ resourcesPath: deps.resourcesPath, logPath: deps.logPath })
    this.discoverHost = deps.host ?? listHostInterfaces
    this.capabilityCheck = deps.capability ?? (() => detectCapability(deps.resourcesPath))
    this.prepare = deps.prepareHost ?? prepareDownstream
    this.revert = deps.revertHost ?? revertHost
    this.forwarder = new GatewayForwarder(
      this.nat,
      () => this.uplinkRuntimes(),
      () => this.downstreamRuntime(),
      () => this.now(),
      {
        tcpFailover: this.config.tcpFailover,
        dnsRelay: { enabled: this.config.dnsRelay, resolver: '1.1.1.1' }
      }
    )
  }

  /** The window's subscription to snapshots (one push a second, and one per change). */
  onChange(listener: (snapshot: GatewaySnapshot) => void): () => void {
    this.listener = listener
    return () => {
      if (this.listener === listener) this.listener = null
    }
  }

  get currentConfig(): GatewayConfig {
    return { ...this.config }
  }

  /** Applies settings; starts, stops or reconfigures to match. */
  async configure(config: GatewayConfig): Promise<GatewaySnapshot> {
    const previous = this.config
    this.config = { ...DEFAULT_GATEWAY_CONFIG, ...config }
    // The forwarder reads these live, so a settings change takes effect on the next packet.
    this.setForwarderOptions()
    this.syncHealth()
    // Reported even while stopped: the window needs to know whether this machine can do it at all
    // before it offers a Start button, not after a failed start.
    await this.refreshHosts(true).catch(() => undefined)
    this.capability = await this.capabilityCheck(this.config).catch(() => this.capability)
    this.emit()

    const structural =
      previous.enabled !== this.config.enabled ||
      previous.downstreamId !== this.config.downstreamId ||
      previous.uplinkIds.join(',') !== this.config.uplinkIds.join(',') ||
      Boolean(previous.manageHost) !== Boolean(this.config.manageHost) ||
      previous.downstreamSubnet !== this.config.downstreamSubnet ||
      previous.dhcp !== this.config.dhcp

    if (structural) {
      if (this.status === 'running' || this.status === 'starting') await this.stop()
      if (this.config.enabled) await this.start()
    }
    this.emit()
    return this.snapshot()
  }

  async start(): Promise<void> {
    if (this.status === 'running' || this.status === 'starting') return
    this.status = 'starting'
    this.error = null
    this.emit()
    try {
      await this.refreshHosts(true)
      this.capability = await this.capabilityCheck(this.config)
      if (!this.capability.supported)
        throw new Error(this.capability.reason ?? 'Not supported here.')
      if (!this.capability.admin)
        throw new Error(this.capability.reason ?? 'Administrator rights are required.')
      if (!this.capability.driverInstalled) {
        throw new Error(this.capability.reason ?? 'The WinDivert driver was not found.')
      }

      const downstream = this.hosts.get(this.config.downstreamId ?? '')
      if (!downstream) throw new Error('Choose the Ethernet port the console is plugged into.')
      const subnet = parseSubnet(this.config.downstreamSubnet)
      if (!subnet) throw new Error('The console subnet must look like 192.168.77.1/24.')

      if (this.config.manageHost) {
        this.changes = await this.prepare({
          interfaceAlias: downstream.id,
          address: subnet.address,
          prefixLength: subnet.prefixLength,
          dhcp: this.config.dhcp
        })
        await this.refreshHosts(true)
      }

      if (this.config.dhcp) {
        this.dhcpServer = new DhcpServer({
          serverAddress: subnet.address,
          subnet: cidrNetwork(subnet.address, subnet.prefixLength),
          netmask: netmaskOf(subnet.prefixLength),
          // The console resolves through public resolvers, so its DNS goes out the uplinks like any
          // other flow and never depends on the gateway being up for a lookup.
          dnsServers: ['1.1.1.1', '8.8.8.8'],
          mtu: 1500,
          leaseSeconds: 3600
        })
      } else {
        this.dhcpServer = null
      }

      const uplinks = this.uplinkRuntimes()
      await this.backend.start(
        {
          downstreamIfIdx: downstream.ifIdx,
          uplinks: uplinks.map((uplink) => ({ ifIdx: uplink.ifIdx, id: uplink.id })),
          labels: new Map(uplinks.map((uplink) => [uplink.ifIdx, uplink.id])),
          // The same range the NAT allocates from: return traffic is only captured on these ports,
          // so the PC's own traffic on those adapters is never taken.
          publicPorts: this.nat.portRange
        },
        {
          outbound: (packet) => this.handleOutbound(packet),
          inbound: (packet, ifIdx) => this.handleInbound(packet, ifIdx)
        }
      )

      this.status = 'running'
      this.startedAt = this.now()
      this.previousBytes = { up: 0, down: 0, at: this.startedAt }
      this.startTicking()
      await this.probeRound(true)
    } catch (error) {
      this.error = (error as Error).message
      this.status = 'error'
      await this.backend.stop().catch(() => undefined)
      // Leave the host as it was: a failed start must not silently change the machine.
      if (this.changes.length > 0) {
        await this.revert(this.changes).catch(() => undefined)
        this.changes = []
      }
    }
    this.emit()
  }

  async stop(): Promise<void> {
    if (this.status === 'stopped') return
    this.status = 'stopping'
    this.stopTicking()
    await this.backend.stop().catch(() => undefined)
    if (this.changes.length > 0) {
      await this.revert(this.changes).catch(() => undefined)
      this.changes = []
    }
    this.dhcpServer = null
    this.status = 'stopped'
    this.startedAt = null
    this.error = null
    this.emit()
  }

  async restart(): Promise<GatewaySnapshot> {
    await this.stop()
    if (this.config.enabled) await this.start()
    return this.snapshot()
  }

  /** The UI's "test" button: proves the driver and the adapter indexes work, and says why not. */
  async selfTest(): Promise<{ ok: boolean; detail: string }> {
    try {
      await this.refreshHosts(true)
      const downstream = this.hosts.get(this.config.downstreamId ?? '')
      if (!downstream)
        return { ok: false, detail: 'Choose the Ethernet port the console is plugged into.' }
      const capability = await this.capabilityCheck(this.config)
      if (!capability.supported)
        return { ok: false, detail: capability.reason ?? 'Not supported here.' }
      if (!capability.driverInstalled) {
        return { ok: false, detail: capability.reason ?? 'The WinDivert driver was not found.' }
      }
      if (!capability.admin)
        return { ok: false, detail: capability.reason ?? 'Needs Administrator.' }
      const uplinks = this.uplinkRuntimes()
      return await this.backend.selfTest({
        downstreamIfIdx: downstream.ifIdx,
        uplinks: uplinks.map((uplink) => ({ ifIdx: uplink.ifIdx, id: uplink.id })),
        labels: new Map(),
        publicPorts: this.nat.portRange
      })
    } catch (error) {
      return { ok: false, detail: (error as Error).message }
    }
  }

  /** Everything the window draws. */
  snapshot(): GatewaySnapshot {
    const now = this.now()
    const samples = this.sampleHealth()
    const choices = choicesFrom(samples)
    const shareOf = new Map(choices.map((choice) => [choice.id, choice.weight]))
    const mappings = this.nat.mappings()
    const adapters = [...this.hosts.values()]
      .map((host) => ({
        id: host.id,
        label: host.id,
        kind: classifyAdapter(host.description || host.id),
        addresses: [...host.addresses],
        up: host.up
      }))
      .sort((a, b) => a.label.localeCompare(b.label))

    const uplinks: GatewayUplink[] = this.config.uplinkIds.map((id) => {
      const host = this.hosts.get(id)
      const sample = samples.find((entry) => entry.id === id) ?? null
      const counters = this.forwarder.uplinkCounters(id)
      const uplinkFlows = mappings.filter((mapping) => mapping.linkId === id).length
      return {
        id,
        label: host?.id ?? id,
        kind: classifyAdapter(host?.description ?? host?.id ?? id),
        address: host?.addresses[0] ?? null,
        mac: host?.mac ?? null,
        gateway: host?.gateway ?? null,
        mtu: host?.mtu ?? 1500,
        phase: sample?.phase ?? 'down',
        downReason: sample ? downReasonOf(sample) : 'disconnected',
        share:
          this.config.balancing === 'equal'
            ? 1 / Math.max(1, this.config.uplinkIds.length)
            : (shareOf.get(id) ?? 0),
        targetShare: 1 / Math.max(1, this.config.uplinkIds.length),
        capacityBps: sample?.capacityBps ?? 0,
        throughputBps: sample?.throughputBps ?? 0,
        rttMs: sample?.rttMs ?? null,
        lossPct: (sample?.loss ?? 0) * 100,
        flows: uplinkFlows,
        bytesOut: counters.bytesOut,
        bytesIn: counters.bytesIn,
        probes: sample?.probes ?? 0,
        probeFailures: sample?.probeFailures ?? 0
      }
    })

    const downstream = this.hosts.get(this.config.downstreamId ?? '')
    const subnet = parseSubnet(this.config.downstreamSubnet)
    const lease = this.dhcpServer?.clientLease() ?? null
    const stats = this.nat.stats()
    // Read once: the capture process's own account of itself, which is what a failure is explained
    // by — including when the process died before it could report anything.
    const capture = this.backend.status()

    return {
      status: this.status,
      error: this.error,
      errorDetail: (capture.diagnostics ?? []).length > 0 ? capture.diagnostics.join('\n') : null,
      startedAt: this.startedAt,
      downstream: downstream
        ? {
            id: downstream.id,
            label: downstream.id,
            address: subnet?.address ?? downstream.addresses[0] ?? null,
            mac: downstream.mac,
            subnet: subnet
              ? `${cidrNetwork(subnet.address, subnet.prefixLength)}/${subnet.prefixLength}`
              : null,
            mtu: downstream.mtu,
            client:
              this.client ??
              (lease
                ? {
                    ip: lease.ip,
                    mac: lease.mac,
                    firstSeenAt: lease.expiresAt - 3_600_000,
                    lastSeenAt: now
                  }
                : null),
            leases: this.dhcpServer?.leasesNow(now) ?? []
          }
        : null,
      uplinks,
      flows: { total: stats.mappings, tcp: stats.tcp, udp: stats.udp, icmp: stats.icmp },
      totals: { ...this.forwarder.totals },
      downstreamThroughputBps: this.downstreamThroughputBps,
      capability: this.capability,
      adapters,
      intercepting: capture.running,
      balancing: this.config.balancing,
      tcpFailover: this.config.tcpFailover,
      dhcp: this.config.dhcp,
      dnsRelay: this.config.dnsRelay
    }
  }

  // ---- packet paths -------------------------------------------------------------------------

  /** A packet from the console. DHCP is answered here; everything else is the forwarder's. */
  private handleOutbound(packet: Buffer): void {
    const parsed = parseIpv4(packet)
    if (!parsed) return
    const downstream = this.downstreamRuntime()
    if (
      downstream &&
      parsed.srcIp !== downstream.address &&
      inSubnet(parsed.srcIp, downstream.subnet)
    ) {
      const now = this.now()
      if (!this.client || this.client.ip !== parsed.srcIp) {
        this.client = { ip: parsed.srcIp, mac: null, firstSeenAt: now, lastSeenAt: now }
      } else {
        this.client.lastSeenAt = now
      }
      const lease = this.dhcpServer?.clientLease()
      if (lease && this.client && lease.ip === this.client.ip) this.client.mac = lease.mac
    }

    if (parsed.protocol === IPPROTO.UDP && this.dhcpServer) {
      const ports = portsOf(parsed)
      if (ports?.dstPort === DHCP_PORT) {
        const reply = this.dhcpServer.handle(packet.subarray(parsed.payloadOffset + 8), this.now())
        if (reply) {
          const target = reply.broadcast
            ? '255.255.255.255'
            : (this.client?.ip ?? '255.255.255.255')
          const datagram = dhcpReplyDatagram({
            payload: reply.payload,
            serverAddress: this.downstreamRuntime()?.address ?? this.config.downstreamAddress,
            broadcast: reply.broadcast,
            clientIp: target
          })
          if (datagram) this.backend.send([{ packet: datagram, ifIdx: downstream?.ifIdx ?? 0 }])
        }
        return
      }
    }

    const result = this.forwarder.outbound(packet)
    if (result.transmit.length > 0) this.backend.send(result.transmit)
  }

  /** A packet from an uplink. */
  private handleInbound(packet: Buffer, ifIdx: number): void {
    const result = this.forwarder.inbound(packet, ifIdx)
    if (result.transmit.length > 0) this.backend.send(result.transmit)
  }

  // ---- the clock ----------------------------------------------------------------------------

  private startTicking(): void {
    this.stopTicking()
    this.ticker = setInterval(() => void this.pump(), TICK_MS)
    this.ticker.unref?.()
  }

  private stopTicking(): void {
    if (this.ticker) clearInterval(this.ticker)
    this.ticker = null
  }

  /**
   * One housekeeping and measurement pass: expire what has gone stale, re-measure the uplinks,
   * update the throughput numbers. Runs once a second on its own timer; public so the tests (and the
   * diagnostics screen) can drive it without waiting for a wall clock.
   */
  async pump(): Promise<void> {
    const now = this.now()
    this.forwarder.housekeeping(now)
    this.nat.expire(now)
    this.dhcpServer?.expire(now)

    if (now - this.hostRefreshedAt > HOST_REFRESH_MS)
      await this.refreshHosts().catch(() => undefined)

    // Health first, so this tick's weights are the ones the forwarder uses.
    this.sampleHealth()

    const totals = this.forwarder.totals
    const elapsed = Math.max(0.001, (now - this.previousBytes.at) / 1000)
    const instant =
      (totals.bytesUp + totals.bytesDown - this.previousBytes.up - this.previousBytes.down) /
      elapsed
    this.downstreamThroughputBps = this.downstreamThroughputBps * 0.6 + instant * 0.4
    this.previousBytes = { up: totals.bytesUp, down: totals.bytesDown, at: now }

    await this.probeIfDue(now)
    this.emit()
  }

  /** Probes on a schedule: light and often, with a throughput sample now and then. */
  private async probeIfDue(now: number): Promise<void> {
    const targets = this.config.uplinkIds
      .map((id) => ({ id, host: this.hosts.get(id) }))
      .filter((entry): entry is { id: string; host: HostInterface } =>
        Boolean(entry.host && entry.host.addresses.length > 0)
      )
    if (targets.length === 0) return

    const due = targets.filter((target) => {
      const times = this.probeTimes.get(target.id) ?? { light: 0, full: 0 }
      return now - times.light >= this.probeSchedule.lightMs
    })
    if (due.length === 0) return
    const full = targets.some((target) => {
      const times = this.probeTimes.get(target.id) ?? { light: 0, full: 0 }
      return now - times.full >= this.probeSchedule.fullMs
    })
    for (const target of due) {
      const times = this.probeTimes.get(target.id) ?? { light: 0, full: 0 }
      this.probeTimes.set(target.id, { light: now, full: full ? now : times.full })
    }
    await this.probeRound(full)
  }

  private async probeRound(full: boolean): Promise<void> {
    const targets = this.config.uplinkIds
      .map((id) => ({ id, host: this.hosts.get(id) }))
      .filter((entry): entry is { id: string; host: HostInterface } =>
        Boolean(entry.host && entry.host.addresses.length > 0)
      )
      .map((entry) => ({ id: entry.id, address: entry.host.addresses[0] }))
    if (targets.length === 0) return
    let samples
    try {
      samples = await this.prober.round(targets, full)
    } catch {
      return
    }
    const now = this.now()
    for (const [index, sample] of samples.entries()) {
      const target = targets[index]
      const health = this.health.get(target.id)
      if (health) health.observeProbe(sample, now)
    }
  }

  // ---- state --------------------------------------------------------------------------------

  private setForwarderOptions(): void {
    this.forwarder.setOptions({
      tcpFailover: this.config.tcpFailover,
      dnsRelay: { enabled: this.config.dnsRelay, resolver: '1.1.1.1' }
    })
  }

  /** Creates and removes health trackers as the uplink list changes. */
  private syncHealth(): void {
    for (const id of this.config.uplinkIds) {
      if (!this.health.has(id)) this.health.set(id, new LinkHealth(id, {}, this.now()))
    }
    for (const id of [...this.health.keys()]) {
      if (!this.config.uplinkIds.includes(id)) this.health.delete(id)
    }
  }

  private async refreshHosts(force = false): Promise<void> {
    const now = this.now()
    if (!force && now - this.hostRefreshedAt < HOST_REFRESH_MS) return
    this.hostRefreshedAt = now
    const hosts = await this.discoverHost()
    this.hosts = hosts
    for (const id of this.config.uplinkIds) {
      const host = hosts.get(id)
      const health = this.health.get(id)
      if (!health) continue
      const connected = Boolean(host && host.up && host.addresses.length > 0)
      health.setConnected(connected)
    }
  }

  /** What the forwarder sees for each uplink: where to send, how big, and how much to use it. */
  private uplinkRuntimes(): UplinkRuntime[] {
    const samples = this.sampleHealth()
    const choices = choicesFrom(samples)
    const weights = new Map(choices.map((choice) => [choice.id, choice.weight]))
    return this.config.uplinkIds
      .map((id) => {
        const host = this.hosts.get(id)
        const sample = samples.find((entry) => entry.id === id)
        const weight =
          this.config.balancing === 'equal'
            ? sample?.phase === 'down'
              ? 0
              : 1
            : (weights.get(id) ?? 0)
        const override = this.config.uplinkWeights[id]
        return {
          id,
          address: host?.addresses[0] ?? '',
          mac: null,
          ifIdx: host?.ifIdx ?? 0,
          mtu: host?.mtu ?? 1500,
          usable:
            Boolean(host && host.up && host.addresses.length > 0 && host.ifIdx > 0) &&
            sample?.phase !== 'down' &&
            sample?.phase !== 'disabled',
          weight: override !== undefined && weight > 0 ? override : weight
        }
      })
      .filter((uplink) => uplink.address.length > 0)
  }

  private downstreamRuntime(): DownstreamRuntime | null {
    const host = this.hosts.get(this.config.downstreamId ?? '')
    const subnet = parseSubnet(this.config.downstreamSubnet)
    if (!subnet) return null
    return {
      id: host?.id ?? this.config.downstreamId ?? '',
      address: subnet.address,
      mac: null,
      ifIdx: host?.ifIdx ?? 0,
      mtu: host?.mtu ?? 1500,
      subnet: cidrNetwork(subnet.address, subnet.prefixLength) + `/${subnet.prefixLength}`
    }
  }

  /**
   * One sampling point per instant. `sample()` folds in the seconds since the last call, so calling
   * it from the tick, from the forwarder and from the snapshot would triple-count throughput and
   * collapse the averaging window; this returns the same samples to all three.
   */
  private sampleHealth(): LinkHealthSample[] {
    const now = this.now()
    if (this.samplesAt !== now) {
      this.samplesCache = [...this.health.values()].map((health) => health.sample(now))
      this.samplesAt = now
    }
    return this.samplesCache
  }

  private emit(): void {
    this.listener?.(this.snapshot())
  }

  /** For the tests and the diagnostics screen: the flow table's current contents. */
  debugState(): {
    mappings: ReturnType<NatTable['mappings']>
    totals: GatewayTotals
    samples: LinkHealthSample[]
    status: GatewayStatus
  } {
    return {
      mappings: this.nat.mappings(),
      totals: { ...this.forwarder.totals },
      samples: [...this.health.values()].map((health) => health.sample(this.now())),
      status: this.status
    }
  }

  /** Kept for the UI's "why is this flow here?" tooltip. */
  flowOf(clientIp: string, clientPort: number, proto: number): string | undefined {
    const mapping = this.nat.lookup(proto, clientIp, clientPort)
    return mapping ? flowId(mapping) : undefined
  }
}

/**
 * What an adapter is, from its name and description, for the icon the UI draws. Windows names a
 * Wi-Fi adapter "Wi-Fi" and describes it "Intel(R) Wi-Fi 6 AX201"; a tethered phone shows up as
 * "Remote NDIS Compatible Device" or with its carrier's name.
 */
export function classifyAdapter(text: string): NetworkInterfaceKind {
  const name = text.toLowerCase()
  if (/wi-?fi|wireless|wlan|802\.11|ax2|ax1|ac\d/.test(name)) return 'wifi'
  if (/rndis|remote ndis|tether|iphone|android|usb/.test(name)) return 'usb'
  if (/ethernet|realtek|intel\(r\) i219|gbe|lan/.test(name)) return 'ethernet'
  if (/bridge/.test(name)) return 'bridge'
  return 'other'
}

/** `192.168.77.1`, 24 → `192.168.77.0` */
export function cidrNetwork(address: string, prefixLength: number): string {
  const octets = address.split('.').map(Number)
  const value = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0
  const mask = prefixLength === 0 ? 0 : (0xffffffff << (32 - prefixLength)) >>> 0
  const network = (value & mask) >>> 0
  return [network >>> 24, (network >>> 16) & 0xff, (network >>> 8) & 0xff, network & 0xff].join('.')
}

/** 24 → `255.255.255.0` */
export function netmaskOf(prefixLength: number): string {
  const mask = prefixLength === 0 ? 0 : (0xffffffff << (32 - prefixLength)) >>> 0
  return [mask >>> 24, (mask >>> 16) & 0xff, (mask >>> 8) & 0xff, mask & 0xff].join('.')
}

/** Exposed for the settings screen: an uplink's link speed, when the OS reports one. */
export const uplinkLinkSpeed = parseLinkSpeed
