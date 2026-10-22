import type { NetworkInterfaceKind } from './types'

/**
 * LAN gateway: the console-facing half of Plexo.
 *
 * Plexo's downloads pick a network per *stream* inside its own process. A console plugged into the
 * PC's Ethernet port is not a stream Plexo can open, so the gateway does the same job one layer
 * down: it intercepts the console's packets, gives each of its sockets a NAT mapping pinned to one
 * uplink, rewrites the packets and sends them out that uplink, and translates the replies back.
 * Everything about "which uplink" — the weights, the failover, the measurement — is the same idea
 * as the download manager's per-network streams, applied to flows it never sees as sockets.
 */

/** Where the gateway as a whole is. */
export type GatewayStatus = 'stopped' | 'starting' | 'running' | 'stopping' | 'error'

/** What a link (an uplink, or the LAN port itself) is doing. */
export type LinkPhase = 'up' | 'degraded' | 'probing' | 'down' | 'disabled'

/** One uplink as the gateway sees it. */
export interface GatewayUplink {
  /** NetworkInterfaceInfo id (the OS device name). */
  id: string
  label: string
  kind: NetworkInterfaceKind
  /** IPv4 address the gateway NATs to; null while it has none (no address, no uplink). */
  address: string | null
  mac: string | null
  gateway: string | null
  mtu: number
  phase: LinkPhase
  /** Why it is not being used, when it is not. */
  downReason: 'disabled' | 'disconnected' | 'unreachable' | null
  /** Share of new flows it is taking, 0..1. */
  share: number
  /** Share it is configured to take (1/n by default), for comparison. */
  targetShare: number
  capacityBps: number
  throughputBps: number
  rttMs: number | null
  lossPct: number
  flows: number
  bytesOut: number
  bytesIn: number
  probes: number
  probeFailures: number
}

/** The Ethernet port the console is plugged into. */
export interface GatewayDownstream {
  id: string
  label: string
  address: string | null
  mac: string | null
  subnet: string | null
  mtu: number
  /** The console, once the gateway has seen it (DHCP lease or its first packet). */
  client: { ip: string; mac: string | null; firstSeenAt: number; lastSeenAt: number } | null
  leases: GatewayLease[]
}

export interface GatewayLease {
  ip: string
  mac: string
  hostname: string | null
  expiresAt: number
}

export interface GatewayFlowCounts {
  total: number
  tcp: number
  udp: number
  icmp: number
}

export interface GatewayTotals {
  /** Console → internet. */
  bytesUp: number
  /** Internet → console. */
  bytesDown: number
  /** Packets the gateway refused to forward (no uplink, malformed, IPv6 while blocked). */
  dropped: number
  /** TCP connections the gateway reset to make them reconnect on a surviving uplink. */
  resets: number
  /** Flows moved from a failed uplink to a working one. */
  repins: number
  /** Packets split to fit an uplink's smaller MTU. */
  fragments: number
  /** ICMP "fragmentation needed" answers sent to the console. */
  pmtuAnswers: number
}

export interface GatewaySnapshot {
  status: GatewayStatus
  error: string | null
  /**
   * The capture process's own words when something went wrong: which filter it asked for, what the
   * driver answered, and the exit code. Without it a failure is a sentence with no cause.
   */
  errorDetail: string | null
  startedAt: number | null
  downstream: GatewayDownstream | null
  uplinks: GatewayUplink[]
  flows: GatewayFlowCounts
  totals: GatewayTotals
  /** Measured console speed, bytes/s, both directions. */
  downstreamThroughputBps: number
  /** Whether the platform can intercept packets, and why not if it cannot. */
  capability: GatewayCapability
  /** Every adapter, so the console's port can be picked even when it has no internet. */
  adapters: GatewayAdapter[]
  /** Whether the console's traffic is actually being intercepted right now. */
  intercepting: boolean
  /** The balancer in use, so the UI can say what it does. */
  balancing: 'auto' | 'equal'
  /** What happens to an open TCP connection when its uplink dies. */
  tcpFailover: 'reset' | 'hold'
  dhcp: boolean
  dnsRelay: boolean
}

/** What the platform allows, which is the difference between "configured" and "working". */
export interface GatewayCapability {
  /** This OS can do it at all: Windows, with the WinDivert driver available. */
  supported: boolean
  platform: string
  /** Running with the privileges the driver and the adapter settings need. */
  admin: boolean
  /** WinDivert.dll + its driver were found. */
  driverInstalled: boolean
  /** Checking for an update of the driver bundle is possible (packaged builds only). */
  canInstallDriver: boolean
  /** A sentence for the UI when `supported` is false. */
  reason: string | null
}

/** The user's gateway settings, saved with the rest of the app's. */
export interface GatewayConfig {
  enabled: boolean
  /** The Ethernet port the console is on. */
  downstreamId: string | null
  /** The uplinks, in the order they were added. */
  uplinkIds: string[]
  /** Manual share per uplink (relative, ≥ 0). Empty: measured automatically. */
  uplinkWeights: Record<string, number>
  /** How the shares are decided. */
  balancing: 'auto' | 'equal'
  /** What to do with a TCP connection whose uplink disappeared. */
  tcpFailover: 'reset' | 'hold'
  /** Give the console an address over DHCP, and answer its DNS through the gateway. */
  dhcp: boolean
  dnsRelay: boolean
  /** The address the gateway takes on the LAN port, and hands out as the console's gateway. */
  downstreamAddress: string
  /** A /24 prefix for the LAN port, e.g. 192.168.77.1/24. */
  downstreamSubnet: string
  /** Allow the gateway to change adapter settings and firewall rules when it starts. */
  manageHost: boolean
}

export const DEFAULT_GATEWAY_CONFIG: GatewayConfig = {
  enabled: false,
  downstreamId: null,
  uplinkIds: [],
  uplinkWeights: {},
  balancing: 'auto',
  tcpFailover: 'reset',
  dhcp: true,
  dnsRelay: true,
  downstreamAddress: '192.168.77.1',
  downstreamSubnet: '192.168.77.1/24',
  manageHost: true
}

/**
 * An adapter the PC has, for the console-port picker. Listed from the gateway's own enumeration
 * rather than the download manager's network list: the port the console is on has no internet, so
 * the downloader may well have skipped it.
 */
export interface GatewayAdapter {
  id: string
  label: string
  kind: NetworkInterfaceKind
  addresses: string[]
  up: boolean
}

/** A control the renderer can ask for, other than a settings change. */
export type GatewayAction = 'start' | 'stop' | 'restart' | 'installDriver' | 'selfTest' | 'elevate'
