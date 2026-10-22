/**
 * What the OS knows about an adapter that Node's `networkInterfaces()` does not: the interface
 * index (what WinDivert and the routing table use), the MTU, the default gateway, and the link
 * speed. The gateway needs the index to capture and to send, the MTU to clamp and fragment, and the
 * gateway address to know an uplink is actually configured.
 *
 * Windows is read through PowerShell (one call, JSON out) because there is no other stable way from
 * Node without a native module. Elsewhere — and on a Windows whose PowerShell is locked down — the
 * function degrades to defaults taken from Node's own list, so the UI still works and only the
 * capture (which is Windows-only anyway) is affected.
 */

import { execFile } from 'node:child_process'
import { networkInterfaces } from 'node:os'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
// Windows PowerShell can take many seconds to start on a loaded machine (the first launch after a
// boot especially). Six was too short: the call timed out, the code fell back to Node's adapter list,
// and every interface index came back 0 — which the gateway reads as "no usable uplink".
const TIMEOUT_MS = 30_000

export interface HostInterface {
  /** The OS device name / adapter alias, which is the app's interface id everywhere else. */
  id: string
  /** Interface index; 0 when it could not be determined. */
  ifIdx: number
  description: string | null
  /** The adapter's MAC, when the OS reports one. */
  mac: string | null
  /** IPv4 addresses on the adapter. */
  addresses: string[]
  /** MTU of the link as the OS reports it, 1500 when unknown. */
  mtu: number
  /** Default gateway for IPv4, when the adapter has one. */
  gateway: string | null
  /** Negotiated link speed in bits/s, when the OS reports one. */
  linkSpeedBps: number | null
  /** Whether the OS considers the adapter connected. */
  up: boolean
}

interface PowerShellAdapter {
  Name?: string
  MacAddress?: string
  ifIndex?: number
  InterfaceDescription?: string
  Status?: string
  LinkSpeed?: string | number
  NlMtu?: number
  IPv4Address?: string | string[] | null
  IPv4DefaultGateway?: { NextHop?: string } | { NextHop?: string }[] | null
}

function asArray<T>(value: T | T[] | null | undefined): T[] {
  if (value === null || value === undefined) return []
  return Array.isArray(value) ? value : [value]
}

/** "1 Gbps" / "100 Mbps" / "1500000000" → bits per second. */
export function parseLinkSpeed(value: string | number | null | undefined): number | null {
  if (value === null || value === undefined) return null
  if (typeof value === 'number') return value > 0 ? value : null
  const match = /^([\d.]+)\s*(Gbps|Mbps|Kbps|bps)$/i.exec(value.trim())
  if (!match) {
    const numeric = Number(value)
    return Number.isFinite(numeric) && numeric > 0 ? numeric : null
  }
  const scale = { bps: 1, kbps: 1e3, mbps: 1e6, gbps: 1e9 }[match[2].toLowerCase() as 'bps']
  return Math.round(Number(match[1]) * scale)
}

/**
 * Why the PowerShell enumeration failed, if it did. Swallowing it silently is how a machine ends up
 * with every adapter reporting interface index 0 — which looks like "the gateway captures nothing"
 * and says nothing about the cause.
 */
let enumerationError: string | null = null

export function hostEnumerationError(): string | null {
  return enumerationError
}

async function windowsInterfaces(): Promise<Map<string, HostInterface> | null> {
  if (process.platform !== 'win32') return null
  try {
    const script = [
      // Setting the console encoding throws when stdout is a pipe ("the handle is invalid") on some
      // Windows hosts, and an exception here would fail the whole call — which then silently falls
      // back to an enumeration with no interface indexes. It is a nicety for non-Latin adapter
      // names, so a failure to set it must not matter.
      'try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { };',
      "$ProgressPreference = 'SilentlyContinue';",
      "$ErrorActionPreference = 'Stop';",
      'Get-NetAdapter -ErrorAction Stop | ForEach-Object {',
      '  $a = $_;',
      // Adapter-down entries have no IP interface at all, and Get-NetIPConfiguration throws
      // ("No MSFT_NetIPInterface objects found with property 'InterfaceIndex' equal to 'N'") for
      // them — on real hardware that aborted the whole enumeration and left every adapter at
      // index 0. One unusable adapter must cost only its own address fields, never the list.
      '  $row = [pscustomobject]@{',
      '    Name = $a.Name; MacAddress = $a.MacAddress; ifIndex = [int]$a.ifIndex; InterfaceDescription = $a.InterfaceDescription;',
      '    Status = [string]$a.Status; LinkSpeed = [string]$a.LinkSpeed;',
      '    NlMtu = 0; IPv4Address = @(); IPv4DefaultGateway = @()',
      '  };',
      '  try {',
      '    $ip = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue);',
      '    if ($ip.Count -gt 0) {',
      '      $row.NlMtu = [int]$ip[0].NlMtu;',
      '      $row.IPv4Address = @($ip | ForEach-Object { $_.IPAddress });',
      '    }',
      '  } catch { };',
      '  try {',
      '    $cfg = @(Get-NetIPConfiguration -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue);',
      '    if ($cfg.Count -gt 0) {',
      '      $row.IPv4DefaultGateway = @($cfg[0].IPv4DefaultGateway | ForEach-Object { $_.NextHop });',
      '    }',
      '  } catch { };',
      '  $row',
      '} | ConvertTo-Json -Compress'
    ].join('\n')
    const { stdout } = await execFileAsync(
      'powershell.exe',
      ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
      { windowsHide: true, timeout: TIMEOUT_MS, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }
    )
    const parsed = JSON.parse(stdout.trim().replace(/^\uFEFF/, '')) as
      PowerShellAdapter | PowerShellAdapter[]
    const result = new Map<string, HostInterface>()
    for (const adapter of asArray(parsed)) {
      if (!adapter.Name) continue
      const gateway = asArray(adapter.IPv4DefaultGateway)
        .map((entry) => (typeof entry === 'string' ? entry : entry?.NextHop))
        .find((hop): hop is string => typeof hop === 'string' && hop.length > 0)
      result.set(adapter.Name, {
        id: adapter.Name,
        ifIdx: adapter.ifIndex ?? 0,
        description: adapter.InterfaceDescription ?? null,
        mac: adapter.MacAddress ?? null,
        addresses: asArray(adapter.IPv4Address).filter((address) =>
          /^\d+\.\d+\.\d+\.\d+$/.test(address)
        ),
        mtu: adapter.NlMtu && adapter.NlMtu > 0 ? adapter.NlMtu : 1500,
        gateway: gateway ?? null,
        linkSpeedBps: parseLinkSpeed(adapter.LinkSpeed),
        up: (adapter.Status ?? '').toLowerCase() === 'up'
      })
    }
    return result
  } catch (error) {
    // Restricted PowerShell must not stop the app; the caller falls back to Node's view. The reason
    // is kept so the panel and the tests can say what happened — including the exit code and
    // whatever PowerShell wrote, which is usually the whole explanation.
    const failed = error as {
      message?: string
      stderr?: string
      stdout?: string
      code?: number | string
      signal?: string
      killed?: boolean
    }
    const detail = [
      `exit ${failed.code ?? '?'}${failed.killed ? ' (killed)' : ''}${failed.signal ? ` signal ${failed.signal}` : ''}`,
      String(failed.stderr ?? '').trim(),
      String(failed.stdout ?? '').trim()
    ]
      .filter((part) => part.length > 0)
      .join(' · ')
    enumerationError = `${(failed.message ?? 'PowerShell failed').split('\n')[0]} [${detail.slice(0, 600)}]`
    return null
  }
}

/** Every adapter, by the app's interface id, with the platform details the gateway needs. */
export async function listHostInterfaces(): Promise<Map<string, HostInterface>> {
  const discovered = await windowsInterfaces()
  if (discovered && discovered.size > 0) {
    enumerationError = null
    return discovered
  }

  const result = new Map<string, HostInterface>()
  for (const [device, addresses] of Object.entries(networkInterfaces())) {
    if (!addresses) continue
    const ipv4 = addresses
      .filter((address) => !address.internal && address.family === 'IPv4')
      .map((address) => address.address)
    const mac =
      addresses.find((address) => address.mac && address.mac !== '00:00:00:00:00:00')?.mac ?? null
    result.set(device, {
      id: device,
      ifIdx: 0,
      description: mac,
      mac,
      addresses: ipv4,
      mtu: 1500,
      gateway: null,
      linkSpeedBps: null,
      up: ipv4.length > 0
    })
  }
  return result
}

/** The interface a given IPv4 address belongs to, as the OS sees it. */
export function interfaceOfAddress(
  interfaces: Map<string, HostInterface>,
  address: string
): HostInterface | null {
  for (const iface of interfaces.values()) {
    if (iface.addresses.includes(address)) return iface
  }
  return null
}
