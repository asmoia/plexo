/**
 * Everything the gateway has to change on the PC itself before any packet can be forwarded, and how
 * to put it back.
 *
 * A PC is not a router. For a console plugged into its Ethernet port to use it as one, four things
 * must be true, and each is a Windows setting rather than something an app can do from user space:
 *
 *  1. The console's port has an address in a subnet of its own, with a netmask and a gateway that
 *     point at this PC. (Otherwise Windows puts the console's traffic in the same subnet as one of
 *     the uplinks and the routing table quietly bypasses the gateway.)
 *  2. Internet Connection Sharing is off on that port. ICS would NAT the console itself, on one
 *     uplink, behind a second NAT the gateway could not see — the exact opposite of what is wanted.
 *  3. IP forwarding is on, so a packet the driver lets through is not dropped for being for another
 *     host. (The gateway also reinjects explicitly; this is the belt to that braces, and it is what
 *     makes the console's own ARP and broadcast traffic behave.)
 *  4. The Windows Firewall lets DHCP and DNS reach the gateway's own addresses.
 *
 * Each function here is a small, idempotent PowerShell script. They are only ever run when the user
 * has turned `manageHost` on, and every change is recorded so `revert` can undo exactly it.
 */

import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import type { GatewayCapability } from '../../shared/gateway'
import { findWinDivert } from './backends/winDivert'

const execFileAsync = promisify(execFile)
const TIMEOUT_MS = 20_000

export interface HostChange {
  kind: 'ip' | 'forwarding' | 'ics' | 'firewall'
  /** Enough to describe the change in the UI and to undo it. */
  interfaceAlias?: string
  address?: string
  prefixLength?: number
  ruleName?: string
}

async function powershell(script: string): Promise<string> {
  const { stdout } = await execFileAsync(
    'powershell.exe',
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
    { windowsHide: true, timeout: TIMEOUT_MS, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }
  )
  return stdout
}

/** Whether this process can change adapter settings and open a WinDivert handle. */
export async function isAdministrator(): Promise<boolean> {
  if (process.platform !== 'win32') return false
  try {
    const output = await powershell(
      '([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
    )
    return output.trim().toLowerCase() === 'true'
  } catch {
    return false
  }
}

/**
 * Restarts Plexo elevated. Windows has no way for a running process to give itself rights, so the
 * app asks the shell to launch a second, elevated copy and then exits; that copy starts the gateway
 * from the settings already saved. Resolves once the new copy has been launched, so the caller can
 * quit without racing it.
 */
export async function relaunchElevated(execPath: string): Promise<void> {
  if (process.platform !== 'win32') throw new Error('Elevating is Windows-only')
  await execFileAsync(
    'powershell.exe',
    [
      '-NoLogo',
      '-NoProfile',
      '-NonInteractive',
      '-ExecutionPolicy',
      'Bypass',
      '-Command',
      `Start-Process -FilePath '${execPath.replace(/'/g, "''")}' -Verb RunAs`
    ],
    { windowsHide: true, timeout: TIMEOUT_MS }
  )
}

/** What this machine can do, for the UI to explain itself with. */
export async function detectCapability(resourcesPath?: string): Promise<GatewayCapability> {
  const platform = process.platform
  if (platform !== 'win32') {
    return {
      supported: false,
      platform,
      admin: false,
      driverInstalled: false,
      canInstallDriver: false,
      reason:
        'The console gateway needs Windows: it intercepts packets with the WinDivert driver, which only exists for Windows. Downloads still combine networks on any platform.'
    }
  }
  const admin = await isAdministrator()
  const driverPath = findWinDivert(resourcesPath)
  return {
    supported: true,
    platform,
    admin,
    driverInstalled: driverPath !== null,
    canInstallDriver: false,
    reason: !driverPath
      ? 'WinDivert was not found. Reinstall Plexo, or put WinDivert.dll and WinDivert64.sys in its windivert folder, and try again.'
      : admin
        ? null
        : 'Run Plexo as Administrator: intercepting packets and changing adapter settings both need it.'
  }
}

export interface AdapterSetupRequest {
  /** The Windows adapter alias of the console's port, e.g. "Ethernet 2". */
  interfaceAlias: string
  /** The address the gateway takes on that port. */
  address: string
  /** Prefix length of the subnet, e.g. 24 for 192.168.77.1/24. */
  prefixLength: number
  /** Serve DHCP on this port, so the console is configured automatically. */
  dhcp: boolean
}

/**
 * Prepares the console's port. Returns the changes made, so they can be undone; a change that was
 * already in place is not reported as new.
 */
export async function prepareDownstream(request: AdapterSetupRequest): Promise<HostChange[]> {
  if (process.platform !== 'win32') throw new Error('Adapter setup is Windows-only')
  const changes: HostChange[] = []
  const alias = request.interfaceAlias.replace(/'/g, "''")

  // 1. The address. Set-NetIPAddress updates in place when the address already exists; a second
  //    address on the same adapter is removed first so the console's subnet is unambiguous.
  const existing = await powershell(
    `(Get-NetIPAddress -InterfaceAlias '${alias}' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne '${request.address}' } | ForEach-Object { $_.IPAddress }) -join ','`
  )
  for (const stale of existing.trim().split(',').filter(Boolean)) {
    await powershell(
      `Remove-NetIPAddress -InterfaceAlias '${alias}' -IPAddress '${stale}' -Confirm:$false -ErrorAction SilentlyContinue`
    )
    changes.push({ kind: 'ip', interfaceAlias: alias, address: stale })
  }
  await powershell(
    `if (-not (Get-NetIPAddress -InterfaceAlias '${alias}' -IPAddress '${request.address}' -ErrorAction SilentlyContinue)) { New-NetIPAddress -InterfaceAlias '${alias}' -IPAddress '${request.address}' -PrefixLength ${request.prefixLength} -ErrorAction Stop | Out-Null; 'created' } else { 'exists' }`
  ).then((output) => {
    if (output.trim() === 'created') {
      changes.push({
        kind: 'ip',
        interfaceAlias: alias,
        address: request.address,
        prefixLength: request.prefixLength
      })
    }
  })

  // 2. Forwarding, both the IP interface setting and the global routing one.
  await powershell(
    `Set-NetIPInterface -InterfaceAlias '${alias}' -AddressFamily IPv4 -Forwarding Enabled -ErrorAction SilentlyContinue; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name 'IPEnableRouter' -Value 1 -ErrorAction SilentlyContinue`
  )
  changes.push({ kind: 'forwarding', interfaceAlias: alias })

  // 3. ICS must not touch this port.
  const ics = await powershell(
    `try { $s = (Get-Service -Name 'SharedAccess' -ErrorAction Stop).Status } catch { $s = 'absent' }; $s`
  )
  if (ics.trim() === 'Running') {
    await powershell(`Stop-Service -Name 'SharedAccess' -Force -ErrorAction SilentlyContinue`)
    await powershell(
      `Set-Service -Name 'SharedAccess' -StartupType Manual -ErrorAction SilentlyContinue`
    )
    changes.push({ kind: 'ics', interfaceAlias: alias })
  }

  // 4. Firewall: DHCP and DNS aimed at the gateway's own address.
  if (request.dhcp) {
    const rule = 'Plexo gateway DHCP'
    await powershell(
      `if (-not (Get-NetFirewallRule -DisplayName '${rule}' -ErrorAction SilentlyContinue)) { New-NetFirewallRule -DisplayName '${rule}' -Direction Inbound -Action Allow -Protocol UDP -LocalPort 67 -Profile Any | Out-Null; 'created' }`
    ).then((output) => {
      if (output.trim() === 'created') changes.push({ kind: 'firewall', ruleName: rule })
    })
  }

  return changes
}

/**
 * Undoes what `prepareDownstream` did, by name. Deliberately conservative: only things this app
 * created are removed, and the console's port keeps its address if the user set it themselves.
 */
export async function revertHost(changes: readonly HostChange[]): Promise<void> {
  if (process.platform !== 'win32') return
  for (const change of changes) {
    try {
      if (change.kind === 'ip' && change.interfaceAlias && change.address) {
        await powershell(
          `Remove-NetIPAddress -InterfaceAlias '${change.interfaceAlias}' -IPAddress '${change.address}' -Confirm:$false -ErrorAction SilentlyContinue`
        )
      } else if (change.kind === 'firewall' && change.ruleName) {
        await powershell(
          `Remove-NetFirewallRule -DisplayName '${change.ruleName}' -ErrorAction SilentlyContinue`
        )
      }
      // Forwarding and the ICS service are machine-wide and harmless to leave on: turning IP
      // forwarding back off could break a user's own setup, and ICS is stopped, not disabled.
    } catch {
      // Reverting is best effort: nothing here may stop the gateway from stopping.
    }
  }
}

/** `192.168.77.1/24` → `{ address, prefixLength }`, for the settings the UI edits as one field. */
export function parseSubnet(cidr: string): { address: string; prefixLength: number } | null {
  const match = /^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/.exec(cidr.trim())
  if (!match) return null
  const prefix = Number(match[2])
  if (prefix < 8 || prefix > 30) return null
  return { address: match[1], prefixLength: prefix }
}
