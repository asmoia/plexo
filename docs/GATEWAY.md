# Console gateway

Plexo's download manager spreads one download over every network the computer has. The console
gateway does the same thing for a **whole device** — typically a PlayStation plugged straight into
the PC with an Ethernet cable — so that everything that device does, not just downloads started
inside Plexo, leaves over both connections.

```
   PS4 ──Ethernet cable──▶ PC ┌──────────────┐ ──Wi-Fi──▶ mobile router ──▶ internet
                              │   Plexo      │
                              │ gateway      │ ──USB tethering──▶ phone ──▶ internet
                              └──────────────┘
```

What the device gets: one network, with the combined capacity of the uplinks for anything that opens
several connections (game updates, store downloads, streaming), and automatic failover so a Wi-Fi
drop doesn't end a session.

What it does **not** do: bond a single connection across two uplinks. One TCP connection still
travels over one uplink at a time, because the two uplinks have different public addresses and
nothing on the other side can reassemble them. This is the same limit Plexo has for downloads, and
it is a property of the internet, not of the implementation — the only way around it is a relay
server you own, which this design deliberately does not need.

## Requirements

|              |                                                                                         |
| ------------ | --------------------------------------------------------------------------------------- |
| OS           | Windows 10 or 11, 64-bit                                                                |
| Privileges   | Plexo running as Administrator (interception and adapter settings both need it)         |
| Driver       | WinDivert 2.2, bundled: `resources/windivert/{WinDivert.dll,WinDivert64.sys}`           |
| Console port | Any wired Ethernet adapter that is not one of the uplinks                               |
| Uplinks      | Any two or more adapters with working internet: Wi-Fi, USB tethering, a second Ethernet |

Plexo ships the WinDivert files. They are © Basil (LGPL v3, see `resources/windivert/LICENSE.txt`)
and are loaded from the app's own `windivert` folder, never from `System32`.

## Using it

1. Start Plexo **as Administrator**. Without it the gateway panel says so instead of half working.
2. Plug the console into the PC's Ethernet port with a normal cable (no crossover needed).
3. Open **Console** in the status bar at the bottom of the window.
4. **Console port**: pick the adapter the console is plugged into.
5. **Internet connections**: switch on the uplinks that should carry the console. Add every one you
   have — the weights sort themselves out from measurements.
6. Leave _Give the console an address (DHCP)_ on, and set the console's network settings to
   **automatic**. If you prefer to configure it by hand: address `192.168.77.100`, mask
   `255.255.255.0`, gateway and primary DNS `192.168.77.1`.
7. **Start gateway**.

The panel then shows, per uplink: its address, how much of new traffic it gets, what it is carrying
right now, its round-trip time, its loss, and how many flows are pinned to it. The bottom row is the
console's own throughput, the number of flows open through the gateway, and the resets and drops the
engine has produced.

Stopping the gateway puts the PC back the way it was: the address it added, the firewall rule it
created, all removed.

## How it works

### Interception

Everything the console sends arrives on one adapter, addressed to distant servers. Windows would
drop those packets (they are not for this machine), so Plexo takes them at the Windows Filtering
Platform with **WinDivert**, before routing, and injects them back out with a chosen adapter.

- One **receive** handle matches the console's adapter, and every uplink's inbound traffic **only on
  the public ports the gateway allocates** (`20 000–29 999` by default). That restriction is what
  keeps the rest of the computer working: an unfiltered capture on an uplink would take the PC's own
  traffic — Plexo's downloads, the browser, Windows Update — off the stack and out of the machine's
  internet.
- One **send-only** handle, with a filter that matches nothing, is used purely for injection, so an
  injected packet can never come back round into the gateway and be translated twice.

The blocking receive loop and the two driver handles live in a **separate process**
(`out/main/winDivertWorker.js`), because `WinDivertRecv` is a blocking call and this app's main
process must stay responsive. The app-side half (`backends/winDivert.ts`) starts that process,
relays packets over IPC, and reports status: if the driver dies the process exits and the UI says
so, rather than claiming to be running.

The choice of uplink per packet is made by setting the interface index on the injected packet. This
is the one thing Windows routing cannot do — the routing table sends everything out of one default
gateway — and it is why the driver is required.

### Per-flow NAT

Every connection the console opens becomes a **flow**, identified by its five-tuple. The flow gets:

- one uplink, chosen once and then kept;
- one translated source port on that uplink's address, kept for the life of the flow.

Because a UDP flow keeps the same public address and port for everything it sends, the console sits
behind a **full-cone NAT** — PlayStation's network test reports **NAT Type 2** and party chat, match
making and voice all work.

Return traffic is recognised by the uplink it arrived on plus the translated port, and rewritten
back to the console's address and original port.

### Choosing the uplink (weights, not round-robin)

Each uplink is scored continuously and given a weight:

- **capacity** — the best sustained throughput it has shown, decaying slowly when it is idle, so a
  fast link that is quiet doesn't get forgotten;
- **quality** — round-trip time and probe loss, so a slow-but-alive link loses to a fast one without
  being dropped;
- **liveness** — probe success and the adapter's link state.

New flows are placed with **weighted rendezvous hashing**: each uplink scores the flow against its
weight and the highest score wins. That matters for stability. When an uplink's weight changes,
only the flows that should move move; when an uplink disappears, only its own flows are affected.
Round-robin re-placing would reshuffle everything, breaking connections that had nothing wrong with
them.

### Failover

What happens when an uplink dies depends on the protocol, because the two cases are genuinely
different:

| Flow                          | On uplink loss                                                                                                                                                             |
| ----------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| UDP                           | **Re-pinned** to a live uplink, keeping the same translated port. Stateless, so the game's session survives and its keepalive continues from the new address.              |
| TCP                           | **Reset** to the console, which reconnects in milliseconds instead of waiting out a retransmit timeout measured in tens of seconds. New connection, new flow, live uplink. |
| TCP, if resets are turned off | Held until the flow's own timeout, so an app that must not be interrupted can retry on its own terms.                                                                      |

A link is only declared dead after several consecutive failed probes — a gap of Wi-Fi with a
momentary stall doesn't move traffic — and it comes back only after probes succeed again for a
little while. Both thresholds are hysteresis, and they are what keep a flapping link from dragging
connections back and forth.

### Packets

- Checksums are recomputed after every rewrite (addresses, ports, TTL decrement), for IPv4, TCP, UDP
  and ICMP.
- **Path MTU**: each uplink's smallest known MTU is learned from ICMP _fragmentation needed_
  messages (and the adapter's own MTU) and never raised again, and TCP's MSS option is clamped on the
  way out so connections size themselves to the smallest uplink they might use. Packets that are
  still too big are fragmented when the sender allowed it, or answered with ICMP _fragmentation
  needed_ when it did not.
- **ICMP errors** from the internet are translated back to the console, including the copy of the
  offending header inside them, so `traceroute` and path-MTU discovery work from the console too.
- **IPv6** is counted and dropped. Translating it would need a prefix both uplinks agree on, which
  no phone and hotspot pair provides; consoles fall back to IPv4, which is what PSN and game
  traffic use anyway. A console that insists on IPv6 will report no connection.

### DHCP and DNS

The console expects to be configured by DHCP, so the gateway answers it itself: it hands out an
address in its own subnet, with itself as router, MTU 1500, and a one-hour lease that is offered
consistently to the same MAC. The DNS servers it hands out are public resolvers rather than itself,
so lookups leave through the uplinks like everything else and stay balanced.

**Answer DNS aimed at this PC** is for a console configured by hand with the gateway as its DNS
server: those queries are redirected to a resolver and NAT'd like any other flow, instead of being
swallowed by the PC.

### What the host is changed for

The gateway needs the console's adapter to have an address, and Windows to not interfere:

1. the gateway address on the console's adapter (other addresses on it are removed, so the subnet is
   unambiguous);
2. IPv4 forwarding on that adapter, and `IPEnableRouter`;
3. the Internet Connection Sharing service stopped, because ICS also NATs and would take the port;
4. an inbound firewall rule for DHCP.

All of it is reverted on stop, except forwarding and the ICS service's startup type, which are left
alone deliberately: turning them back off could break a setup the user made themselves.

## Verifying it on real hardware

Nothing in this list can be covered by the automated tests — they run on Linux, without a Windows
kernel, a driver, or a console. Run it once per release candidate on the machine that will be used.

### 0. If it fails to start, read the log first

Every start, failure and exit is written to `%APPDATA%\Plexo\gateway.log`, with the filter the
driver was asked for and the driver's own error text. The panel shows the last lines under
**Details** in the red box, with a **Copy details** button.

The most common first-run failures and what they mean in that log:

| Line in the log                                                                          | Meaning                                                                                                                                                   |
| ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `WinDivertOpen failed: access denied — Plexo must run as Administrator (error 5)`        | Not elevated. Use the panel's **Restart** button.                                                                                                         |
| `... the WinDivert driver is disabled (error 1058)` or `blocked by Windows (error 1275)` | The driver did not load: driver-signature enforcement, memory integrity, or an antivirus. Reboot and retry, and allow `WinDivert64.sys` in the antivirus. |
| `the capture filter was rejected (error 87)`                                             | A bug — send the log.                                                                                                                                     |
| `capture process stopped (exit code 1)` with nothing above it                            | The capture process died before the driver was reached; send the log.                                                                                     |

### 1. Driver and prerequisites

```powershell
# Plexo must be elevated: this should print True.
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)

# The bundled driver files are where the app looks for them.
Get-ChildItem "$env:LOCALAPPDATA\Programs\plexo\resources\windivert" |
  Select-Object Name, Length
```

Expected: `True`, and `WinDivert.dll` (≈47 KB) plus `WinDivert64.sys` (≈94 KB).

The gateway panel's **Test** button loads the DLL, opens a handle on the console's adapter, and
reports what happened. Expected: _WinDivert is working_ followed by the DLL's path. A driver that
cannot load (the usual causes are a blocked test-signing policy or an antivirus that deletes `.sys`
files) reports the driver's own error text instead.

### 2. Addresses and interception

With the gateway running and the console connected:

```powershell
Get-NetIPAddress -AddressFamily IPv4 | Where-Object InterfaceAlias -like 'Ethernet*' |
  Select-Object InterfaceAlias, IPAddress, PrefixLength
Get-NetIPInterface -AddressFamily IPv4 -Forwarding Enabled |
  Select-Object InterfaceAlias, Forwarding
```

Expected: the console's adapter has `192.168.77.1/24`; forwarding is enabled on it and on both
uplinks.

### 3. The console's view

On the console: **Settings → Network → Test Internet Connection**.

Expected: _Obtain IP Address_ succeeds, _Internet Connection_ succeeds, and **NAT Type is 2**. Type
3 means the console is behind a symmetric NAT — check that the gateway is the one answering DHCP
(and that ICS is off). _Connection speed_ should reflect the faster uplink, not the sum, because
that test uses a single connection.

### 4. Both uplinks in use

Start a game update or a store download, then watch the panel. Expected: both uplinks show
non-zero throughput and a flow count, and the shares roughly follow the weights (the faster uplink's
share is larger). The console's speed should exceed what either uplink alone manages, because the
download opens several connections.

Cross-check from the PC:

```powershell
Get-NetAdapterStatistics | Select-Object Name, ReceivedBytes, SentBytes
```

Run it twice a few seconds apart: every uplink in the panel should be moving bytes.

### 5. Failover — Wi-Fi

With a download running (or a game online), turn the Wi-Fi router off, or disable the adapter:

```powershell
Disable-NetAdapter -Name 'Wi-Fi' -Confirm:$false
```

Expected, within about five seconds: the Wi-Fi uplink goes to _Not usable_, the tether's share goes
to 100 %, the console's throughput continues on the tether, and any TCP connection on Wi-Fi was
reset so it reconnects immediately (a game that was loading continues; a PSN download restarts that
file's connection, not the whole update). Turning Wi-Fi back on returns it to the pool within about
ten seconds.

Repeat in the other direction with the USB cable: `flows` should not go to zero, and the console
should not lose its network.

### 6. Failover — total loss

Disable both uplinks. Expected: the panel shows both _Not usable_, the console keeps its address
(DHCP still answers), and stopping/starting the gateway does not leave the PC's adapters changed.

### 7. Path MTU

The USB tethering uplink usually has an MTU below 1500. With the console idle:

```powershell
# From the PC, through the tether, to a host that answers pings.
ping -f -l 1472 1.1.1.1 -S 192.168.168.1
```

Then open a large page or start an update on the console. Expected: no stalls, no connections that
open and hang — that is the failure signature of MSS not being clamped. If a single site stalls,
check the panel's drops counter: a rising drop count with rising flows means the ICMP _fragmentation
needed_ messages are being eaten by something (usually a firewall on the upstream).

### 8. DHCP and DNS

```powershell
# From a PC plugged into the same port instead of the console
ipconfig /release; ipconfig /renew; ipconfig /all
nslookup www.playstation.com 192.168.77.1
```

Expected: an address in `192.168.77.0/24`, gateway `192.168.77.1`, and a DNS answer through the
gateway.

### 9. Leaving nothing behind

Stop the gateway, then:

```powershell
Get-NetIPAddress -IPAddress 192.168.77.1 -ErrorAction SilentlyContinue   # nothing
Get-NetFirewallRule -DisplayName 'Plexo gateway DHCP' -ErrorAction SilentlyContinue  # nothing
```

Expected: both empty. The console should lose its routed internet (the PC is no longer a gateway)
but keep working when the gateway is started again.

### 10. Long session

Leave a game online for an hour with a phone tethering. Expected: no growth in the `flows` number
beyond what the game opens (the NAT table expires idle flows), no rising `dropped` count, and no
memory growth in Task Manager beyond a few tens of MB. Switch the phone's screen off and back on
mid-session to force a tethering reconnection: the game should stall and recover rather than
disconnect.

## Troubleshooting

| Symptom                                         | Likely cause                                                                                                                              |
| ----------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Panel says _Run Plexo as Administrator_         | Started without elevation.                                                                                                                |
| Panel says _WinDivert was not found_            | Antivirus removed the driver files, or a build without `resources/windivert`.                                                             |
| Console gets no address                         | DHCP firewall rule missing, or another DHCP server on that port (a router plugged in by mistake).                                         |
| NAT Type 3 on the console                       | ICS is running, or the console is on the same subnet as an uplink.                                                                        |
| Only one uplink carries traffic                 | The other's weight is near zero: check its RTT/loss in the panel. A `0 %` share with _In use_ means it is being probed and failing.       |
| Downloads slower than one uplink                | The console's downloader is using a single connection; this is the bonding limit described above, not a fault.                            |
| Everything drops for a second every few minutes | The uplink is flapping. Raise the probe interval, or check the adapter's power management ("Allow the computer to turn off this device"). |

## For developers

The engine is almost entirely platform-free and lives in `src/main/gateway/`:

| File                                   | What it decides                                                                                                                                                         |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packet.ts`                            | Parsing and rewriting IPv4/TCP/UDP/ICMP, checksums, fragmentation, IPv4-in-IPv4 quote translation.                                                                      |
| `flow.ts`                              | Flow identity and the weighted-rendezvous hash input.                                                                                                                   |
| `scheduler.ts`                         | Which uplink a new flow goes to, given weights.                                                                                                                         |
| `health.ts`                            | Per-uplink scoring: capacity, RTT, loss, availability, hysteresis.                                                                                                      |
| `nat.ts`                               | The mapping table: allocation, lookup by public port, timeouts.                                                                                                         |
| `forwarder.ts`                         | The engine itself: a packet in, a forwarding decision out.                                                                                                              |
| `dhcp.ts`                              | The DHCP server that configures the console.                                                                                                                            |
| `prober.ts`                            | Per-uplink HTTP probes, each bound to its own adapter's address.                                                                                                        |
| `service.ts`                           | Lifecycle, sampling, snapshots for the UI.                                                                                                                              |
| `backends/`                            | Packet capture: `capture.ts` is the seam; `winDivert*` is the Windows implementation, split into a driver wrapper, a loop, an IPC protocol and the child-process entry. |
| `windowsHost.ts` / `hostInterfaces.ts` | Everything that touches the machine: adapters, addresses, firewall, admin.                                                                                              |

Tests are in `test/gateway/`, run with `npm run test:gateway` (Node's test runner; no browser, no
driver, no Windows). `test/gateway/simulation.test.ts` is the interesting one: it drives the real
scheduler, health and forwarder with a simulated world — asymmetric capacities, jitter, loss, an
uplink that dies mid-session — and a simulated clock, so a minute of game traffic runs in
milliseconds and every run is identical.
