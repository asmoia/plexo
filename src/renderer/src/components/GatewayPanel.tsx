import { DEFAULT_GATEWAY_CONFIG, type GatewayConfig, type GatewayUplink } from '@shared/gateway'
import type { GatewayAdapter } from '@shared/gateway'
import type { SpeedUnit } from '@shared/types'
import { useEffect, useState } from 'react'
import { useGateway } from '../hooks/useGateway'
import { useAppStore } from '../store/useAppStore'
import { formatSpeed } from '../utils/format'
import { Button } from './ui/button'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from './ui/dialog'
import { Switch } from './ui/switch'

const PHASE_LABEL: Record<GatewayUplink['phase'], string> = {
  up: 'In use',
  degraded: 'Degraded',
  probing: 'Measuring',
  down: 'Not usable',
  disabled: 'Off'
}

function phaseColor(phase: GatewayUplink['phase']): string {
  if (phase === 'up') return 'var(--color-success, #22c55e)'
  if (phase === 'degraded') return 'var(--color-warning, #f59e0b)'
  if (phase === 'probing') return 'var(--color-info, #60a5fa)'
  return 'var(--color-danger, #ef4444)'
}

function Row({ children, label }: { children: React.ReactNode; label: string }): React.JSX.Element {
  return (
    <div className="flex items-center justify-between gap-3 py-1.5">
      <span className="text-[12.5px] text-[var(--text-secondary)]">{label}</span>
      <div className="flex items-center gap-2 text-[12.5px]">{children}</div>
    </div>
  )
}

function UplinkRow({
  uplink,
  speedUnit,
  checked,
  onToggle
}: {
  uplink: GatewayUplink
  speedUnit: SpeedUnit
  checked: boolean
  onToggle: (enabled: boolean) => void
}): React.JSX.Element {
  return (
    <div className="flex items-start gap-3 rounded-[8px] border-[0.5px] border-border p-2.5">
      <Switch checked={checked} onCheckedChange={onToggle} />
      <div className="min-w-0 flex-1">
        <div className="flex items-center justify-between gap-2">
          <span className="truncate text-[13px] font-medium">{uplink.label}</span>
          <span
            className="flex shrink-0 items-center gap-1.5 font-mono text-[11px]"
            style={{ color: phaseColor(uplink.phase) }}
          >
            <span
              className="size-1.5 rounded-full"
              style={{ background: phaseColor(uplink.phase) }}
            />
            {PHASE_LABEL[uplink.phase]}
          </span>
        </div>
        <div className="mt-0.5 flex flex-wrap gap-x-3 gap-y-0.5 font-mono text-[11px] text-muted-foreground tabular-nums">
          <span>{uplink.address ?? 'no address'}</span>
          {uplink.phase !== 'down' && uplink.phase !== 'disabled' && (
            <>
              <span>{Math.round(uplink.share * 100)}% of new flows</span>
              <span>{formatSpeed(uplink.throughputBps, speedUnit)}</span>
              {uplink.rttMs !== null && <span>{Math.round(uplink.rttMs)} ms</span>}
              {uplink.lossPct > 0.5 && <span>{uplink.lossPct.toFixed(0)}% loss</span>}
              <span>
                {uplink.flows} {uplink.flows === 1 ? 'flow' : 'flows'}
              </span>
            </>
          )}
          {uplink.downReason === 'unreachable' && <span>not answering probes</span>}
          {uplink.downReason === 'disconnected' && <span>adapter is down</span>}
        </div>
      </div>
    </div>
  )
}

/**
 * The console gateway: a PlayStation (or anything else) plugged into one Ethernet port, its traffic
 * spread over the other networks and failing over between them.
 *
 * The panel is split the way the feature is: what the console is plugged into, which connections
 * carry it, and what is happening right now. Everything is a direct view of the main process's
 * snapshot — this screen holds no state of its own except the settings being edited.
 */
export function GatewayPanel({
  open,
  onOpenChange
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
}): React.JSX.Element {
  const { snapshot } = useGateway()
  const speedUnit = useAppStore((store) => store.speedUnit)
  const [draft, setDraft] = useState<GatewayConfig>(DEFAULT_GATEWAY_CONFIG)
  const [busy, setBusy] = useState(false)
  const [detail, setDetail] = useState<string | null>(null)

  // The saved settings, when the panel opens: the snapshot carries the running state, and the
  // saved config is what the editor starts from.
  useEffect(() => {
    if (!open) return
    void window.plexo
      .gatewayConfig()
      .then((saved) => setDraft(saved))
      .catch(() => {})
  }, [open])

  const apply = async (config: GatewayConfig): Promise<void> => {
    setBusy(true)
    try {
      const next = await window.plexo.gatewayConfigure(config)
      setDraft((current) => ({ ...current, enabled: next.status === 'running' }))
    } catch (error) {
      setDetail((error as Error).message)
    } finally {
      setBusy(false)
    }
  }

  const running = snapshot?.status === 'running'
  const capability = snapshot?.capability
  const downstream = snapshot?.downstream

  // Every adapter the PC has, from the gateway's own enumeration — not the download manager's
  // network list, which only holds adapters with internet: the console's port has none by design,
  // so it would be missing exactly where it is needed most.
  const adapters: GatewayAdapter[] = snapshot?.adapters ?? []
  const lanCandidates = adapters
  const uplinkCandidates = adapters.filter((iface) => iface.id !== draft.downstreamId)

  const configFor = (patch: Partial<GatewayConfig>): GatewayConfig => ({ ...draft, ...patch })

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-[560px]">
        <DialogHeader>
          <DialogTitle>Console gateway</DialogTitle>
        </DialogHeader>

        {/* What the platform allows, first: everything below is moot without it. */}
        {capability && !capability.supported && (
          <p className="rounded-[8px] bg-[var(--bg-secondary)] p-3 text-[12.5px] text-muted-foreground">
            {capability.reason}
          </p>
        )}
        {capability?.supported && capability.reason && (
          <p className="rounded-[8px] bg-[var(--bg-secondary)] p-3 text-[12.5px] text-[var(--color-danger)]">
            {capability.reason}
          </p>
        )}
        {capability?.supported && !capability.admin && (
          <div className="flex items-center justify-between gap-2 rounded-[8px] bg-[var(--bg-secondary)] p-2.5">
            <span className="text-[12.5px]">
              Restart Plexo as Administrator to use the gateway.
            </span>
            <Button
              type="button"
              variant="secondary"
              className="text-[12px]"
              onClick={() => void window.plexo.gatewayAction('elevate')}
            >
              Restart
            </Button>
          </div>
        )}
        {snapshot?.error && (
          <div className="space-y-1.5 rounded-[8px] bg-[var(--bg-secondary)] p-3">
            <p className="text-[12.5px] text-[var(--color-danger)]">{snapshot.error}</p>
            {snapshot.errorDetail && (
              <details>
                <summary className="cursor-pointer text-[11.5px] text-muted-foreground">
                  Details (what the capture process said)
                </summary>
                <pre className="mt-1.5 max-h-[180px] overflow-auto rounded-[4px] bg-background p-2 font-mono text-[10.5px] leading-[1.45] whitespace-pre-wrap">
                  {snapshot.errorDetail}
                </pre>
                <button
                  type="button"
                  className="mt-1 text-[11.5px] text-[var(--text-secondary)] underline"
                  onClick={() => void navigator.clipboard.writeText(snapshot.errorDetail ?? '')}
                >
                  Copy details
                </button>
              </details>
            )}
          </div>
        )}

        <section className="space-y-1.5">
          <h3 className="text-[11px] font-semibold tracking-[0.06em] text-muted-foreground uppercase">
            Console port
          </h3>
          <div className="grid grid-cols-2 gap-1.5">
            {lanCandidates.map((iface) => (
              <button
                key={iface.id}
                type="button"
                disabled={running || busy}
                onClick={() => setDraft((current) => ({ ...current, downstreamId: iface.id }))}
                className={`truncate rounded-[6px] border-[0.5px] px-2 py-1.5 text-left text-[12px] disabled:opacity-60 ${
                  draft.downstreamId === iface.id
                    ? 'border-[var(--color-accent)] bg-[var(--bg-secondary)]'
                    : 'border-border'
                }`}
              >
                {iface.label}
                {iface.addresses[0] ? ` · ${iface.addresses[0]}` : ''}
              </button>
            ))}
          </div>
          <Row label="Console’s address">
            <span className="font-mono">
              {downstream?.client?.ip ?? (running ? 'waiting for DHCP' : '—')}
            </span>
          </Row>
        </section>

        <section className="space-y-1.5">
          <h3 className="text-[11px] font-semibold tracking-[0.06em] text-muted-foreground uppercase">
            Internet connections
          </h3>
          {(snapshot?.uplinks ?? []).length > 0 ? (
            <div className="space-y-1.5">
              {snapshot?.uplinks.map((uplink) => (
                <UplinkRow
                  key={uplink.id}
                  uplink={uplink}
                  speedUnit={speedUnit}
                  checked={draft.uplinkIds.includes(uplink.id)}
                  onToggle={(enabled) =>
                    setDraft((current) => ({
                      ...current,
                      uplinkIds: enabled
                        ? [...current.uplinkIds, uplink.id]
                        : current.uplinkIds.filter((id) => id !== uplink.id)
                    }))
                  }
                />
              ))}
            </div>
          ) : (
            <p className="text-[12.5px] text-muted-foreground">
              Pick the connections that should carry the console. A second one adds its speed;
              either one alone keeps the console online.
            </p>
          )}
          <div className="flex flex-wrap gap-1.5">
            {uplinkCandidates
              .filter((iface) => !draft.uplinkIds.includes(iface.id))
              .map((iface) => (
                <Button
                  key={iface.id}
                  type="button"
                  variant="secondary"
                  className="text-[12px]"
                  onClick={() =>
                    setDraft((current) => ({
                      ...current,
                      uplinkIds: [...current.uplinkIds, iface.id]
                    }))
                  }
                >
                  Add {iface.label}
                </Button>
              ))}
          </div>
        </section>

        <section className="space-y-1">
          <Row label="Console subnet">
            <input
              value={draft.downstreamSubnet}
              disabled={running || busy}
              onChange={(event) =>
                setDraft((current) => ({ ...current, downstreamSubnet: event.target.value }))
              }
              className="w-[150px] rounded-[4px] border-[0.5px] border-border bg-transparent px-1.5 py-0.5 font-mono text-[12px]"
            />
          </Row>
          <Row label="Give the console an address (DHCP)">
            <Switch
              checked={draft.dhcp}
              onCheckedChange={(checked) => setDraft((current) => ({ ...current, dhcp: checked }))}
            />
          </Row>
          <Row label="Answer DNS aimed at this PC">
            <Switch
              checked={draft.dnsRelay}
              onCheckedChange={(checked) =>
                setDraft((current) => ({ ...current, dnsRelay: checked }))
              }
            />
          </Row>
          <Row label="When a connection drops, reset its TCP flows">
            <Switch
              checked={draft.tcpFailover === 'reset'}
              onCheckedChange={(checked) =>
                setDraft((current) => ({ ...current, tcpFailover: checked ? 'reset' : 'hold' }))
              }
            />
          </Row>
          <Row label="Let Plexo change this PC’s network settings">
            <Switch
              checked={draft.manageHost}
              onCheckedChange={(checked) =>
                setDraft((current) => ({ ...current, manageHost: checked }))
              }
            />
          </Row>
        </section>

        <section className="grid grid-cols-4 gap-2 rounded-[8px] bg-[var(--bg-secondary)] p-2.5 font-mono text-[11px] tabular-nums">
          <span className="flex flex-col">
            <span className="text-muted-foreground">down</span>
            {formatSpeed(snapshot?.downstreamThroughputBps ?? 0, speedUnit)}
          </span>
          <span className="flex flex-col">
            <span className="text-muted-foreground">flows</span>
            {snapshot?.flows.total ?? 0}
          </span>
          <span className="flex flex-col">
            <span className="text-muted-foreground">resets</span>
            {snapshot?.totals.resets ?? 0}
          </span>
          <span className="flex flex-col">
            <span className="text-muted-foreground">dropped</span>
            {snapshot?.totals.dropped ?? 0}
          </span>
        </section>

        <div className="flex items-center justify-between gap-2 pt-1">
          <div className="flex gap-1.5">
            <Button
              type="button"
              variant="secondary"
              className="text-[12px]"
              disabled={busy}
              onClick={async () => {
                setBusy(true)
                try {
                  const result = await window.plexo.gatewayAction('selfTest')
                  setDetail(result.detail ?? null)
                } finally {
                  setBusy(false)
                }
              }}
            >
              Test
            </Button>
            <Button
              type="button"
              variant="secondary"
              className="text-[12px]"
              disabled={busy}
              onClick={() => void apply(configFor({}))}
            >
              Save
            </Button>
          </div>
          <Button
            type="button"
            disabled={busy || (capability ? !capability.supported : true)}
            onClick={async () => {
              setBusy(true)
              try {
                if (running) {
                  await window.plexo.gatewayAction('stop')
                  setDraft((current) => ({ ...current, enabled: false }))
                } else {
                  // Save the edited settings first, then start: the console's port and uplinks are
                  // what starting needs, and this way there is one code path for both.
                  await apply(configFor({ enabled: true }))
                }
              } finally {
                setBusy(false)
              }
            }}
          >
            {running ? 'Stop gateway' : 'Start gateway'}
          </Button>
        </div>

        {detail && (
          <p className="rounded-[8px] bg-[var(--bg-secondary)] p-2.5 font-mono text-[11px] text-muted-foreground">
            {detail}
          </p>
        )}
      </DialogContent>
    </Dialog>
  )
}
