import type { GatewaySnapshot } from '@shared/gateway'
import { useCallback, useEffect, useState } from 'react'

/**
 * The gateway's state, as the main process pushes it: once a second while it runs, and immediately
 * after any change. The first fetch covers the case where the window opens after a push.
 */
export function useGateway(): {
  snapshot: GatewaySnapshot | null
  refresh: () => void
} {
  const [snapshot, setSnapshot] = useState<GatewaySnapshot | null>(null)

  useEffect(() => {
    let disposed = false
    void window.plexo
      .gatewaySnapshot()
      .then((next) => !disposed && setSnapshot(next))
      .catch(() => {})
    const unsubscribe = window.plexo.onGatewayChanged((next) => setSnapshot(next))
    return () => {
      disposed = true
      unsubscribe()
    }
  }, [])

  const refresh = useCallback(() => {
    void window.plexo
      .gatewaySnapshot()
      .then(setSnapshot)
      .catch(() => {})
  }, [])

  return { snapshot, refresh }
}
