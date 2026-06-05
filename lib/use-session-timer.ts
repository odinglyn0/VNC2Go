import * as React from "react"

export interface SessionTimerState {
  elapsedMs: number
  remainingMs: number | null
  idleRemainingMs: number
}

export function useSessionTimer(
  active: boolean,
  hardCapMs: number,
  idleCapMs: number,
  lastActivityRef: React.RefObject<number>,
): SessionTimerState {
  const [state, setState] = React.useState<SessionTimerState>({
    elapsedMs: 0,
    remainingMs: hardCapMs > 0 ? hardCapMs : null,
    idleRemainingMs: idleCapMs,
  })

  React.useEffect(() => {
    if (!active) {
      return
    }

    const startedAt = performance.now()

    const tick = () => {
      const now = performance.now()
      const elapsedMs = now - startedAt
      const remainingMs = hardCapMs > 0 ? Math.max(0, hardCapMs - elapsedMs) : null
      const sinceActivity = now - lastActivityRef.current
      const idleRemainingMs = Math.max(0, idleCapMs - sinceActivity)
      setState({ elapsedMs, remainingMs, idleRemainingMs })
    }

    tick()
    const interval = window.setInterval(tick, 1000)
    return () => window.clearInterval(interval)
  }, [active, hardCapMs, idleCapMs, lastActivityRef])

  return state
}

export function formatDuration(ms: number): string {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000))
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  return `${minutes.toString().padStart(2, "0")}:${seconds.toString().padStart(2, "0")}`
}
