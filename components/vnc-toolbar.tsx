"use client"

import * as React from "react"
import {
  ClockIcon,
  GripVerticalIcon,
  KeyboardIcon,
  MonitorIcon,
  PowerIcon,
  RotateCcwIcon,
  ShieldCheckIcon,
} from "lucide-react"

import type { ConnectionPhase } from "@/lib/connection"
import {
  Menubar,
  MenubarContent,
  MenubarItem,
  MenubarMenu,
  MenubarSeparator,
  MenubarShortcut,
  MenubarTrigger,
} from "@/components/ui/menubar"

interface VncToolbarProps {
  targetDisplay: string
  privateMode: boolean
  proxyCountry: string | null
  phase: ConnectionPhase
  connected: boolean
  timeLabel: string
  idleLabel: string
  hardCapped: boolean
  nearExpiry: boolean
  onCtrlAltDel: () => void
  onDisconnect: () => void
}

interface Position {
  x: number
  y: number
}

const MARGIN = 12

function statusLabel(phase: ConnectionPhase): string {
  switch (phase) {
    case "connected":
      return "Connected"
    case "credentials":
      return "Awaiting credentials"
    case "error":
      return "Connection error"
    default:
      return "Connecting"
  }
}

export function VncToolbar({
  targetDisplay,
  privateMode,
  proxyCountry,
  phase,
  connected,
  timeLabel,
  idleLabel,
  hardCapped,
  nearExpiry,
  onCtrlAltDel,
  onDisconnect,
}: VncToolbarProps) {
  const toolbarRef = React.useRef<HTMLDivElement | null>(null)
  const dragRef = React.useRef<{ offsetX: number; offsetY: number } | null>(null)
  const [position, setPosition] = React.useState<Position | null>(null)

  const clampToViewport = React.useCallback((x: number, y: number): Position => {
    const el = toolbarRef.current
    const width = el?.offsetWidth ?? 0
    const height = el?.offsetHeight ?? 0
    const maxX = Math.max(MARGIN, window.innerWidth - width - MARGIN)
    const maxY = Math.max(MARGIN, window.innerHeight - height - MARGIN)
    return {
      x: Math.min(Math.max(MARGIN, x), maxX),
      y: Math.min(Math.max(MARGIN, y), maxY),
    }
  }, [])

  React.useLayoutEffect(() => {
    if (position !== null) {
      return
    }
    const el = toolbarRef.current
    if (!el) {
      return
    }
    const width = el.offsetWidth
    setPosition({ x: Math.max(MARGIN, (window.innerWidth - width) / 2), y: MARGIN })
  }, [position])

  React.useEffect(() => {
    const onResize = () => {
      setPosition((current) => (current ? clampToViewport(current.x, current.y) : current))
    }
    window.addEventListener("resize", onResize)
    return () => window.removeEventListener("resize", onResize)
  }, [clampToViewport])

  const onHandlePointerDown = (event: React.PointerEvent<HTMLButtonElement>) => {
    const el = toolbarRef.current
    if (!el) {
      return
    }
    const rect = el.getBoundingClientRect()
    dragRef.current = { offsetX: event.clientX - rect.left, offsetY: event.clientY - rect.top }
    event.currentTarget.setPointerCapture(event.pointerId)
    event.preventDefault()
  }

  const onHandlePointerMove = (event: React.PointerEvent<HTMLButtonElement>) => {
    const drag = dragRef.current
    if (!drag) {
      return
    }
    setPosition(clampToViewport(event.clientX - drag.offsetX, event.clientY - drag.offsetY))
  }

  const onHandlePointerUp = (event: React.PointerEvent<HTMLButtonElement>) => {
    if (!dragRef.current) {
      return
    }
    dragRef.current = null
    try {
      event.currentTarget.releasePointerCapture(event.pointerId)
    } catch {
      void 0
    }
  }

  return (
    <div
      ref={toolbarRef}
      className="fixed z-50 flex items-center gap-1 rounded-xl border border-white/15 bg-card/70 p-1 shadow-2xl ring-1 ring-white/10 backdrop-blur-xl"
      style={{
        left: position?.x ?? 0,
        top: position?.y ?? 0,
        opacity: position ? 1 : 0,
      }}
    >
      <button
        type="button"
        aria-label="Drag toolbar"
        onPointerDown={onHandlePointerDown}
        onPointerMove={onHandlePointerMove}
        onPointerUp={onHandlePointerUp}
        onPointerCancel={onHandlePointerUp}
        className="flex h-8 w-6 shrink-0 touch-none cursor-grab items-center justify-center rounded-md text-muted-foreground select-none hover:bg-accent hover:text-accent-foreground active:cursor-grabbing"
      >
        <GripVerticalIcon className="size-4" />
      </button>

      <span
        className={`flex items-center gap-1 rounded-md px-2 py-1 font-mono text-xs tabular-nums ${
          nearExpiry ? "bg-destructive/20 text-destructive" : "text-muted-foreground"
        }`}
        title={hardCapped ? "Time remaining" : "Session duration"}
      >
        <ClockIcon className="size-3" />
        {timeLabel}
      </span>

      <Menubar className="h-auto border-0 bg-transparent p-0 shadow-none">
        <MenubarMenu>
          <MenubarTrigger className="gap-1.5">
            <MonitorIcon className="size-4" />
            <span className="hidden sm:inline">Session</span>
          </MenubarTrigger>
          <MenubarContent align="start" className="w-60">
            <MenubarItem disabled className="flex-col items-start gap-0.5">
              <span className="text-xs text-muted-foreground">Target</span>
              <span className="font-medium">{targetDisplay}</span>
            </MenubarItem>
            <MenubarItem disabled>
              Status
              <MenubarShortcut>{statusLabel(phase)}</MenubarShortcut>
            </MenubarItem>
            {privateMode && proxyCountry ? (
              <MenubarItem disabled>
                <ShieldCheckIcon className="size-4" />
                Private proxy
                <MenubarShortcut>{proxyCountry}</MenubarShortcut>
              </MenubarItem>
            ) : null}
            <MenubarSeparator />
            <MenubarItem disabled>
              {hardCapped ? "Time remaining" : "Elapsed"}
              <MenubarShortcut>{timeLabel}</MenubarShortcut>
            </MenubarItem>
            <MenubarItem disabled>
              Idle disconnect
              <MenubarShortcut>{idleLabel}</MenubarShortcut>
            </MenubarItem>
            <MenubarSeparator />
            <MenubarItem variant="destructive" onSelect={onDisconnect}>
              <PowerIcon className="size-4" />
              Disconnect
            </MenubarItem>
          </MenubarContent>
        </MenubarMenu>

        <MenubarMenu>
          <MenubarTrigger className="gap-1.5">
            <KeyboardIcon className="size-4" />
            <span className="hidden sm:inline">Keys</span>
          </MenubarTrigger>
          <MenubarContent align="start" className="w-52">
            <MenubarItem disabled={!connected} onSelect={onCtrlAltDel}>
              <RotateCcwIcon className="size-4" />
              Send Ctrl+Alt+Del
              <MenubarShortcut>⌃⌥⌦</MenubarShortcut>
            </MenubarItem>
          </MenubarContent>
        </MenubarMenu>
      </Menubar>

      <button
        type="button"
        onClick={onDisconnect}
        aria-label="Disconnect"
        className="flex h-8 items-center gap-1.5 rounded-md bg-destructive px-2.5 text-sm font-medium text-white transition-colors hover:bg-destructive/90"
      >
        <PowerIcon className="size-4" />
        <span className="hidden sm:inline">Disconnect</span>
      </button>
    </div>
  )
}
