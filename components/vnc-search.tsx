"use client"

import * as React from "react"
import dynamic from "next/dynamic"
import {
  ArrowRightIcon,
  ClockIcon,
  MonitorIcon,
  PowerIcon,
  RotateCcwIcon,
  ShieldCheckIcon,
} from "lucide-react"
import { toast } from "sonner"
import { Loader } from "rsuite"

import type {
  ConnectionPhase,
  CredentialField,
  ResolveResponse,
  VncCredentials,
} from "@/lib/connection"
import { resolveVncAddress } from "@/lib/connection"
import { formatDuration, useSessionTimer } from "@/lib/use-session-timer"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { HumanGate } from "@/components/human-gate"
import { VncLoginDialog } from "@/components/vnc-login-dialog"
import { SiteFooter } from "@/components/site-footer"
import type { VncViewerHandle } from "@/components/vnc-viewer"

const VncViewer = dynamic(() => import("@/components/vnc-viewer").then((mod) => mod.VncViewer), {
  ssr: false,
  loading: () => (
    <div className="flex h-full w-full items-center justify-center bg-black">
      <Loader inverse size="md" content="Loading viewer" />
    </div>
  ),
})

const MeshGradient = dynamic(
  () => import("@paper-design/shaders-react").then((mod) => mod.MeshGradient),
  { ssr: false },
)

function hslToHex(h: number, s: number, l: number): string {
  const saturation = s / 100
  const lightness = l / 100
  const a = saturation * Math.min(lightness, 1 - lightness)
  const channel = (n: number) => {
    const k = (n + h / 30) % 12
    const value = lightness - a * Math.max(-1, Math.min(k - 3, 9 - k, 1))
    return Math.round(255 * value)
      .toString(16)
      .padStart(2, "0")
  }
  return `#${channel(0)}${channel(8)}${channel(4)}`
}

function randomGradientColors(): string[] {
  const baseHue = Math.floor(Math.random() * 360)
  return [
    hslToHex(baseHue % 360, 30 + Math.random() * 25, 86 + Math.random() * 8),
    hslToHex((baseHue + 35 + Math.random() * 60) % 360, 72 + Math.random() * 24, 20 + Math.random() * 16),
    hslToHex((baseHue + 150 + Math.random() * 60) % 360, 70 + Math.random() * 25, 52 + Math.random() * 12),
    hslToHex((baseHue + 240 + Math.random() * 60) % 360, 62 + Math.random() * 30, 54 + Math.random() * 14),
  ]
}

type ViewerStatus = "connecting" | "credentials" | "connected" | "closed" | "error"

export function VncSearch() {
  const [address, setAddress] = React.useState("")
  const [privateMode, setPrivateMode] = React.useState(false)
  const [phase, setPhase] = React.useState<ConnectionPhase>("idle")
  const [errorMessage, setErrorMessage] = React.useState<string | null>(null)
  const [connection, setConnection] = React.useState<ResolveResponse | null>(null)
  const [credentialFields, setCredentialFields] = React.useState<CredentialField[]>([])
  const [loginOpen, setLoginOpen] = React.useState(false)
  const [humanGateOpen, setHumanGateOpen] = React.useState(false)
  const [verified, setVerified] = React.useState(false)
  const [gradientColors, setGradientColors] = React.useState<string[]>(() => [
    "#e0eaff",
    "#241d9a",
    "#f75092",
    "#9f50d3",
  ])

  const viewerRef = React.useRef<VncViewerHandle | null>(null)
  const abortRef = React.useRef<AbortController | null>(null)
  const lastActivityRef = React.useRef<number>(0)
  const pendingConnectRef = React.useRef(false)

  const timer = useSessionTimer(
    phase === "connected",
    connection?.hardCapMs ?? 0,
    connection?.idleCapMs ?? 0,
    lastActivityRef,
  )

  const resetToSearch = React.useCallback(() => {
    abortRef.current?.abort()
    abortRef.current = null
    viewerRef.current?.disconnect()
    setConnection(null)
    setCredentialFields([])
    setLoginOpen(false)
    setPhase("idle")
    setErrorMessage(null)
  }, [])

  const startResolve = React.useCallback(
    async (trimmed: string, usePrivate: boolean) => {
      abortRef.current?.abort()
      const controller = new AbortController()
      abortRef.current = controller

      setPhase("resolving")
      setErrorMessage(null)
      setGradientColors(randomGradientColors())

      try {
        const result = await resolveVncAddress(trimmed, usePrivate, controller.signal)
        lastActivityRef.current = performance.now()
        setConnection(result)
        setPhase("connecting")
        if (result.privateMode && result.proxyCountry) {
          toast.info(`Private mode via ${result.proxyCountry}. Hard cap ${Math.round(result.hardCapMs / 60000)} min.`)
        } else {
          toast.info(`Connecting to ${result.target.display}`)
        }
      } catch (error) {
        if (controller.signal.aborted) {
          return
        }
        const message = error instanceof Error ? error.message : "Unable to resolve the VNC address"
        setErrorMessage(message)
        setPhase("error")
        toast.error(message)
      }
    },
    [],
  )

  const handleConnect = React.useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault()
      const trimmed = address.trim()
      if (trimmed.length === 0) {
        setErrorMessage("Enter a VNC address to connect")
        return
      }

      if (!verified) {
        pendingConnectRef.current = true
        setHumanGateOpen(true)
        return
      }

      void startResolve(trimmed, privateMode)
    },
    [address, privateMode, verified, startResolve],
  )

  const handleVerified = React.useCallback(() => {
    setVerified(true)
    setHumanGateOpen(false)
    toast.success("Verified")
    if (pendingConnectRef.current) {
      pendingConnectRef.current = false
      const trimmed = address.trim()
      if (trimmed.length > 0) {
        void startResolve(trimmed, privateMode)
      }
    }
  }, [address, privateMode, startResolve])

  const handleStatusChange = React.useCallback((status: ViewerStatus, detail?: string) => {
    switch (status) {
      case "connecting":
        setPhase("connecting")
        break
      case "credentials":
        setPhase("credentials")
        break
      case "connected":
        setPhase("connected")
        setLoginOpen(false)
        lastActivityRef.current = performance.now()
        toast.success("Connected")
        break
      case "closed":
        setPhase("idle")
        setConnection(null)
        setLoginOpen(false)
        if (detail) {
          toast.message(detail)
        }
        break
      case "error":
        setPhase("error")
        setLoginOpen(false)
        if (detail) {
          setErrorMessage(detail)
          toast.error(detail)
        }
        break
    }
  }, [])

  const handleCredentialsRequired = React.useCallback((fields: CredentialField[]) => {
    setCredentialFields(fields)
    setLoginOpen(true)
  }, [])

  const handleCredentialSubmit = React.useCallback((credentials: VncCredentials) => {
    setLoginOpen(false)
    setPhase("connecting")
    viewerRef.current?.submitCredentials(credentials)
  }, [])

  const handleCredentialCancel = React.useCallback(() => {
    setLoginOpen(false)
    resetToSearch()
    toast.message("Authentication cancelled")
  }, [resetToSearch])

  const handleActivity = React.useCallback(() => {
    lastActivityRef.current = performance.now()
  }, [])

  const handleDisconnect = React.useCallback(() => {
    abortRef.current?.abort()
    try {
      viewerRef.current?.disconnect()
    } catch {
      void 0
    }
    window.location.reload()
  }, [])

  const isBusy = phase === "resolving"
  const showViewer =
    connection !== null && (phase === "connecting" || phase === "credentials" || phase === "connected")

  if (showViewer && connection) {
    const hardLabel = connection.hardCapMs > 0 && timer.remainingMs !== null
      ? formatDuration(timer.remainingMs)
      : formatDuration(timer.elapsedMs)

    return (
      <TooltipProvider>
        <div className="flex h-svh w-full flex-col bg-background">
          <header className="flex h-14 shrink-0 items-center justify-between gap-3 border-b px-4">
            <div className="flex min-w-0 items-center gap-3">
              <span className="font-coolvetica text-2xl leading-none">VNC2Go</span>
              <Badge variant="secondary" className="gap-1">
                <MonitorIcon className="size-3" />
                <span className="truncate">{connection.target.display}</span>
              </Badge>
              {connection.privateMode && connection.proxyCountry ? (
                <Badge variant="outline" className="gap-1">
                  <ShieldCheckIcon className="size-3" />
                  Private · {connection.proxyCountry}
                </Badge>
              ) : null}
              <StatusBadge phase={phase} />
            </div>

            <div className="flex items-center gap-2">
              <Tooltip>
                <TooltipTrigger asChild>
                  <Badge
                    variant={timer.remainingMs !== null && timer.remainingMs < 60000 ? "destructive" : "secondary"}
                    className="gap-1 font-mono tabular-nums"
                  >
                    <ClockIcon className="size-3" />
                    {hardLabel}
                  </Badge>
                </TooltipTrigger>
                <TooltipContent>
                  {connection.hardCapMs > 0
                    ? "Time remaining before the session ends"
                    : "Session duration"}
                  <br />
                  Idle disconnect in {formatDuration(timer.idleRemainingMs)}
                </TooltipContent>
              </Tooltip>

              <Button
                variant="outline"
                size="sm"
                onClick={() => viewerRef.current?.sendCtrlAltDel()}
                disabled={phase !== "connected"}
              >
                <RotateCcwIcon className="size-4" />
                <span className="hidden sm:inline">Ctrl+Alt+Del</span>
              </Button>
              <Button variant="destructive" size="sm" onClick={handleDisconnect}>
                <PowerIcon className="size-4" />
                <span className="hidden sm:inline">Disconnect</span>
              </Button>
            </div>
          </header>

          <main className="relative min-h-0 flex-1 p-3">
            <div className="pointer-events-none absolute inset-0 overflow-hidden">
              <MeshGradient
                className="h-full w-full"
                width="100%"
                height="100%"
                colors={gradientColors}
                distortion={0.39}
                swirl={0.2}
                speed={0.5}
                scale={0.5}
              />
            </div>
            <div className="relative h-full w-full">
              <VncViewer
                ref={viewerRef}
                proxyUrl={connection.proxyUrl}
                target={connection.target}
                onStatusChange={handleStatusChange}
                onCredentialsRequired={handleCredentialsRequired}
                onActivity={handleActivity}
              />
            </div>
          </main>

          <VncLoginDialog
            open={loginOpen}
            fields={credentialFields}
            target={connection.target}
            onSubmit={handleCredentialSubmit}
            onCancel={handleCredentialCancel}
          />
        </div>
      </TooltipProvider>
    )
  }

  return (
    <div className="flex min-h-svh flex-col items-center justify-between">
      <div className="flex w-full flex-1 flex-col items-center justify-center gap-10 px-4 py-16">
        <div className="flex flex-col items-center gap-3 text-center">
          <h1 className="font-coolvetica text-6xl tracking-tight sm:text-7xl md:text-8xl">VNC2Go</h1>
          <p className="max-w-md text-sm text-muted-foreground sm:text-base">
            Private. VNC. In-browser. Wait, did I mention it&apos;s private?
          </p>
        </div>

        <form onSubmit={handleConnect} className="flex w-full max-w-xl flex-col gap-4">
          <div className="flex items-center gap-2 rounded-full border border-input bg-card px-2 py-1.5 ring-1 ring-foreground/5 transition-colors focus-within:border-ring focus-within:ring-3 focus-within:ring-ring/40">
            <MonitorIcon className="ml-2 size-5 shrink-0 text-muted-foreground" />
            <Input
              value={address}
              onChange={(event) => setAddress(event.target.value)}
              placeholder="vnc.example.com  or  192.0.2.10:5901"
              autoComplete="off"
              autoCapitalize="off"
              autoCorrect="off"
              spellCheck={false}
              inputMode="url"
              aria-label="VNC address"
              className="h-10 flex-1 border-0 bg-transparent text-base shadow-none focus-visible:border-0 focus-visible:ring-0"
            />
            <Button
              type="submit"
              size="icon"
              className="size-10 shrink-0 rounded-full"
              disabled={isBusy}
              aria-label="Connect"
            >
              {isBusy ? <Loader inverse size="xs" /> : <ArrowRightIcon className="size-5" />}
            </Button>
          </div>

          <div className="flex items-center justify-between gap-3 rounded-xl border bg-card/50 px-4 py-3">
            <div className="flex flex-col gap-0.5">
              <Label htmlFor="private-mode" className="flex items-center gap-1.5 text-sm font-medium">
                <ShieldCheckIcon className="size-4" />
                Private mode
              </Label>
              <span className="text-xs text-muted-foreground">
                Route through a random proxy. Sessions are limited to 10m
              </span>
            </div>
            <Switch id="private-mode" checked={privateMode} onCheckedChange={setPrivateMode} />
          </div>

          <p className="flex items-center justify-center gap-1.5 text-center text-xs text-muted-foreground">
            Defaults to port 5900.
          </p>
        </form>

        {errorMessage ? (
          <Alert variant="destructive" className="max-w-xl">
            <AlertTitle>Could not connect</AlertTitle>
            <AlertDescription>{errorMessage}</AlertDescription>
          </Alert>
        ) : null}
      </div>

      <SiteFooter />

      <HumanGate open={humanGateOpen} onVerified={handleVerified} />
    </div>
  )
}

function StatusBadge({ phase }: { phase: ConnectionPhase }) {
  if (phase === "connected") {
    return <Badge className="bg-emerald-600 text-white">Connected</Badge>
  }
  if (phase === "credentials") {
    return <Badge variant="outline">Awaiting credentials</Badge>
  }
  if (phase === "error") {
    return <Badge variant="destructive">Fuck, something broke</Badge>
  }
  return <Badge variant="secondary">Connecting</Badge>
}
