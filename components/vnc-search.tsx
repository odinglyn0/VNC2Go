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
import { VncToolbar } from "@/components/vnc-toolbar"
import type { VncViewerHandle } from "@/components/vnc-viewer"

const VncViewer = dynamic(() => import("@/components/vnc-viewer").then((mod) => mod.VncViewer), {
  ssr: false,
  loading: () => (
    <div className="flex h-full w-full items-center justify-center bg-black">
      <Loader inverse size="md" content="Loading viewer" />
    </div>
  ),
})

const GrainGradient = dynamic(
  () => import("@paper-design/shaders-react").then((mod) => mod.GrainGradient),
  { ssr: false },
)

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
        <div className="relative flex h-svh w-full flex-col bg-background">
          <main className="relative min-h-0 flex-1 p-3">
            <div className="pointer-events-none absolute inset-0 overflow-hidden">
              <GrainGradient
                className="h-full w-full"
                width="100%"
                height="100%"
                colors={["#7300ff", "#eba8ff", "#00bfff", "#2b00ff"]}
                colorBack="#000000"
                softness={0.5}
                intensity={0.5}
                noise={0.25}
                shape="corners"
                speed={1}
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

          <VncToolbar
            targetDisplay={connection.target.display}
            privateMode={connection.privateMode}
            proxyCountry={connection.proxyCountry}
            phase={phase}
            connected={phase === "connected"}
            timeLabel={hardLabel}
            idleLabel={formatDuration(timer.idleRemainingMs)}
            hardCapped={connection.hardCapMs > 0}
            nearExpiry={timer.remainingMs !== null && timer.remainingMs < 60000}
            onCtrlAltDel={() => viewerRef.current?.sendCtrlAltDel()}
            onDisconnect={handleDisconnect}
          />

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
    <div className="relative flex h-svh flex-col items-center justify-between overflow-hidden">
      <div className="pointer-events-none absolute inset-0 z-0">
        <GrainGradient
          className="h-full w-full"
          width="100%"
          height="100%"
          colors={["#ae00ff", "#00ff95", "#ffc105"]}
          colorBack="#000a0f"
          softness={0.7}
          intensity={0.44}
          noise={0.5}
          shape="wave"
          speed={1}
          offsetX={0.22}
          offsetY={0.3}
        />
        <div className="absolute inset-0 bg-background/30" />
      </div>

      <div className="relative z-10 flex w-full min-h-0 flex-1 flex-col items-center justify-center gap-10 px-4 py-16">
        <div className="flex flex-col items-center gap-3 text-center mix-blend-difference">
          <h1 className="font-coolvetica text-6xl tracking-tight text-white sm:text-7xl md:text-8xl">
            VNC2Go
          </h1>
          <p className="max-w-md text-sm text-white/90 sm:text-base">
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

          <div className="flex items-center justify-between gap-3 rounded-xl border border-input bg-card px-4 py-3 ring-1 ring-foreground/5">
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
        </form>

        {errorMessage ? (
          <Alert variant="destructive" className="max-w-xl">
            <AlertTitle>Could not connect</AlertTitle>
            <AlertDescription>{errorMessage}</AlertDescription>
          </Alert>
        ) : null}
      </div>

      <div className="relative z-10 flex w-full justify-center">
        <SiteFooter />
      </div>

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
