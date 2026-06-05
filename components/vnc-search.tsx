"use client"

import * as React from "react"
import dynamic from "next/dynamic"
import { ArrowRightIcon, MonitorIcon, PowerIcon, RotateCcwIcon } from "lucide-react"
import { toast } from "sonner"
import { Loader } from "rsuite"

import type {
  ConnectionPhase,
  CredentialField,
  ResolveResponse,
  VncCredentials,
} from "@/lib/connection"
import { resolveVncAddress } from "@/lib/connection"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { VncLoginDialog } from "@/components/vnc-login-dialog"
import type { VncViewerHandle } from "@/components/vnc-viewer"

const VncViewer = dynamic(() => import("@/components/vnc-viewer").then((mod) => mod.VncViewer), {
  ssr: false,
  loading: () => (
    <div className="flex h-full w-full items-center justify-center bg-black">
      <Loader inverse size="md" content="Loading viewer" />
    </div>
  ),
})

type ViewerStatus = "connecting" | "credentials" | "connected" | "closed" | "error"

export function VncSearch() {
  const [address, setAddress] = React.useState("")
  const [phase, setPhase] = React.useState<ConnectionPhase>("idle")
  const [errorMessage, setErrorMessage] = React.useState<string | null>(null)
  const [connection, setConnection] = React.useState<ResolveResponse | null>(null)
  const [credentialFields, setCredentialFields] = React.useState<CredentialField[]>([])
  const [loginOpen, setLoginOpen] = React.useState(false)

  const viewerRef = React.useRef<VncViewerHandle | null>(null)
  const abortRef = React.useRef<AbortController | null>(null)

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

  const handleConnect = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault()
      const trimmed = address.trim()
      if (trimmed.length === 0) {
        setErrorMessage("Enter a VNC address to connect")
        return
      }

      abortRef.current?.abort()
      const controller = new AbortController()
      abortRef.current = controller

      setPhase("resolving")
      setErrorMessage(null)

      try {
        const result = await resolveVncAddress(trimmed, controller.signal)
        setConnection(result)
        setPhase("connecting")
        toast.info(`Connecting to ${result.target.display}`)
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
    [address],
  )

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

  const isBusy = phase === "resolving"
  const showViewer = connection !== null && (phase === "connecting" || phase === "credentials" || phase === "connected")

  if (showViewer && connection) {
    return (
      <div className="flex h-svh w-full flex-col bg-background">
        <header className="flex items-center justify-between gap-3 border-b px-4 py-3">
          <div className="flex items-center gap-3">
            <span className="font-coolvetica text-2xl leading-none">VNC2Go</span>
            <Badge variant="secondary" className="gap-1">
              <MonitorIcon className="size-3" />
              {connection.target.display}
            </Badge>
            <StatusBadge phase={phase} />
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => viewerRef.current?.sendCtrlAltDel()}
              disabled={phase !== "connected"}
            >
              <RotateCcwIcon className="size-4" />
              Ctrl+Alt+Del
            </Button>
            <Button variant="destructive" size="sm" onClick={resetToSearch}>
              <PowerIcon className="size-4" />
              Disconnect
            </Button>
          </div>
        </header>

        <main className="min-h-0 flex-1 p-3">
          <VncViewer
            ref={viewerRef}
            proxyUrl={connection.proxyUrl}
            target={connection.target}
            onStatusChange={handleStatusChange}
            onCredentialsRequired={handleCredentialsRequired}
          />
        </main>

        <VncLoginDialog
          open={loginOpen}
          fields={credentialFields}
          target={connection.target}
          onSubmit={handleCredentialSubmit}
          onCancel={handleCredentialCancel}
        />
      </div>
    )
  }

  return (
    <main className="relative flex min-h-svh flex-col items-center justify-center gap-10 px-4">
      <div className="flex flex-col items-center gap-3 text-center">
        <h1 className="font-coolvetica text-6xl tracking-tight sm:text-7xl md:text-8xl">VNC2Go</h1>
        <p className="max-w-md text-sm text-muted-foreground sm:text-base">
          Private. VNC. In-browser. Wait, did I mention it's private?
        </p>
      </div>

      <form onSubmit={handleConnect} className="flex w-full max-w-xl flex-col gap-3">
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
            {isBusy ? (
              <Loader inverse size="xs" />
            ) : (
              <ArrowRightIcon className="size-5" />
            )}
          </Button>
        </div>

        <p className="flex items-center justify-center gap-1.5 text-center text-xs text-muted-foreground">
          Defaults to 5900
        </p>
      </form>

      {errorMessage ? (
        <Alert variant="destructive" className="max-w-xl">
          <AlertTitle>Could not connect</AlertTitle>
          <AlertDescription>{errorMessage}</AlertDescription>
        </Alert>
      ) : null}
    </main>
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
    return <Badge variant="destructive">Error</Badge>
  }
  return <Badge variant="secondary">Connecting</Badge>
}
