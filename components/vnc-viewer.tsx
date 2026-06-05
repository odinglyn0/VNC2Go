"use client"

import * as React from "react"
import RFB from "@novnc/novnc"
import { Loader } from "rsuite"

import type { CredentialField, ResolvedTarget, VncCredentials } from "@/lib/connection"

type ViewerStatus = "connecting" | "credentials" | "connected" | "closed" | "error"

interface VncViewerProps {
  proxyUrl: string
  target: ResolvedTarget
  onStatusChange: (status: ViewerStatus, detail?: string) => void
  onCredentialsRequired: (fields: CredentialField[]) => void
}

export interface VncViewerHandle {
  submitCredentials: (credentials: VncCredentials) => void
  disconnect: () => void
  sendCtrlAltDel: () => void
}

export const VncViewer = React.forwardRef<VncViewerHandle, VncViewerProps>(function VncViewer(
  { proxyUrl, target, onStatusChange, onCredentialsRequired },
  ref,
) {
  const containerRef = React.useRef<HTMLDivElement | null>(null)
  const rfbRef = React.useRef<RFB | null>(null)
  const [showLoader, setShowLoader] = React.useState(true)

  const statusChangeRef = React.useRef(onStatusChange)
  const credentialsRef = React.useRef(onCredentialsRequired)

  React.useEffect(() => {
    statusChangeRef.current = onStatusChange
    credentialsRef.current = onCredentialsRequired
  }, [onStatusChange, onCredentialsRequired])

  React.useImperativeHandle(
    ref,
    () => ({
      submitCredentials(credentials: VncCredentials) {
        const rfb = rfbRef.current
        if (!rfb) {
          return
        }
        const payload = {
          username: credentials.username ?? "",
          password: credentials.password ?? "",
          target: credentials.target ?? "",
        }
        rfb.sendCredentials(payload)
        setShowLoader(true)
        statusChangeRef.current("connecting")
      },
      disconnect() {
        rfbRef.current?.disconnect()
      },
      sendCtrlAltDel() {
        rfbRef.current?.sendCtrlAltDel()
      },
    }),
    [],
  )

  React.useEffect(() => {
    const container = containerRef.current
    if (!container) {
      return
    }

    let disposed = false
    setShowLoader(true)
    statusChangeRef.current("connecting")

    const rfb = new RFB(container, proxyUrl)
    rfb.viewOnly = false
    rfb.focusOnClick = true
    rfb.scaleViewport = true
    rfb.clipViewport = true
    rfb.resizeSession = false
    rfb.background = "transparent"
    rfbRef.current = rfb

    const handleConnect = () => {
      if (disposed) {
        return
      }
      setShowLoader(false)
      statusChangeRef.current("connected")
      rfb.focus()
    }

    const handleDisconnect = (event: CustomEvent<{ clean: boolean }>) => {
      if (disposed) {
        return
      }
      setShowLoader(false)
      if (event.detail.clean) {
        statusChangeRef.current("closed", "The session ended.")
      } else {
        statusChangeRef.current("error", "The connection was lost unexpectedly.")
      }
    }

    const handleCredentials = (event: CustomEvent<{ types: CredentialField[] }>) => {
      if (disposed) {
        return
      }
      setShowLoader(false)
      statusChangeRef.current("credentials")
      credentialsRef.current(event.detail.types)
    }

    const handleSecurityFailure = (event: CustomEvent<{ status: number; reason?: string }>) => {
      if (disposed) {
        return
      }
      setShowLoader(false)
      const reason = event.detail.reason
        ? event.detail.reason
        : `Authentication failed (status ${event.detail.status}).`
      statusChangeRef.current("error", reason)
    }

    rfb.addEventListener("connect", handleConnect)
    rfb.addEventListener("disconnect", handleDisconnect)
    rfb.addEventListener("credentialsrequired", handleCredentials)
    rfb.addEventListener("securityfailure", handleSecurityFailure)

    return () => {
      disposed = true
      rfb.removeEventListener("connect", handleConnect)
      rfb.removeEventListener("disconnect", handleDisconnect)
      rfb.removeEventListener("credentialsrequired", handleCredentials)
      rfb.removeEventListener("securityfailure", handleSecurityFailure)
      try {
        rfb.disconnect()
      } catch {
        statusChangeRef.current("closed")
      }
      rfbRef.current = null
    }
  }, [proxyUrl])

  return (
    <div className="relative h-full w-full overflow-hidden rounded-lg bg-black">
      <div
        ref={containerRef}
        className="h-full w-full"
        aria-label={`VNC session for ${target.display}`}
      />
      {showLoader ? (
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center gap-3 bg-black/70">
          <Loader inverse size="md" content={`Connecting to ${target.display}`} />
        </div>
      ) : null}
    </div>
  )
})
