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
  onActivity: () => void
}

export interface VncViewerHandle {
  submitCredentials: (credentials: VncCredentials) => void
  disconnect: () => void
  sendCtrlAltDel: () => void
  clipboardPaste: (text: string) => void
}

export const VncViewer = React.forwardRef<VncViewerHandle, VncViewerProps>(function VncViewer(
  { proxyUrl, target, onStatusChange, onCredentialsRequired, onActivity },
  ref,
) {
  const containerRef = React.useRef<HTMLDivElement | null>(null)
  const mirrorRef = React.useRef<HTMLCanvasElement | null>(null)
  const rfbRef = React.useRef<RFB | null>(null)
  const [showLoader, setShowLoader] = React.useState(true)

  const statusChangeRef = React.useRef(onStatusChange)
  const credentialsRef = React.useRef(onCredentialsRequired)
  const activityRef = React.useRef(onActivity)

  React.useEffect(() => {
    statusChangeRef.current = onStatusChange
    credentialsRef.current = onCredentialsRequired
    activityRef.current = onActivity
  }, [onStatusChange, onCredentialsRequired, onActivity])

  React.useImperativeHandle(
    ref,
    () => ({
      submitCredentials(credentials: VncCredentials) {
        const rfb = rfbRef.current
        if (!rfb) {
          return
        }
        rfb.sendCredentials({
          username: credentials.username ?? "",
          password: credentials.password ?? "",
          target: credentials.target ?? "",
        })
        setShowLoader(true)
        statusChangeRef.current("connecting")
      },
      disconnect() {
        rfbRef.current?.disconnect()
      },
      sendCtrlAltDel() {
        rfbRef.current?.sendCtrlAltDel()
      },
      clipboardPaste(text: string) {
        rfbRef.current?.clipboardPasteFrom(text)
      },
    }),
    [],
  )

  React.useEffect(() => {
    let raf = 0
    let disposed = false

    const draw = () => {
      if (disposed) {
        return
      }
      const mirror = mirrorRef.current
      const container = containerRef.current
      const source = container?.querySelector("canvas") as HTMLCanvasElement | null
      if (mirror && source && source.width > 0 && source.height > 0) {
        if (mirror.width !== source.width || mirror.height !== source.height) {
          mirror.width = source.width
          mirror.height = source.height
        }
        const ctx = mirror.getContext("2d")
        if (ctx) {
          ctx.clearRect(0, 0, mirror.width, mirror.height)
          ctx.drawImage(source, 0, 0)
        }
      }
      raf = requestAnimationFrame(draw)
    }

    raf = requestAnimationFrame(draw)
    return () => {
      disposed = true
      cancelAnimationFrame(raf)
    }
  }, [proxyUrl])

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
    rfb.showDotCursor = true
    rfb.background = "transparent"
    rfbRef.current = rfb

    const markActivity = () => activityRef.current()

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

    container.addEventListener("mousedown", markActivity)
    container.addEventListener("keydown", markActivity)
    container.addEventListener("touchstart", markActivity, { passive: true })

    return () => {
      disposed = true
      rfb.removeEventListener("connect", handleConnect)
      rfb.removeEventListener("disconnect", handleDisconnect)
      rfb.removeEventListener("credentialsrequired", handleCredentials)
      rfb.removeEventListener("securityfailure", handleSecurityFailure)
      container.removeEventListener("mousedown", markActivity)
      container.removeEventListener("keydown", markActivity)
      container.removeEventListener("touchstart", markActivity)
      try {
        rfb.disconnect()
      } catch {
        statusChangeRef.current("closed")
      }
      rfbRef.current = null
    }
  }, [proxyUrl])

  return (
    <div className="relative h-full w-full bg-transparent">
      <canvas
        ref={mirrorRef}
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 z-0 h-full w-full scale-[1.03] object-contain opacity-80 blur-2xl"
      />
      <div className="absolute inset-0 z-10 h-full w-full overflow-hidden rounded-xl">
        <div
          ref={containerRef}
          className="absolute inset-0 h-full w-full"
          aria-label={`VNC session for ${target.display}`}
        />
      </div>
      {showLoader ? (
        <div className="pointer-events-none absolute inset-0 z-20 flex flex-col items-center justify-center gap-3 bg-black/40">
          <Loader inverse size="md" content={`Connecting to ${target.display}`} />
        </div>
      ) : null}
    </div>
  )
})
