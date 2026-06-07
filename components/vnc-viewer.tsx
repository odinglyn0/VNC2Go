"use client"

import * as React from "react"
import RFB from "@novnc/novnc"
import { Loader } from "rsuite"

import type { CredentialField, ResolvedTarget, VncCredentials } from "@/lib/connection"

type ViewerStatus = "connecting" | "credentials" | "connected" | "closed" | "error"

const CLOSE_NORMAL = 1000
const CLOSE_NO_STATUS = 1005
const CLOSE_ABNORMAL = 1006
const CLOSE_IDLE_TIMEOUT = 4000
const CLOSE_HARD_CAP = 4001
const CLOSE_FRAME_TOO_LARGE = 4009
const CLOSE_REMOTE_UNREACHABLE = 4502
const CLOSE_WRITE_FAILED = 4503
const CLOSE_CONNECTION_LOST = 4504
const CLOSE_SERVER_CLOSED = 4505

const CLOSE_MESSAGES: Record<number, string> = {
  [CLOSE_NORMAL]: "The session ended.",
  [CLOSE_IDLE_TIMEOUT]: "Disconnected after 3 minutes of inactivity.",
  [CLOSE_HARD_CAP]: "The private session reached its 10 minute limit.",
  [CLOSE_FRAME_TOO_LARGE]: "The VNC server sent too much data at once.",
  [CLOSE_REMOTE_UNREACHABLE]:
    "Could not reach the VNC server. Check the address and that the server is online.",
  [CLOSE_WRITE_FAILED]: "Lost the link to the VNC server.",
  [CLOSE_CONNECTION_LOST]: "The connection to the VNC server was lost.",
  [CLOSE_SERVER_CLOSED]: "The VNC server closed the connection.",
}

const GRACEFUL_CLOSE_CODES = new Set([
  CLOSE_NORMAL,
  CLOSE_NO_STATUS,
  CLOSE_IDLE_TIMEOUT,
  CLOSE_HARD_CAP,
  CLOSE_SERVER_CLOSED,
])

function isGracefulClose(info: { code: number; reason: string } | null): boolean {
  if (!info) {
    return false
  }
  return GRACEFUL_CLOSE_CODES.has(info.code)
}

function describeClose(
  info: { code: number; reason: string } | null,
  clean: boolean,
): string {
  if (info) {
    if (info.reason && info.reason.trim().length > 0) {
      return info.reason.trim()
    }
    const mapped = CLOSE_MESSAGES[info.code]
    if (mapped) {
      return mapped
    }
    if (info.code === CLOSE_ABNORMAL) {
      return "Could not reach the VNC server. Check the address and that the server is online."
    }
  }
  return clean ? "The session ended." : "The connection was lost unexpectedly."
}

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
        try {
          rfbRef.current?.disconnect()
        } catch {
          rfbRef.current = null
        }
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
    let connectionClosed = false
    let closeInfo: { code: number; reason: string } | null = null
    setShowLoader(true)
    statusChangeRef.current("connecting")

    const socket = new WebSocket(proxyUrl)
    socket.binaryType = "arraybuffer"
    socket.addEventListener("close", (event) => {
      closeInfo = { code: event.code, reason: event.reason }
    })

    const rfb = new RFB(container, socket)
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
      connectionClosed = true
      if (disposed) {
        return
      }
      setShowLoader(false)
      const message = describeClose(closeInfo, event.detail.clean)
      if (event.detail.clean && isGracefulClose(closeInfo)) {
        statusChangeRef.current("closed", message)
      } else {
        statusChangeRef.current("error", message)
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
      connectionClosed = true
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
      if (!connectionClosed) {
        try {
          rfb.disconnect()
        } catch {
          statusChangeRef.current("closed")
        }
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
