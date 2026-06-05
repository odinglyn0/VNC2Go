import { connect } from "cloudflare:sockets"

import { deriveIteSession, encryptFrame, decryptFrame, generateHandshakeKeys, importPeerPublicKey, type IteSession } from "./ite-crypto"
import {
  ControlOp,
  FrameType,
  ITE_PROTOCOL_VERSION,
  buildHandshakeFrame,
  decodeApplicationFrame,
  encodeApplicationFrame,
  encodeControl,
  parseHandshakeFrame,
} from "./ite-protocol"
import { openWebshareTunnel } from "./webshare"
import { verifyVncToken, type VncTokenClaims } from "./token"

export interface Env {
  VNC_PROXY_SECRET: string
  ALLOWED_ORIGINS: string
  WEBSHARE_PROXY_USERNAME?: string
  WEBSHARE_PROXY_PASSWORD?: string
  WEBSHARE_PROXY_HOST?: string
  WEBSHARE_PROXY_PORT?: string
}

const MAX_PORT = 65535
const MAX_FRAME_BYTES = 4 * 1024 * 1024

function parseAllowedOrigins(raw: string): string[] {
  return raw
    .split(",")
    .map((value) => value.trim().replace(/\/+$/, "").toLowerCase())
    .filter((value) => value.length > 0)
}

function isOriginAllowed(origin: string | null, env: Env): boolean {
  const allowed = parseAllowedOrigins(env.ALLOWED_ORIGINS)
  if (allowed.length === 0) {
    return false
  }
  if (allowed.includes("*")) {
    return true
  }
  if (!origin) {
    return false
  }
  return allowed.includes(origin.replace(/\/+$/, "").toLowerCase())
}

function badRequest(message: string, status = 400): Response {
  return new Response(message, { status, headers: { "content-type": "text/plain" } })
}

interface RemoteConnection {
  readable: ReadableStream<Uint8Array>
  writable: WritableStream<Uint8Array>
  closed: Promise<void>
  close: () => void
}

async function openRemote(claims: VncTokenClaims, env: Env): Promise<RemoteConnection> {
  if (claims.privateMode) {
    if (!env.WEBSHARE_PROXY_USERNAME || !env.WEBSHARE_PROXY_PASSWORD) {
      throw new Error("Private mode proxy is not configured")
    }
    return openWebshareTunnel({
      targetHost: claims.host,
      targetPort: claims.port,
      country: claims.proxyCountry,
      sessionId: claims.sid,
      proxyHost: env.WEBSHARE_PROXY_HOST ?? "p.webshare.io",
      proxyPort: Number.parseInt(env.WEBSHARE_PROXY_PORT ?? "80", 10),
      username: env.WEBSHARE_PROXY_USERNAME,
      password: env.WEBSHARE_PROXY_PASSWORD,
    })
  }

  const socket = connect(
    { hostname: claims.host, port: claims.port },
    { allowHalfOpen: false, secureTransport: "off" },
  )
  return {
    readable: socket.readable,
    writable: socket.writable,
    closed: socket.closed,
    close: () => {
      socket.close().catch(() => undefined)
    },
  }
}

async function handleConnect(request: Request, env: Env): Promise<Response> {
  if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
    return badRequest("Expected a WebSocket upgrade", 426)
  }

  if (!isOriginAllowed(request.headers.get("Origin"), env)) {
    return badRequest("Origin is not allowed", 403)
  }

  if (!env.VNC_PROXY_SECRET) {
    return badRequest("Proxy is missing its signing secret", 500)
  }

  const url = new URL(request.url)
  const token = url.searchParams.get("token")
  if (!token) {
    return badRequest("A connection token is required", 401)
  }

  const claims = await verifyVncToken(token, env.VNC_PROXY_SECRET)
  if (!claims) {
    return badRequest("The connection token is invalid or expired", 401)
  }

  if (claims.port < 1 || claims.port > MAX_PORT) {
    return badRequest("The token contains an invalid port", 400)
  }

  const pair = new WebSocketPair()
  const client = pair[0]
  const server = pair[1]
  server.accept()

  runSession(server, claims, env).catch(() => {
    try {
      server.close(1011, "session error")
    } catch {
      void 0
    }
  })

  return new Response(null, { status: 101, webSocket: client })
}

async function runSession(ws: WebSocket, claims: VncTokenClaims, env: Env): Promise<void> {
  const incoming: Uint8Array[] = []
  let resolveNext: ((value: Uint8Array) => void) | null = null
  let sessionClosed = false

  const onMessage = (event: MessageEvent) => {
    if (typeof event.data === "string") {
      return
    }
    const bytes = new Uint8Array(event.data as ArrayBuffer)
    if (resolveNext) {
      const resolver = resolveNext
      resolveNext = null
      resolver(bytes)
    } else {
      incoming.push(bytes)
    }
  }

  const onClose = () => {
    sessionClosed = true
    if (resolveNext) {
      const resolver = resolveNext
      resolveNext = null
      resolver(new Uint8Array(0))
    }
  }

  ws.addEventListener("message", onMessage as EventListener)
  ws.addEventListener("close", onClose as EventListener)

  const nextMessage = (timeoutMs: number): Promise<Uint8Array> => {
    const queued = incoming.shift()
    if (queued) {
      return Promise.resolve(queued)
    }
    if (sessionClosed) {
      return Promise.resolve(new Uint8Array(0))
    }
    return new Promise<Uint8Array>((resolve, reject) => {
      const timer = setTimeout(() => {
        resolveNext = null
        reject(new Error("handshake timeout"))
      }, timeoutMs)
      resolveNext = (value) => {
        clearTimeout(timer)
        resolve(value)
      }
    })
  }

  const handshakeKeys = await generateHandshakeKeys()
  ws.send(buildHandshakeFrame(FrameType.ServerHello, ITE_PROTOCOL_VERSION, handshakeKeys.publicKeyRaw))

  const clientHelloBytes = await nextMessage(10_000)
  const clientHello = parseHandshakeFrame(clientHelloBytes)
  if (!clientHello || clientHello.type !== FrameType.ClientHello || clientHello.version !== ITE_PROTOCOL_VERSION) {
    ws.removeEventListener("message", onMessage as EventListener)
    ws.removeEventListener("close", onClose as EventListener)
    ws.close(1002, "bad handshake")
    return
  }

  const peerKey = await importPeerPublicKey(clientHello.publicKey)
  const ite = await deriveIteSession(handshakeKeys.privateKey, peerKey)

  ws.send(buildHandshakeFrame(FrameType.Ready, ITE_PROTOCOL_VERSION, new Uint8Array(0)))

  ws.removeEventListener("message", onMessage as EventListener)
  ws.removeEventListener("close", onClose as EventListener)

  let remote: RemoteConnection
  try {
    remote = await openRemote(claims, env)
  } catch {
    await sendControl(ws, ite, ControlOp.Disconnect, "Unable to reach the VNC server")
    ws.close(1011, "remote unreachable")
    return
  }

  const pendingFrames = incoming.slice()
  await bridgeEncrypted(ws, ite, remote, claims, pendingFrames)
}

async function sendControl(ws: WebSocket, ite: IteSession, op: number, reason?: string): Promise<void> {
  try {
    const frame = encodeApplicationFrame(FrameType.Control, encodeControl({ op, reason }))
    const encrypted = await encryptFrame(ite, frame)
    ws.send(encrypted)
  } catch {
    void 0
  }
}

async function bridgeEncrypted(
  ws: WebSocket,
  ite: IteSession,
  remote: RemoteConnection,
  claims: VncTokenClaims,
  pendingFrames: Uint8Array[],
): Promise<void> {
  const writer = remote.writable.getWriter()
  const reader = remote.readable.getReader()

  let closed = false
  let idleTimer: ReturnType<typeof setTimeout> | null = null
  let hardTimer: ReturnType<typeof setTimeout> | null = null
  const startedAt = Date.now()

  const clearTimers = () => {
    if (idleTimer) {
      clearTimeout(idleTimer)
      idleTimer = null
    }
    if (hardTimer) {
      clearTimeout(hardTimer)
      hardTimer = null
    }
  }

  const shutdown = async (op: number | null, reason: string, wsCode: number) => {
    if (closed) {
      return
    }
    closed = true
    clearTimers()
    if (op !== null) {
      await sendControl(ws, ite, op, reason)
    }
    try {
      await reader.cancel()
    } catch {
      void 0
    }
    try {
      await writer.close()
    } catch {
      void 0
    }
    remote.close()
    try {
      ws.close(wsCode, reason)
    } catch {
      void 0
    }
  }

  const armIdle = () => {
    if (idleTimer) {
      clearTimeout(idleTimer)
    }
    idleTimer = setTimeout(() => {
      void shutdown(ControlOp.IdleTimeout, "Disconnected after 3 minutes of inactivity", 1000)
    }, claims.idleCapMs)
  }

  if (claims.hardCapMs > 0) {
    const deadline = startedAt + claims.hardCapMs
    const scheduleHard = () => {
      const remaining = deadline - Date.now()
      if (remaining <= 0) {
        void shutdown(ControlOp.HardTimeout, "Private session reached its 10 minute limit", 1000)
        return
      }
      hardTimer = setTimeout(scheduleHard, Math.min(remaining, 30_000))
    }
    scheduleHard()
  }

  armIdle()

  const handleClientFrame = async (encrypted: Uint8Array) => {
    let plaintext: Uint8Array
    try {
      plaintext = await decryptFrame(ite, encrypted)
    } catch {
      await shutdown(ControlOp.Disconnect, "Decryption failed", 1002)
      return
    }

    armIdle()

    const { kind, payload } = decodeApplicationFrame(plaintext)
    if (kind === FrameType.Control) {
      return
    }
    if (kind !== FrameType.Data) {
      return
    }

    try {
      await writer.write(payload)
    } catch {
      await shutdown(ControlOp.Disconnect, "Write to VNC server failed", 1011)
    }
  }

  ws.addEventListener("message", (event) => {
    if (closed || typeof event.data === "string") {
      return
    }
    const data = new Uint8Array(event.data as ArrayBuffer)
    if (data.byteLength > MAX_FRAME_BYTES) {
      void shutdown(ControlOp.Disconnect, "Frame too large", 1009)
      return
    }
    void handleClientFrame(data)
  })

  ws.addEventListener("close", () => {
    void shutdown(null, "client closed", 1000)
  })

  ws.addEventListener("error", () => {
    void shutdown(null, "socket error", 1011)
  })

  for (const frame of pendingFrames) {
    if (closed) {
      break
    }
    await handleClientFrame(frame)
  }

  remote.closed
    .then(() => shutdown(ControlOp.Disconnect, "The VNC server closed the connection", 1000))
    .catch(() => shutdown(ControlOp.Disconnect, "The connection was lost", 1011))

  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) {
        break
      }
      if (closed) {
        break
      }
      if (value && value.byteLength > 0) {
        armIdle()
        const frame = encodeApplicationFrame(FrameType.Data, value)
        const encrypted = await encryptFrame(ite, frame)
        ws.send(encrypted)
      }
    }
    await shutdown(ControlOp.Disconnect, "The VNC server closed the connection", 1000)
  } catch {
    await shutdown(ControlOp.Disconnect, "The connection was lost", 1011)
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const url = new URL(request.url)

      if (request.method === "GET" && url.pathname === "/connect") {
        return await handleConnect(request, env)
      }

      if (request.method === "GET" && url.pathname === "/health") {
        return new Response("ok", { status: 200, headers: { "content-type": "text/plain" } })
      }

      return badRequest("Not found", 404)
    } catch {
      return new Response("Service unavailable", {
        status: 500,
        headers: { "content-type": "text/plain" },
      })
    }
  },
}
