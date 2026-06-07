import { connect } from "cloudflare:sockets"

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

const CLOSE_NORMAL = 1000
const CLOSE_REMOTE_UNREACHABLE = 4502
const CLOSE_IDLE_TIMEOUT = 4000
const CLOSE_HARD_CAP = 4001
const CLOSE_FRAME_TOO_LARGE = 4009
const CLOSE_WRITE_FAILED = 4503
const CLOSE_CONNECTION_LOST = 4504
const CLOSE_SERVER_CLOSED = 4505

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
  await socket.opened
  return {
    readable: socket.readable,
    writable: socket.writable,
    closed: socket.closed,
    close: () => {
      socket.close().catch(() => undefined)
    },
  }
}

async function runSession(ws: WebSocket, claims: VncTokenClaims, env: Env): Promise<void> {
  let remote: RemoteConnection
  try {
    remote = await openRemote(claims, env)
  } catch (error) {
    try {
      ws.close(CLOSE_REMOTE_UNREACHABLE, describeRemoteFailure(error, claims))
    } catch {
      void 0
    }
    return
  }

  const writer = remote.writable.getWriter()
  const reader = remote.readable.getReader()
  let closed = false
  let idleTimer: ReturnType<typeof setTimeout> | null = null
  let hardTimer: ReturnType<typeof setTimeout> | null = null

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

  const shutdown = (reason: string, wsCode: number) => {
    if (closed) {
      return
    }
    closed = true
    clearTimers()
    reader.cancel().catch(() => undefined)
    writer.close().catch(() => undefined)
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
      shutdown("Disconnected after 3 minutes of inactivity.", CLOSE_IDLE_TIMEOUT)
    }, claims.idleCapMs)
  }

  const scheduleHardCap = () => {
    if (claims.hardCapMs <= 0) {
      return
    }
    const deadline = Date.now() + claims.hardCapMs
    const tick = () => {
      const remaining = deadline - Date.now()
      if (remaining <= 0) {
        shutdown("Private session reached its 10 minute limit.", CLOSE_HARD_CAP)
        return
      }
      hardTimer = setTimeout(tick, Math.min(remaining, 30_000))
    }
    tick()
  }

  ws.addEventListener("message", (event) => {
    if (closed || typeof event.data === "string") {
      return
    }
    const data = new Uint8Array(event.data as ArrayBuffer)
    if (data.byteLength === 0) {
      return
    }
    if (data.byteLength > MAX_FRAME_BYTES) {
      shutdown("The VNC server sent too much data at once.", CLOSE_FRAME_TOO_LARGE)
      return
    }
    armIdle()
    const copy = new Uint8Array(data.byteLength)
    copy.set(data)
    writer.write(copy).catch(() => shutdown("Lost the link to the VNC server.", CLOSE_WRITE_FAILED))
  })

  ws.addEventListener("close", () => {
    shutdown("client closed", CLOSE_NORMAL)
  })

  ws.addEventListener("error", () => {
    shutdown("The connection was lost unexpectedly.", CLOSE_CONNECTION_LOST)
  })

  remote.closed
    .then(() => shutdown("The VNC server closed the connection.", CLOSE_SERVER_CLOSED))
    .catch(() => shutdown("The connection to the VNC server was lost.", CLOSE_CONNECTION_LOST))

  armIdle()
  scheduleHardCap()

  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done || closed) {
        break
      }
      if (value && value.byteLength > 0) {
        armIdle()
        const copy = new Uint8Array(value.byteLength)
        copy.set(value)
        ws.send(copy)
      }
    }
    shutdown("The VNC server closed the connection.", CLOSE_SERVER_CLOSED)
  } catch {
    shutdown("The connection to the VNC server was lost.", CLOSE_CONNECTION_LOST)
  }
}

async function handleConnect(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
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
  server.binaryType = "arraybuffer"
  server.accept()

  ctx.waitUntil(
    runSession(server, claims, env).catch(() => {
      try {
        server.close(CLOSE_CONNECTION_LOST, "The session ended unexpectedly.")
      } catch {
        void 0
      }
    }),
  )

  return new Response(null, { status: 101, webSocket: client })
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      const url = new URL(request.url)

      if (request.method === "GET" && url.pathname === "/connect") {
        return await handleConnect(request, env, ctx)
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
