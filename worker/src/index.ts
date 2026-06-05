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

async function runSession(ws: WebSocket, claims: VncTokenClaims, env: Env): Promise<void> {
  let remote: RemoteConnection
  try {
    remote = await openRemote(claims, env)
  } catch {
    try {
      ws.close(1011, "remote unreachable")
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
      shutdown("Disconnected after 3 minutes of inactivity", 4000)
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
        shutdown("Private session reached its 10 minute limit", 4001)
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
      shutdown("Frame too large", 1009)
      return
    }
    armIdle()
    writer.write(data).catch(() => shutdown("Write to VNC server failed", 1011))
  })

  ws.addEventListener("close", () => {
    shutdown("client closed", 1000)
  })

  ws.addEventListener("error", () => {
    shutdown("socket error", 1011)
  })

  remote.closed
    .then(() => shutdown("The VNC server closed the connection", 1000))
    .catch(() => shutdown("The connection was lost", 1011))

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
        ws.send(value)
      }
    }
    shutdown("The VNC server closed the connection", 1000)
  } catch {
    shutdown("The connection was lost", 1011)
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
  server.accept()

  ctx.waitUntil(
    runSession(server, claims, env).catch(() => {
      try {
        server.close(1011, "session error")
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
