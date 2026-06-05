import { connect } from "cloudflare:sockets"

import { verifyVncToken } from "./token"

export interface Env {
  VNC_PROXY_SECRET: string
  ALLOWED_ORIGINS: string
}

const MAX_PORT = 65535

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

async function handleConnect(request: Request, env: Env): Promise<Response> {
  if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
    return badRequest("Expected a WebSocket upgrade", 426)
  }

  const origin = request.headers.get("Origin")
  if (!isOriginAllowed(origin, env)) {
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

  const payload = await verifyVncToken(token, env.VNC_PROXY_SECRET)
  if (!payload) {
    return badRequest("The connection token is invalid or expired", 401)
  }

  if (typeof payload.port !== "number" || payload.port < 1 || payload.port > MAX_PORT) {
    return badRequest("The token contains an invalid port", 400)
  }

  let socket: ReturnType<typeof connect>
  try {
    socket = connect(
      { hostname: payload.host, port: payload.port },
      { allowHalfOpen: false, secureTransport: "off" },
    )
  } catch {
    return badRequest("Unable to open a connection to the VNC server", 502)
  }

  const pair = new WebSocketPair()
  const client = pair[0]
  const server = pair[1]

  server.accept()

  bridge(server, socket)

  return new Response(null, { status: 101, webSocket: client })
}

function bridge(ws: WebSocket, socket: ReturnType<typeof connect>): void {
  const writer = socket.writable.getWriter()
  const reader = socket.readable.getReader()

  let closed = false

  const closeAll = (code?: number, reason?: string) => {
    if (closed) {
      return
    }
    closed = true
    try {
      reader.cancel().catch(() => undefined)
    } catch {
      void 0
    }
    try {
      writer.close().catch(() => undefined)
    } catch {
      void 0
    }
    try {
      socket.close().catch(() => undefined)
    } catch {
      void 0
    }
    try {
      if (code === undefined) {
        ws.close()
      } else {
        ws.close(code, reason)
      }
    } catch {
      void 0
    }
  }

  ws.addEventListener("message", (event) => {
    if (closed) {
      return
    }
    const data = event.data
    if (typeof data === "string") {
      writer.write(new TextEncoder().encode(data)).catch(() => closeAll(1011, "write failed"))
      return
    }
    writer.write(new Uint8Array(data as ArrayBuffer)).catch(() => closeAll(1011, "write failed"))
  })

  ws.addEventListener("close", () => closeAll())
  ws.addEventListener("error", () => closeAll(1011, "socket error"))

  const pump = async () => {
    try {
      for (;;) {
        const { value, done } = await reader.read()
        if (done) {
          break
        }
        if (value && value.byteLength > 0) {
          ws.send(value)
        }
      }
      closeAll(1000, "remote closed")
    } catch {
      closeAll(1011, "read failed")
    }
  }

  socket.closed.then(() => closeAll(1000, "remote closed")).catch(() => closeAll(1011, "remote error"))

  pump()
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url)

    if (request.method === "GET" && url.pathname === "/connect") {
      return handleConnect(request, env)
    }

    if (request.method === "GET" && url.pathname === "/health") {
      return new Response("ok", { status: 200, headers: { "content-type": "text/plain" } })
    }

    return badRequest("Not found", 404)
  },
}
