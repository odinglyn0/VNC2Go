var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/index.ts
import { connect } from "cloudflare:sockets";

// src/token.ts
function base64UrlDecode(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
__name(base64UrlDecode, "base64UrlDecode");
async function importKey(secret) {
  const encoder = new TextEncoder();
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}
__name(importKey, "importKey");
function timingSafeEqual(a, b) {
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i += 1) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}
__name(timingSafeEqual, "timingSafeEqual");
async function verifyVncToken(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 2) {
    return null;
  }
  const [body, providedSig] = parts;
  const encoder = new TextEncoder();
  const key = await importKey(secret);
  const expectedSignature = await crypto.subtle.sign("HMAC", key, encoder.encode(body));
  const expected = new Uint8Array(expectedSignature);
  const provided = base64UrlDecode(providedSig);
  if (!timingSafeEqual(expected, provided)) {
    return null;
  }
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(body)));
    if (typeof payload.host !== "string" || typeof payload.port !== "number" || typeof payload.exp !== "number") {
      return null;
    }
    if (Date.now() > payload.exp) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}
__name(verifyVncToken, "verifyVncToken");

// src/index.ts
var MAX_PORT = 65535;
function parseAllowedOrigins(raw) {
  return raw.split(",").map((value) => value.trim().replace(/\/+$/, "").toLowerCase()).filter((value) => value.length > 0);
}
__name(parseAllowedOrigins, "parseAllowedOrigins");
function isOriginAllowed(origin, env) {
  const allowed = parseAllowedOrigins(env.ALLOWED_ORIGINS);
  if (allowed.length === 0) {
    return false;
  }
  if (allowed.includes("*")) {
    return true;
  }
  if (!origin) {
    return false;
  }
  return allowed.includes(origin.replace(/\/+$/, "").toLowerCase());
}
__name(isOriginAllowed, "isOriginAllowed");
function badRequest(message, status = 400) {
  return new Response(message, { status, headers: { "content-type": "text/plain" } });
}
__name(badRequest, "badRequest");
async function handleConnect(request, env) {
  if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
    return badRequest("Expected a WebSocket upgrade", 426);
  }
  const origin = request.headers.get("Origin");
  if (!isOriginAllowed(origin, env)) {
    return badRequest("Origin is not allowed", 403);
  }
  if (!env.VNC_PROXY_SECRET) {
    return badRequest("Proxy is missing its signing secret", 500);
  }
  const url = new URL(request.url);
  const token = url.searchParams.get("token");
  if (!token) {
    return badRequest("A connection token is required", 401);
  }
  const payload = await verifyVncToken(token, env.VNC_PROXY_SECRET);
  if (!payload) {
    return badRequest("The connection token is invalid or expired", 401);
  }
  if (typeof payload.port !== "number" || payload.port < 1 || payload.port > MAX_PORT) {
    return badRequest("The token contains an invalid port", 400);
  }
  let socket;
  try {
    socket = connect(
      { hostname: payload.host, port: payload.port },
      { allowHalfOpen: false, secureTransport: "off" }
    );
  } catch {
    return badRequest("Unable to open a connection to the VNC server", 502);
  }
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.accept();
  bridge(server, socket);
  return new Response(null, { status: 101, webSocket: client });
}
__name(handleConnect, "handleConnect");
function bridge(ws, socket) {
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  let closed = false;
  const closeAll = /* @__PURE__ */ __name((code, reason) => {
    if (closed) {
      return;
    }
    closed = true;
    try {
      reader.cancel().catch(() => void 0);
    } catch {
    }
    try {
      writer.close().catch(() => void 0);
    } catch {
    }
    try {
      socket.close().catch(() => void 0);
    } catch {
    }
    try {
      if (code === void 0) {
        ws.close();
      } else {
        ws.close(code, reason);
      }
    } catch {
    }
  }, "closeAll");
  ws.addEventListener("message", (event) => {
    if (closed) {
      return;
    }
    const data = event.data;
    if (typeof data === "string") {
      writer.write(new TextEncoder().encode(data)).catch(() => closeAll(1011, "write failed"));
      return;
    }
    writer.write(new Uint8Array(data)).catch(() => closeAll(1011, "write failed"));
  });
  ws.addEventListener("close", () => closeAll());
  ws.addEventListener("error", () => closeAll(1011, "socket error"));
  const pump = /* @__PURE__ */ __name(async () => {
    try {
      for (; ; ) {
        const { value, done } = await reader.read();
        if (done) {
          break;
        }
        if (value && value.byteLength > 0) {
          ws.send(value);
        }
      }
      closeAll(1e3, "remote closed");
    } catch {
      closeAll(1011, "read failed");
    }
  }, "pump");
  socket.closed.then(() => closeAll(1e3, "remote closed")).catch(() => closeAll(1011, "remote error"));
  pump();
}
__name(bridge, "bridge");
var index_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/connect") {
      return handleConnect(request, env);
    }
    if (request.method === "GET" && url.pathname === "/health") {
      return new Response("ok", { status: 200, headers: { "content-type": "text/plain" } });
    }
    return badRequest("Not found", 404);
  }
};
export {
  index_default as default
};
//# sourceMappingURL=index.js.map
