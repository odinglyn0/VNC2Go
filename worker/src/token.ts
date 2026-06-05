import { jwtVerify } from "jose"

export interface VncTokenClaims {
  host: string
  port: number
  sid: string
  nonce: string
  privateMode: boolean
  proxyCountry?: string
  hardCapMs: number
  idleCapMs: number
}

const ISSUER = "vnc2go.odinglynn.com"
const AUDIENCE = "vnc2go-proxy"
const ALG = "HS256"

export async function verifyVncToken(token: string, secret: string): Promise<VncTokenClaims | null> {
  try {
    const key = new TextEncoder().encode(secret)
    const { payload } = await jwtVerify(token, key, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: [ALG],
    })

    if (
      typeof payload.host !== "string" ||
      typeof payload.port !== "number" ||
      typeof payload.sub !== "string" ||
      typeof payload.nonce !== "string" ||
      typeof payload.privateMode !== "boolean" ||
      typeof payload.hardCapMs !== "number" ||
      typeof payload.idleCapMs !== "number"
    ) {
      return null
    }

    return {
      host: payload.host,
      port: payload.port,
      sid: payload.sub,
      nonce: payload.nonce,
      privateMode: payload.privateMode,
      proxyCountry: typeof payload.proxyCountry === "string" ? payload.proxyCountry : undefined,
      hardCapMs: payload.hardCapMs,
      idleCapMs: payload.idleCapMs,
    }
  } catch {
    return null
  }
}
