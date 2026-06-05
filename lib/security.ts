import { SignJWT, jwtVerify } from "jose"

export const CSRF_COOKIE = "vnc2go_csrf"
export const CSRF_HEADER = "x-vnc2go-csrf"
export const HUMAN_COOKIE = "vnc2go_human"

const HUMAN_ISSUER = "vnc2go.odinglynn.com"
const HUMAN_AUDIENCE = "vnc2go-human"
const ALG = "HS256"

export function randomId(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength)
  crypto.getRandomValues(bytes)
  let value = ""
  for (const byte of bytes) {
    value += byte.toString(16).padStart(2, "0")
  }
  return value
}

export function constantTimeEqual(a: string, b: string): boolean {
  const aBytes = new TextEncoder().encode(a)
  const bBytes = new TextEncoder().encode(b)
  if (aBytes.length !== bBytes.length) {
    return false
  }
  let result = 0
  for (let i = 0; i < aBytes.length; i += 1) {
    result |= aBytes[i] ^ bBytes[i]
  }
  return result === 0
}

export async function issueHumanPass(secret: string, ttlSeconds: number): Promise<{ token: string; jti: string }> {
  const key = new TextEncoder().encode(secret)
  const jti = randomId(16)
  const token = await new SignJWT({ verified: true })
    .setProtectedHeader({ alg: ALG, typ: "JWT" })
    .setIssuer(HUMAN_ISSUER)
    .setAudience(HUMAN_AUDIENCE)
    .setIssuedAt()
    .setJti(jti)
    .setExpirationTime(`${ttlSeconds}s`)
    .sign(key)
  return { token, jti }
}

export async function verifyHumanPass(token: string, secret: string): Promise<boolean> {
  try {
    const key = new TextEncoder().encode(secret)
    const { payload } = await jwtVerify(token, key, {
      issuer: HUMAN_ISSUER,
      audience: HUMAN_AUDIENCE,
      algorithms: [ALG],
    })
    return payload.verified === true
  } catch {
    return false
  }
}

export function parseCookies(header: string | null): Map<string, string> {
  const result = new Map<string, string>()
  if (!header) {
    return result
  }
  for (const part of header.split(";")) {
    const index = part.indexOf("=")
    if (index === -1) {
      continue
    }
    const name = part.slice(0, index).trim()
    const value = part.slice(index + 1).trim()
    if (name.length > 0) {
      result.set(name, decodeURIComponent(value))
    }
  }
  return result
}

export function buildCookie(
  name: string,
  value: string,
  options: { maxAge?: number; httpOnly?: boolean; sameSite?: "Strict" | "Lax" | "None"; secure?: boolean; path?: string },
): string {
  const segments = [`${name}=${encodeURIComponent(value)}`]
  segments.push(`Path=${options.path ?? "/"}`)
  segments.push(`SameSite=${options.sameSite ?? "Strict"}`)
  if (options.maxAge !== undefined) {
    segments.push(`Max-Age=${options.maxAge}`)
  }
  if (options.httpOnly) {
    segments.push("HttpOnly")
  }
  if (options.secure) {
    segments.push("Secure")
  }
  return segments.join("; ")
}

export async function withSafeErrors(handler: () => Promise<Response>): Promise<Response> {
  try {
    return await handler()
  } catch {
    return new Response(JSON.stringify({ error: "Something went wrong. Please try again." }), {
      status: 500,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    })
  }
}
