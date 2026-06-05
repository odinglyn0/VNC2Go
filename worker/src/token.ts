export interface VncTokenPayload {
  host: string
  port: number
  exp: number
}

function base64UrlDecode(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/")
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=")
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

async function importKey(secret: string): Promise<CryptoKey> {
  const encoder = new TextEncoder()
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  )
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false
  }
  let result = 0
  for (let i = 0; i < a.length; i += 1) {
    result |= a[i] ^ b[i]
  }
  return result === 0
}

export async function verifyVncToken(token: string, secret: string): Promise<VncTokenPayload | null> {
  const parts = token.split(".")
  if (parts.length !== 2) {
    return null
  }
  const [body, providedSig] = parts
  const encoder = new TextEncoder()
  const key = await importKey(secret)
  const expectedSignature = await crypto.subtle.sign("HMAC", key, encoder.encode(body))
  const expected = new Uint8Array(expectedSignature)
  const provided = base64UrlDecode(providedSig)
  if (!timingSafeEqual(expected, provided)) {
    return null
  }
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(body))) as VncTokenPayload
    if (typeof payload.host !== "string" || typeof payload.port !== "number" || typeof payload.exp !== "number") {
      return null
    }
    if (Date.now() > payload.exp) {
      return null
    }
    return payload
  } catch {
    return null
  }
}
