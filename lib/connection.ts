export type ConnectionPhase =
  | "idle"
  | "verifying"
  | "resolving"
  | "connecting"
  | "credentials"
  | "connected"
  | "error"

export interface ResolvedTarget {
  host: string
  port: number
  display: string
  type: "hostname" | "ipv4" | "ipv6"
}

export interface ResolveResponse {
  proxyUrl: string
  sessionId: string
  target: ResolvedTarget
  privateMode: boolean
  proxyCountry: string | null
  hardCapMs: number
  idleCapMs: number
  expiresInMs: number
}

export interface ResolveError {
  error: string
}

export type CredentialField = "username" | "password" | "target"

export interface VncCredentials {
  username?: string
  password?: string
  target?: string
}

let cachedCsrfToken: string | null = null

export async function getCsrfToken(forceRefresh = false): Promise<string> {
  if (cachedCsrfToken && !forceRefresh) {
    return cachedCsrfToken
  }
  const response = await fetch("/api/csrf", { method: "GET", credentials: "same-origin" })
  if (!response.ok) {
    throw new Error("Unable to establish a secure session")
  }
  const data = (await response.json()) as { csrfToken: string }
  cachedCsrfToken = data.csrfToken
  return data.csrfToken
}

export async function submitHumanVerification(captchaToken: string): Promise<void> {
  const csrf = await getCsrfToken()
  const response = await fetch("/api/verify", {
    method: "POST",
    headers: { "content-type": "application/json", "x-vnc2go-csrf": csrf },
    credentials: "same-origin",
    body: JSON.stringify({ captchaToken }),
  })

  const data = (await response.json()) as { verified?: boolean; error?: string }
  if (!response.ok || !data.verified) {
    throw new Error(data.error ?? "Human verification failed")
  }
}

export async function resolveVncAddress(
  address: string,
  privateMode: boolean,
  signal?: AbortSignal,
): Promise<ResolveResponse> {
  const csrf = await getCsrfToken()
  const response = await fetch("/api/resolve", {
    method: "POST",
    headers: { "content-type": "application/json", "x-vnc2go-csrf": csrf },
    credentials: "same-origin",
    body: JSON.stringify({ address, privateMode }),
    signal,
  })

  const data = (await response.json()) as ResolveResponse | ResolveError

  if (!response.ok) {
    const message = "error" in data ? data.error : "Unable to resolve the VNC address"
    throw new Error(message)
  }

  return data as ResolveResponse
}
