export type ConnectionPhase =
  | "idle"
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
  target: ResolvedTarget
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

export async function resolveVncAddress(address: string, signal?: AbortSignal): Promise<ResolveResponse> {
  const response = await fetch("/api/resolve", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ address }),
    signal,
  })

  const data = (await response.json()) as ResolveResponse | ResolveError

  if (!response.ok) {
    const message = "error" in data ? data.error : "Unable to resolve the VNC address"
    throw new Error(message)
  }

  return data as ResolveResponse
}
