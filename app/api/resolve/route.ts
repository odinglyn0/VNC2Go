import { NextResponse } from "next/server"

import { formatTarget, isPrivateOrReservedTarget, parseVncAddress } from "@/lib/vnc"
import { signVncToken } from "@/lib/token"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

const TOKEN_TTL_MS = 60_000

interface ResolveRequestBody {
  address?: unknown
}

function getProxyBase(): string {
  const configured = process.env.NEXT_PUBLIC_VNC_PROXY_URL
  if (!configured) {
    throw new Error("VNC proxy endpoint is not configured")
  }
  return configured.replace(/\/+$/, "")
}

function allowPrivateTargets(): boolean {
  return process.env.VNC_ALLOW_PRIVATE_TARGETS === "true"
}

export async function POST(request: Request): Promise<Response> {
  let body: ResolveRequestBody
  try {
    body = (await request.json()) as ResolveRequestBody
  } catch {
    return NextResponse.json({ error: "Request body must be valid JSON" }, { status: 400 })
  }

  if (typeof body.address !== "string") {
    return NextResponse.json({ error: "An address string is required" }, { status: 400 })
  }

  if (body.address.length > 512) {
    return NextResponse.json({ error: "Address is too long" }, { status: 400 })
  }

  const parsed = parseVncAddress(body.address)
  if (!parsed.ok) {
    return NextResponse.json({ error: parsed.error }, { status: 400 })
  }

  if (isPrivateOrReservedTarget(parsed.target) && !allowPrivateTargets()) {
    return NextResponse.json(
      { error: "Private, loopback, and link-local addresses are blocked for security" },
      { status: 403 },
    )
  }

  const secret = process.env.VNC_PROXY_SECRET
  if (!secret) {
    return NextResponse.json({ error: "Server is missing its signing secret" }, { status: 500 })
  }

  let proxyBase: string
  try {
    proxyBase = getProxyBase()
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Proxy is not configured" },
      { status: 500 },
    )
  }

  const token = await signVncToken(
    { host: parsed.target.host, port: parsed.target.port, exp: Date.now() + TOKEN_TTL_MS },
    secret,
  )

  const proxyUrl = `${proxyBase}/connect?token=${encodeURIComponent(token)}`

  return NextResponse.json(
    {
      proxyUrl,
      target: {
        host: parsed.target.host,
        port: parsed.target.port,
        display: formatTarget(parsed.target),
        type: parsed.target.hostType,
      },
      expiresInMs: TOKEN_TTL_MS,
    },
    { headers: { "cache-control": "no-store" } },
  )
}

export function GET(): Response {
  return NextResponse.json({ error: "Method not allowed" }, { status: 405 })
}
