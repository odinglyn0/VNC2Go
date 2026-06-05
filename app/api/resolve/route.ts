import { NextResponse } from "next/server"

import { PRIVATE_MODE_COUNTRIES, RATE_LIMITS, SESSION_LIMITS, pickRandomCountry } from "@/lib/config"
import { checkRateLimit, clientFingerprint } from "@/lib/rate-limit"
import {
  CSRF_COOKIE,
  CSRF_HEADER,
  HUMAN_COOKIE,
  constantTimeEqual,
  parseCookies,
  randomId,
  verifyHumanPass,
  withSafeErrors,
} from "@/lib/security"
import { signVncToken } from "@/lib/token"
import { formatTarget, isPrivateOrReservedTarget, parseVncAddress } from "@/lib/vnc"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

interface ResolveRequestBody {
  address?: unknown
  privateMode?: unknown
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

export function POST(request: Request): Promise<Response> {
  return withSafeErrors(() => handleResolve(request))
}

async function handleResolve(request: Request): Promise<Response> {
  const fingerprint = await clientFingerprint(request)
  const limit = checkRateLimit(`resolve:${fingerprint}`, RATE_LIMITS.resolve.limit, RATE_LIMITS.resolve.windowMs)
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "Too many connection attempts. Please slow down." },
      { status: 429, headers: { "retry-after": String(limit.retryAfterSeconds), "cache-control": "no-store" } },
    )
  }

  const cookies = parseCookies(request.headers.get("cookie"))
  const cookieCsrf = cookies.get(CSRF_COOKIE)
  const headerCsrf = request.headers.get(CSRF_HEADER)
  if (!cookieCsrf || !headerCsrf || !constantTimeEqual(cookieCsrf, headerCsrf)) {
    return NextResponse.json({ error: "Invalid or missing CSRF token" }, { status: 403, headers: { "cache-control": "no-store" } })
  }

  const humanSecret = process.env.HUMAN_PASS_SECRET
  if (!humanSecret) {
    return NextResponse.json({ error: "Server is missing its verification secret" }, { status: 500 })
  }

  const humanCookie = cookies.get(HUMAN_COOKIE)
  if (!humanCookie || !(await verifyHumanPass(humanCookie, humanSecret))) {
    return NextResponse.json(
      { error: "Please complete human verification before connecting." },
      { status: 401, headers: { "cache-control": "no-store" } },
    )
  }

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

  const privateMode = body.privateMode === true

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

  if (privateMode && !process.env.WEBSHARE_PROXY_USERNAME) {
    return NextResponse.json(
      { error: "Private mode is not configured on this deployment" },
      { status: 503, headers: { "cache-control": "no-store" } },
    )
  }

  let proxyBase: string
  try {
    proxyBase = getProxyBase()
  } catch {
    return NextResponse.json(
      { error: "The proxy is not configured" },
      { status: 500, headers: { "cache-control": "no-store" } },
    )
  }

  const proxyCountry = privateMode ? pickRandomCountry() : undefined
  const hardCapMs = privateMode ? SESSION_LIMITS.privateHardCapMs : SESSION_LIMITS.standardHardCapMs
  const sid = randomId(16)
  const nonce = randomId(16)

  const token = await signVncToken(
    {
      host: parsed.target.host,
      port: parsed.target.port,
      sid,
      nonce,
      privateMode,
      proxyCountry,
      hardCapMs,
      idleCapMs: SESSION_LIMITS.idleTimeoutMs,
    },
    secret,
    SESSION_LIMITS.tokenTtlSeconds,
  )

  const proxyUrl = `${proxyBase}/connect?token=${encodeURIComponent(token)}`

  return NextResponse.json(
    {
      proxyUrl,
      sessionId: sid,
      target: {
        host: parsed.target.host,
        port: parsed.target.port,
        display: formatTarget(parsed.target),
        type: parsed.target.hostType,
      },
      privateMode,
      proxyCountry: proxyCountry ?? null,
      hardCapMs,
      idleCapMs: SESSION_LIMITS.idleTimeoutMs,
      expiresInMs: SESSION_LIMITS.tokenTtlSeconds * 1000,
    },
    { headers: { "cache-control": "no-store" } },
  )
}

export function GET(): Response {
  return NextResponse.json(
    { error: "Method not allowed", supportedCountries: PRIVATE_MODE_COUNTRIES },
    { status: 405 },
  )
}
