import { NextResponse } from "next/server"

import { RATE_LIMITS, SESSION_LIMITS } from "@/lib/config"
import { verifyHcaptchaToken } from "@/lib/hcaptcha"
import { checkRateLimit, clientFingerprint } from "@/lib/rate-limit"
import {
  CSRF_COOKIE,
  CSRF_HEADER,
  HUMAN_COOKIE,
  buildCookie,
  constantTimeEqual,
  issueHumanPass,
  parseCookies,
} from "@/lib/security"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

interface VerifyBody {
  captchaToken?: unknown
}

function isProduction(): boolean {
  return process.env.NODE_ENV === "production"
}

function clientIp(request: Request): string | undefined {
  const forwarded = request.headers.get("x-forwarded-for")
  if (forwarded) {
    return forwarded.split(",")[0].trim()
  }
  return request.headers.get("x-real-ip") ?? undefined
}

export async function POST(request: Request): Promise<Response> {
  const fingerprint = await clientFingerprint(request)
  const limit = checkRateLimit(`verify:${fingerprint}`, RATE_LIMITS.verify.limit, RATE_LIMITS.verify.windowMs)
  if (!limit.allowed) {
    return NextResponse.json(
      { error: "Too many verification attempts. Please wait a moment." },
      { status: 429, headers: { "retry-after": String(limit.retryAfterSeconds), "cache-control": "no-store" } },
    )
  }

  const cookies = parseCookies(request.headers.get("cookie"))
  const cookieCsrf = cookies.get(CSRF_COOKIE)
  const headerCsrf = request.headers.get(CSRF_HEADER)
  if (!cookieCsrf || !headerCsrf || !constantTimeEqual(cookieCsrf, headerCsrf)) {
    return NextResponse.json({ error: "Invalid or missing CSRF token" }, { status: 403, headers: { "cache-control": "no-store" } })
  }

  let body: VerifyBody
  try {
    body = (await request.json()) as VerifyBody
  } catch {
    return NextResponse.json({ error: "Request body must be valid JSON" }, { status: 400 })
  }

  if (typeof body.captchaToken !== "string" || body.captchaToken.length === 0) {
    return NextResponse.json({ error: "A captcha token is required" }, { status: 400 })
  }

  const hcaptchaSecret = process.env.HCAPTCHA_SECRET
  if (!hcaptchaSecret) {
    return NextResponse.json({ error: "Human verification is not configured" }, { status: 500 })
  }

  const humanSecret = process.env.HUMAN_PASS_SECRET
  if (!humanSecret) {
    return NextResponse.json({ error: "Server is missing its verification secret" }, { status: 500 })
  }

  const verified = await verifyHcaptchaToken(body.captchaToken, hcaptchaSecret, clientIp(request))
  if (!verified) {
    return NextResponse.json({ error: "Human verification failed. Please try again." }, { status: 403, headers: { "cache-control": "no-store" } })
  }

  const { token } = await issueHumanPass(humanSecret, SESSION_LIMITS.humanPassTtlSeconds)

  const response = NextResponse.json(
    { verified: true, expiresInSeconds: SESSION_LIMITS.humanPassTtlSeconds },
    { headers: { "cache-control": "no-store" } },
  )

  response.headers.append(
    "set-cookie",
    buildCookie(HUMAN_COOKIE, token, {
      maxAge: SESSION_LIMITS.humanPassTtlSeconds,
      httpOnly: true,
      sameSite: "Strict",
      secure: isProduction(),
      path: "/",
    }),
  )

  return response
}
