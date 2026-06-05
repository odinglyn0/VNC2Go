import { NextResponse } from "next/server"

import { CSRF_COOKIE, buildCookie, parseCookies, randomId } from "@/lib/security"

export const runtime = "nodejs"
export const dynamic = "force-dynamic"

function isProduction(): boolean {
  return process.env.NODE_ENV === "production"
}

export async function GET(request: Request): Promise<Response> {
  const existing = parseCookies(request.headers.get("cookie")).get(CSRF_COOKIE)
  const token = existing && existing.length === 64 ? existing : randomId(32)

  const response = NextResponse.json(
    { csrfToken: token },
    { headers: { "cache-control": "no-store" } },
  )

  response.headers.append(
    "set-cookie",
    buildCookie(CSRF_COOKIE, token, {
      maxAge: 60 * 60,
      httpOnly: false,
      sameSite: "Strict",
      secure: isProduction(),
      path: "/",
    }),
  )

  return response
}
