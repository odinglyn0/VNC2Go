import type { NextConfig } from "next"

const proxyUrl = process.env.NEXT_PUBLIC_VNC_PROXY_URL ?? ""

const HCAPTCHA_ORIGINS = "https://hcaptcha.com https://*.hcaptcha.com"

function proxyConnectSrc(): string {
  if (!proxyUrl) {
    return "wss: ws:"
  }
  try {
    const url = new URL(proxyUrl)
    const wsOrigin = `${url.protocol}//${url.host}`
    const httpProtocol = url.protocol === "wss:" ? "https:" : "http:"
    const httpOrigin = `${httpProtocol}//${url.host}`
    return `${wsOrigin} ${httpOrigin}`
  } catch {
    return "wss: ws:"
  }
}

const isDev = process.env.NODE_ENV !== "production"

const scriptSrc = isDev
  ? `script-src 'self' 'unsafe-inline' 'unsafe-eval' ${HCAPTCHA_ORIGINS}`
  : `script-src 'self' 'unsafe-inline' ${HCAPTCHA_ORIGINS}`

const contentSecurityPolicy = [
  "default-src 'self'",
  scriptSrc,
  `style-src 'self' 'unsafe-inline' ${HCAPTCHA_ORIGINS}`,
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  `connect-src 'self' ${proxyConnectSrc()} ${HCAPTCHA_ORIGINS}`,
  `frame-src ${HCAPTCHA_ORIGINS}`,
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
]
  .join("; ")
  .trim()

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: contentSecurityPolicy },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
          {
            key: "Permissions-Policy",
            value: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
          },
          {
            key: "Strict-Transport-Security",
            value: "max-age=63072000; includeSubDomains; preload",
          },
          { key: "X-DNS-Prefetch-Control", value: "off" },
        ],
      },
    ]
  },
}

export default nextConfig
