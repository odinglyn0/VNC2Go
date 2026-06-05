interface Bucket {
  count: number
  resetAt: number
}

const buckets = new Map<string, Bucket>()

export interface RateLimitResult {
  allowed: boolean
  remaining: number
  resetAt: number
  retryAfterSeconds: number
}

function sweep(now: number): void {
  if (buckets.size < 4096) {
    return
  }
  for (const [key, bucket] of buckets) {
    if (bucket.resetAt <= now) {
      buckets.delete(key)
    }
  }
}

export function checkRateLimit(key: string, limit: number, windowMs: number): RateLimitResult {
  const now = Date.now()
  sweep(now)

  const existing = buckets.get(key)
  if (!existing || existing.resetAt <= now) {
    const resetAt = now + windowMs
    buckets.set(key, { count: 1, resetAt })
    return { allowed: true, remaining: limit - 1, resetAt, retryAfterSeconds: 0 }
  }

  if (existing.count >= limit) {
    return {
      allowed: false,
      remaining: 0,
      resetAt: existing.resetAt,
      retryAfterSeconds: Math.max(1, Math.ceil((existing.resetAt - now) / 1000)),
    }
  }

  existing.count += 1
  return {
    allowed: true,
    remaining: limit - existing.count,
    resetAt: existing.resetAt,
    retryAfterSeconds: 0,
  }
}

export async function clientFingerprint(request: Request): Promise<string> {
  const forwarded = request.headers.get("x-forwarded-for")
  const realIp = request.headers.get("x-real-ip")
  const ip = (forwarded?.split(",")[0] ?? realIp ?? "unknown").trim()
  const ua = request.headers.get("user-agent") ?? "unknown"
  const material = new TextEncoder().encode(`${ip}|${ua}`)
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", material))
  let hash = ""
  for (let i = 0; i < 16; i += 1) {
    hash += digest[i].toString(16).padStart(2, "0")
  }
  return hash
}
