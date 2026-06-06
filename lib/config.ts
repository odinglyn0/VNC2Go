export const SESSION_LIMITS = {
  standardHardCapMs: 0,
  privateHardCapMs: 10 * 60 * 1000,
  idleTimeoutMs: 3 * 60 * 1000,
  tokenTtlSeconds: 240,
  humanPassTtlSeconds: 15 * 60,
} as const

export const RATE_LIMITS = {
  resolve: { limit: 12, windowMs: 60 * 1000 },
  verify: { limit: 8, windowMs: 60 * 1000 },
} as const

export const PRIVATE_MODE_COUNTRIES = [
  "NL",
  "DE",
  "SE",
  "CH",
  "FR",
  "FI",
  "NO",
  "IE",
  "IS",
  "LU",
] as const

export type PrivateModeCountry = (typeof PRIVATE_MODE_COUNTRIES)[number]

export function pickRandomCountry(): PrivateModeCountry {
  const index = Math.floor(Math.random() * PRIVATE_MODE_COUNTRIES.length)
  return PRIVATE_MODE_COUNTRIES[index]
}
