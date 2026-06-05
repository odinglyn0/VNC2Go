export const DEFAULT_VNC_PORT = 5900

export interface ParsedVncTarget {
  host: string
  port: number
  hostType: "hostname" | "ipv4" | "ipv6"
}

export interface VncParseSuccess {
  ok: true
  target: ParsedVncTarget
}

export interface VncParseFailure {
  ok: false
  error: string
}

export type VncParseResult = VncParseSuccess | VncParseFailure

const HOSTNAME_LABEL = /^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$/
const IPV4_OCTET = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/

function stripScheme(raw: string): string {
  const schemeMatch = raw.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//)
  if (!schemeMatch) {
    return raw
  }
  const scheme = schemeMatch[1].toLowerCase()
  const allowed = new Set(["vnc", "ws", "wss", "tcp", "rfb"])
  if (!allowed.has(scheme)) {
    throw new Error(`Unsupported scheme "${scheme}"`)
  }
  return raw.slice(schemeMatch[0].length)
}

function isValidIpv4(value: string): boolean {
  const parts = value.split(".")
  if (parts.length !== 4) {
    return false
  }
  return parts.every((octet) => IPV4_OCTET.test(octet))
}

function isValidIpv6(value: string): boolean {
  if (value.length === 0) {
    return false
  }
  if ((value.match(/::/g) ?? []).length > 1) {
    return false
  }
  const hasCompression = value.includes("::")
  const segments = value.split(":")
  const embeddedIpv4 = segments.length > 0 && segments[segments.length - 1].includes(".")

  let expectedGroups = 8
  let groups = segments
  if (embeddedIpv4) {
    const ipv4Part = segments[segments.length - 1]
    if (!isValidIpv4(ipv4Part)) {
      return false
    }
    groups = segments.slice(0, -1)
    expectedGroups = 6
  }

  const hextets = groups.filter((segment) => segment.length > 0)
  for (const hextet of hextets) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(hextet)) {
      return false
    }
  }

  if (hasCompression) {
    return hextets.length <= expectedGroups - 1
  }
  return hextets.length === expectedGroups
}

function isValidHostname(value: string): boolean {
  if (value.length === 0 || value.length > 253) {
    return false
  }
  const labels = value.replace(/\.$/, "").split(".")
  return labels.every((label) => HOSTNAME_LABEL.test(label))
}

function parsePort(value: string | undefined): number {
  if (value === undefined || value.length === 0) {
    return DEFAULT_VNC_PORT
  }
  if (!/^\d+$/.test(value)) {
    throw new Error(`Invalid port "${value}"`)
  }
  const port = Number.parseInt(value, 10)
  if (port < 1 || port > 65535) {
    throw new Error(`Port ${port} is out of range`)
  }
  return port
}

function splitHostPort(input: string): { host: string; port?: string; hostType: ParsedVncTarget["hostType"] } {
  if (input.startsWith("[")) {
    const closing = input.indexOf("]")
    if (closing === -1) {
      throw new Error("Malformed IPv6 address, missing closing bracket")
    }
    const host = input.slice(1, closing)
    const remainder = input.slice(closing + 1)
    if (!isValidIpv6(host)) {
      throw new Error("Invalid IPv6 address")
    }
    if (remainder.length === 0) {
      return { host, hostType: "ipv6" }
    }
    if (!remainder.startsWith(":")) {
      throw new Error("Unexpected characters after IPv6 address")
    }
    return { host, port: remainder.slice(1), hostType: "ipv6" }
  }

  if (isValidIpv6(input)) {
    return { host: input, hostType: "ipv6" }
  }

  const lastColon = input.lastIndexOf(":")
  if (lastColon === -1) {
    return { host: input, hostType: classifyHost(input) }
  }

  const host = input.slice(0, lastColon)
  const port = input.slice(lastColon + 1)
  return { host, port, hostType: classifyHost(host) }
}

function classifyHost(host: string): ParsedVncTarget["hostType"] {
  if (isValidIpv4(host)) {
    return "ipv4"
  }
  if (isValidHostname(host)) {
    return "hostname"
  }
  throw new Error("Invalid host")
}

export function parseVncAddress(raw: string): VncParseResult {
  try {
    const trimmed = raw.trim()
    if (trimmed.length === 0) {
      return { ok: false, error: "Enter a VNC address to connect" }
    }

    const withoutScheme = stripScheme(trimmed)
    if (withoutScheme.length === 0) {
      return { ok: false, error: "Address is missing a host" }
    }

    const pathIndex = withoutScheme.search(/[/?#]/)
    const authority = pathIndex === -1 ? withoutScheme : withoutScheme.slice(0, pathIndex)

    if (authority.includes("@")) {
      return { ok: false, error: "Credentials in the address are not supported, use the login prompt" }
    }

    const { host, port, hostType } = splitHostPort(authority)
    if (host.length === 0) {
      return { ok: false, error: "Address is missing a host" }
    }

    const resolvedPort = parsePort(port)
    const validatedType =
      hostType === "ipv6"
        ? (isValidIpv6(host) ? "ipv6" : (() => { throw new Error("Invalid IPv6 address") })())
        : classifyHost(host)

    return {
      ok: true,
      target: {
        host: validatedType === "ipv6" ? host.toLowerCase() : host.toLowerCase(),
        port: resolvedPort,
        hostType: validatedType,
      },
    }
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : "Invalid VNC address" }
  }
}

const PRIVATE_IPV4_RANGES: Array<[number, number]> = [
  [ipv4ToInt("10.0.0.0"), ipv4ToInt("10.255.255.255")],
  [ipv4ToInt("172.16.0.0"), ipv4ToInt("172.31.255.255")],
  [ipv4ToInt("192.168.0.0"), ipv4ToInt("192.168.255.255")],
  [ipv4ToInt("127.0.0.0"), ipv4ToInt("127.255.255.255")],
  [ipv4ToInt("169.254.0.0"), ipv4ToInt("169.254.255.255")],
  [ipv4ToInt("0.0.0.0"), ipv4ToInt("0.255.255.255")],
  [ipv4ToInt("100.64.0.0"), ipv4ToInt("100.127.255.255")],
  [ipv4ToInt("192.0.0.0"), ipv4ToInt("192.0.0.255")],
  [ipv4ToInt("198.18.0.0"), ipv4ToInt("198.19.255.255")],
]

function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, octet) => (acc << 8) + Number.parseInt(octet, 10), 0) >>> 0
}

export function isPrivateOrReservedTarget(target: ParsedVncTarget): boolean {
  if (target.hostType === "ipv4") {
    const value = ipv4ToInt(target.host)
    return PRIVATE_IPV4_RANGES.some(([start, end]) => value >= start && value <= end)
  }

  if (target.hostType === "ipv6") {
    const normalized = target.host.toLowerCase()
    if (normalized === "::1" || normalized === "::") {
      return true
    }
    if (normalized.startsWith("fe80") || normalized.startsWith("fc") || normalized.startsWith("fd")) {
      return true
    }
    if (normalized.startsWith("::ffff:")) {
      const mapped = normalized.slice("::ffff:".length)
      if (isValidIpv4(mapped)) {
        const value = ipv4ToInt(mapped)
        return PRIVATE_IPV4_RANGES.some(([start, end]) => value >= start && value <= end)
      }
    }
    return false
  }

  const lowered = target.host.toLowerCase()
  return lowered === "localhost" || lowered.endsWith(".localhost") || lowered.endsWith(".local")
}

export function formatTarget(target: ParsedVncTarget): string {
  if (target.hostType === "ipv6") {
    return `[${target.host}]:${target.port}`
  }
  return `${target.host}:${target.port}`
}
