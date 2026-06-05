import { connect } from "cloudflare:sockets"

export interface WebshareTunnelOptions {
  targetHost: string
  targetPort: number
  country?: string
  sessionId: string
  proxyHost: string
  proxyPort: number
  username: string
  password: string
}

export interface TunnelConnection {
  readable: ReadableStream<Uint8Array>
  writable: WritableStream<Uint8Array>
  closed: Promise<void>
  close: () => void
}

function buildProxyUsername(base: string, country: string | undefined, sessionId: string): string {
  const numericSession = Math.abs(hashString(sessionId)) % 100000
  const parts = [base]
  if (country) {
    parts.push(country.toLowerCase())
  }
  parts.push(String(numericSession))
  return parts.join("-")
}

function hashString(value: string): number {
  let hash = 0
  for (let i = 0; i < value.length; i += 1) {
    hash = (hash << 5) - hash + value.charCodeAt(i)
    hash |= 0
  }
  return hash
}

function encodeBasicAuth(username: string, password: string): string {
  const raw = `${username}:${password}`
  let binary = ""
  const bytes = new TextEncoder().encode(raw)
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

async function readUntilHeadersEnd(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<{ status: number; leftover: Uint8Array }> {
  const decoder = new TextDecoder()
  let buffer = ""
  let raw = new Uint8Array(0)

  for (;;) {
    const { value, done } = await reader.read()
    if (done) {
      throw new Error("Proxy closed during CONNECT handshake")
    }
    const merged = new Uint8Array(raw.length + value.length)
    merged.set(raw, 0)
    merged.set(value, raw.length)
    raw = merged
    buffer = decoder.decode(raw, { stream: true })

    const separatorIndex = buffer.indexOf("\r\n\r\n")
    if (separatorIndex !== -1) {
      const headerText = buffer.slice(0, separatorIndex)
      const statusLine = headerText.split("\r\n")[0]
      const match = statusLine.match(/^HTTP\/\d\.\d\s+(\d{3})/)
      if (!match) {
        throw new Error("Malformed proxy response")
      }
      const status = Number.parseInt(match[1], 10)
      const headerByteLength = byteLengthOfHeaders(raw, separatorIndex + 4)
      const leftover = raw.subarray(headerByteLength)
      return { status, leftover }
    }

    if (raw.length > 16 * 1024) {
      throw new Error("Proxy response headers too large")
    }
  }
}

function byteLengthOfHeaders(raw: Uint8Array, charSeparatorIndex: number): number {
  const decoder = new TextDecoder()
  let low = 0
  let high = raw.length
  while (low < high) {
    const mid = (low + high) >> 1
    const length = decoder.decode(raw.subarray(0, mid)).length
    if (length < charSeparatorIndex) {
      low = mid + 1
    } else {
      high = mid
    }
  }
  return low
}

export async function openWebshareTunnel(options: WebshareTunnelOptions): Promise<TunnelConnection> {
  const socket = connect(
    { hostname: options.proxyHost, port: options.proxyPort },
    { allowHalfOpen: false, secureTransport: "off" },
  )

  const writer = socket.writable.getWriter()
  const reader = socket.readable.getReader()

  const proxyUsername = buildProxyUsername(options.username, options.country, options.sessionId)
  const auth = encodeBasicAuth(proxyUsername, options.password)
  const targetAuthority = `${options.targetHost}:${options.targetPort}`

  const connectRequest =
    `CONNECT ${targetAuthority} HTTP/1.1\r\n` +
    `Host: ${targetAuthority}\r\n` +
    `Proxy-Authorization: Basic ${auth}\r\n` +
    `Proxy-Connection: keep-alive\r\n` +
    `\r\n`

  await writer.write(new TextEncoder().encode(connectRequest))

  const { status, leftover } = await readUntilHeadersEnd(reader)
  if (status < 200 || status >= 300) {
    writer.releaseLock()
    reader.releaseLock()
    socket.close().catch(() => undefined)
    throw new Error(`Proxy refused the tunnel (status ${status})`)
  }

  writer.releaseLock()
  reader.releaseLock()

  const readable = buildReadable(socket.readable, leftover)

  return {
    readable,
    writable: socket.writable,
    closed: socket.closed,
    close: () => {
      socket.close().catch(() => undefined)
    },
  }
}

function buildReadable(source: ReadableStream<Uint8Array>, leftover: Uint8Array): ReadableStream<Uint8Array> {
  const sourceReader = source.getReader()
  let sentLeftover = leftover.length === 0

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (!sentLeftover) {
        sentLeftover = true
        if (leftover.length > 0) {
          controller.enqueue(leftover)
          return
        }
      }
      try {
        const { value, done } = await sourceReader.read()
        if (done) {
          controller.close()
          return
        }
        if (value) {
          controller.enqueue(value)
        }
      } catch (error) {
        controller.error(error)
      }
    },
    cancel(reason) {
      sourceReader.cancel(reason).catch(() => undefined)
    },
  })
}
