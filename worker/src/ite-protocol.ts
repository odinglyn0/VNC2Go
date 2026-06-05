export const ITE_PROTOCOL_VERSION = 1

export const FrameType = {
  ServerHello: 0x01,
  ClientHello: 0x02,
  Ready: 0x03,
  Data: 0x10,
  Control: 0x20,
} as const

export const ControlOp = {
  Disconnect: 0x01,
  IdleTimeout: 0x02,
  HardTimeout: 0x03,
  Ping: 0x04,
  Pong: 0x05,
} as const

export interface ControlMessage {
  op: number
  reason?: string
}

export function buildHandshakeFrame(type: number, version: number, publicKey: Uint8Array): Uint8Array {
  const out = new Uint8Array(2 + publicKey.length)
  out[0] = type
  out[1] = version
  out.set(publicKey, 2)
  return out
}

export function parseHandshakeFrame(frame: Uint8Array): { type: number; version: number; publicKey: Uint8Array } | null {
  if (frame.length < 2) {
    return null
  }
  return {
    type: frame[0],
    version: frame[1],
    publicKey: frame.subarray(2),
  }
}

export function encodeControl(message: ControlMessage): Uint8Array {
  const reasonBytes = message.reason ? new TextEncoder().encode(message.reason) : new Uint8Array(0)
  const out = new Uint8Array(1 + reasonBytes.length)
  out[0] = message.op
  out.set(reasonBytes, 1)
  return out
}

export function decodeControl(payload: Uint8Array): ControlMessage {
  const op = payload[0]
  const reason = payload.length > 1 ? new TextDecoder().decode(payload.subarray(1)) : undefined
  return { op, reason }
}

export function encodeApplicationFrame(kind: number, payload: Uint8Array): Uint8Array {
  const out = new Uint8Array(1 + payload.length)
  out[0] = kind
  out.set(payload, 1)
  return out
}

export function decodeApplicationFrame(frame: Uint8Array): { kind: number; payload: Uint8Array } {
  return { kind: frame[0], payload: frame.subarray(1) }
}
