import {
  deriveIteSession,
  generateHandshakeKeys,
  importPeerPublicKey,
  encryptFrame,
  decryptFrame,
  type IteSession,
} from "@/lib/ite-crypto"
import {
  ControlOp,
  FrameType,
  ITE_PROTOCOL_VERSION,
  buildHandshakeFrame,
  decodeApplicationFrame,
  decodeControl,
  encodeApplicationFrame,
  parseHandshakeFrame,
} from "@/lib/ite-protocol"

type ChannelState = "connecting" | "open" | "closing" | "closed"

export interface IteControlEvent {
  op: number
  reason?: string
}

export interface IteChannelCallbacks {
  onReady?: (fingerprint: string) => void
  onControl?: (event: IteControlEvent) => void
}

export class IteChannel {
  public binaryType: BinaryType = "arraybuffer"
  public readyState: number = WebSocket.CONNECTING
  public protocol = ""

  public onopen: ((this: IteChannel, ev: Event) => unknown) | null = null
  public onmessage: ((this: IteChannel, ev: MessageEvent) => unknown) | null = null
  public onerror: ((this: IteChannel, ev: Event) => unknown) | null = null
  public onclose: ((this: IteChannel, ev: CloseEvent) => unknown) | null = null

  private socket: WebSocket
  private session: IteSession | null = null
  private state: ChannelState = "connecting"
  private handshakeComplete = false
  private privateKey: CryptoKey | null = null
  private publicKeyRaw: Uint8Array | null = null
  private sendQueue: Uint8Array[] = []
  private callbacks: IteChannelCallbacks
  private encryptChain: Promise<void> = Promise.resolve()

  constructor(url: string, callbacks: IteChannelCallbacks = {}) {
    this.callbacks = callbacks
    this.socket = new WebSocket(url)
    this.socket.binaryType = "arraybuffer"

    this.socket.onopen = () => {
      void this.handleSocketOpen()
    }
    this.socket.onmessage = (event) => {
      void this.handleSocketMessage(event)
    }
    this.socket.onerror = (event) => {
      this.onerror?.call(this, event)
    }
    this.socket.onclose = (event) => {
      this.state = "closed"
      this.readyState = WebSocket.CLOSED
      this.onclose?.call(this, event)
    }
  }

  get fingerprint(): string | null {
    return this.session?.fingerprint ?? null
  }

  private async handleSocketOpen(): Promise<void> {
    const keys = await generateHandshakeKeys()
    this.privateKey = keys.privateKey
    this.publicKeyRaw = keys.publicKeyRaw
  }

  private async handleSocketMessage(event: MessageEvent): Promise<void> {
    if (typeof event.data === "string") {
      return
    }
    const data = new Uint8Array(event.data as ArrayBuffer)

    if (!this.handshakeComplete) {
      await this.handleHandshakeFrame(data)
      return
    }

    if (!this.session) {
      return
    }

    let plaintext: Uint8Array
    try {
      plaintext = await decryptFrame(this.session, data)
    } catch {
      this.failClose(4002, "decryption failed")
      return
    }

    const { kind, payload } = decodeApplicationFrame(plaintext)
    if (kind === FrameType.Control) {
      const control = decodeControl(payload)
      this.callbacks.onControl?.({ op: control.op, reason: control.reason })
      if (
        control.op === ControlOp.Disconnect ||
        control.op === ControlOp.IdleTimeout ||
        control.op === ControlOp.HardTimeout
      ) {
        this.close(1000, control.reason ?? "session ended")
      }
      return
    }

    if (kind === FrameType.Data) {
      const messageEvent = new MessageEvent("message", { data: payload.buffer.slice(payload.byteOffset, payload.byteOffset + payload.byteLength) })
      this.onmessage?.call(this, messageEvent)
    }
  }

  private async handleHandshakeFrame(data: Uint8Array): Promise<void> {
    const frame = parseHandshakeFrame(data)
    if (!frame) {
      this.failClose(4000, "bad handshake")
      return
    }

    if (frame.type === FrameType.ServerHello) {
      if (frame.version !== ITE_PROTOCOL_VERSION) {
        this.failClose(4000, "protocol version mismatch")
        return
      }
      if (!this.privateKey || !this.publicKeyRaw) {
        const keys = await generateHandshakeKeys()
        this.privateKey = keys.privateKey
        this.publicKeyRaw = keys.publicKeyRaw
      }
      const peerKey = await importPeerPublicKey(frame.publicKey)
      this.session = await deriveIteSession(this.privateKey, peerKey)
      this.socket.send(buildHandshakeFrame(FrameType.ClientHello, ITE_PROTOCOL_VERSION, this.publicKeyRaw))
      return
    }

    if (frame.type === FrameType.Ready) {
      this.handshakeComplete = true
      this.state = "open"
      this.readyState = WebSocket.OPEN
      if (this.session) {
        this.callbacks.onReady?.(this.session.fingerprint)
      }
      this.onopen?.call(this, new Event("open"))
      this.flushQueue()
    }
  }

  private flushQueue(): void {
    const pending = this.sendQueue
    this.sendQueue = []
    for (const chunk of pending) {
      this.send(chunk)
    }
  }

  send(data: ArrayBuffer | ArrayBufferView | string): void {
    let bytes: Uint8Array
    if (typeof data === "string") {
      bytes = new TextEncoder().encode(data)
    } else if (data instanceof ArrayBuffer) {
      bytes = new Uint8Array(data)
    } else {
      bytes = new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    }

    if (!this.handshakeComplete || !this.session) {
      this.sendQueue.push(bytes.slice())
      return
    }

    const session = this.session
    const frame = encodeApplicationFrame(FrameType.Data, bytes)
    const snapshot = frame.slice()
    this.encryptChain = this.encryptChain
      .then(async () => {
        if (this.state !== "open") {
          return
        }
        const encrypted = await encryptFrame(session, snapshot)
        this.socket.send(encrypted)
      })
      .catch(() => {
        this.failClose(4003, "encryption failed")
      })
  }

  private failClose(code: number, reason: string): void {
    this.onerror?.call(this, new Event("error"))
    this.close(code, reason)
  }

  close(code?: number, reason?: string): void {
    if (this.state === "closed" || this.state === "closing") {
      return
    }
    this.state = "closing"
    this.readyState = WebSocket.CLOSING
    try {
      if (code === undefined) {
        this.socket.close()
      } else {
        this.socket.close(code, reason)
      }
    } catch {
      this.state = "closed"
      this.readyState = WebSocket.CLOSED
    }
  }
}
