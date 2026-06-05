const ITE_INFO = "VNC2Go-ITE-v1"
const ITE_SALT = "VNC2Go-ITE-salt-v1"
const NONCE_BYTES = 12
const KEY_BITS = 256

export interface IteSession {
  key: CryptoKey
  sendCounter: Uint8Array
  recvHighWater: bigint
  fingerprint: string
}

function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0)
  const out = new Uint8Array(total)
  let offset = 0
  for (const chunk of chunks) {
    out.set(chunk, offset)
    offset += chunk.length
  }
  return out
}

export async function generateHandshakeKeys(): Promise<{ privateKey: CryptoKey; publicKeyRaw: Uint8Array }> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, [
    "deriveBits",
  ])) as CryptoKeyPair
  const raw = new Uint8Array((await crypto.subtle.exportKey("raw", pair.publicKey)) as ArrayBuffer)
  return { privateKey: pair.privateKey, publicKeyRaw: raw }
}

export async function importPeerPublicKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw, { name: "ECDH", namedCurve: "P-256" }, false, [])
}

async function deriveFingerprint(keyBytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", keyBytes))
  const groups: string[] = []
  for (let i = 0; i < 8; i += 1) {
    const value = (digest[i * 2] << 8) | digest[i * 2 + 1]
    groups.push(value.toString(16).padStart(4, "0").toUpperCase())
  }
  return groups.join("-")
}

export async function deriveIteSession(privateKey: CryptoKey, peerPublicKey: CryptoKey): Promise<IteSession> {
  const sharedBits = new Uint8Array(
    await crypto.subtle.deriveBits({ name: "ECDH", $public: peerPublicKey }, privateKey, KEY_BITS),
  )

  const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"])
  const encoder = new TextEncoder()

  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: encoder.encode(ITE_SALT),
      info: encoder.encode(ITE_INFO),
    },
    hkdfKey,
    { name: "AES-GCM", length: KEY_BITS },
    true,
    ["encrypt", "decrypt"],
  )

  const exported = new Uint8Array((await crypto.subtle.exportKey("raw", aesKey)) as ArrayBuffer)
  const fingerprint = await deriveFingerprint(exported)

  return {
    key: aesKey,
    sendCounter: new Uint8Array(NONCE_BYTES),
    recvHighWater: -1n,
    fingerprint,
  }
}

function incrementCounter(counter: Uint8Array): void {
  for (let i = counter.length - 1; i >= 0; i -= 1) {
    counter[i] += 1
    if (counter[i] !== 0) {
      return
    }
  }
  throw new Error("ITE nonce space exhausted")
}

function nonceToBigInt(nonce: Uint8Array): bigint {
  let value = 0n
  for (const byte of nonce) {
    value = (value << 8n) | BigInt(byte)
  }
  return value
}

export async function encryptFrame(session: IteSession, plaintext: Uint8Array): Promise<Uint8Array> {
  const nonce = session.sendCounter.slice()
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, tagLength: 128 }, session.key, plaintext),
  )
  incrementCounter(session.sendCounter)
  return concatBytes(nonce, ciphertext)
}

export async function decryptFrame(session: IteSession, frame: Uint8Array): Promise<Uint8Array> {
  if (frame.length < NONCE_BYTES + 16) {
    throw new Error("ITE frame is too short")
  }
  const nonce = frame.subarray(0, NONCE_BYTES)
  const ciphertext = frame.subarray(NONCE_BYTES)

  const counterValue = nonceToBigInt(nonce)
  if (counterValue <= session.recvHighWater) {
    throw new Error("ITE replay detected")
  }

  const plaintext = new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce, tagLength: 128 }, session.key, ciphertext),
  )

  session.recvHighWater = counterValue
  return plaintext
}
