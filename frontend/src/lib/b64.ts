/** Base64 helpers shared by the lab and messaging screens. */

export function toBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

export function fromBase64(value: string): Uint8Array {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

/** UTF-8 → Base64, the shape the lab API accepts for keys and ciphertext. */
export function textToBase64(text: string): string {
  return toBase64(new TextEncoder().encode(text))
}

export function base64ToText(value: string): string {
  return new TextDecoder().decode(fromBase64(value))
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

/** Shorten a long hex/base64 value for display, keeping both ends visible. */
export function truncateMiddle(value: string, keep = 10): string {
  if (value.length <= keep * 2 + 1) return value
  return `${value.slice(0, keep)}…${value.slice(-keep)}`
}
