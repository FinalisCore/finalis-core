import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha2';

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  if ((hex.length & 1) !== 0) throw new Error('hex length must be even');
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error('invalid hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function concatBytes(...chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

export function utf8Bytes(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

export function sha256Bytes(data: Uint8Array): Uint8Array {
  return sha256(data);
}

export function sha256dBytes(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

export function h160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

export function u32le(n: number): Uint8Array {
  const out = new Uint8Array(4);
  const dv = new DataView(out.buffer);
  dv.setUint32(0, n >>> 0, true);
  return out;
}

export function u64le(n: bigint): Uint8Array {
  if (n < 0n || n > 0xffffffffffffffffn) throw new Error('u64 out of range');
  const out = new Uint8Array(8);
  const dv = new DataView(out.buffer);
  dv.setBigUint64(0, n, true);
  return out;
}

export function cmpHexAsc(a: string, b: string): number {
  const aa = a.toLowerCase();
  const bb = b.toLowerCase();
  if (aa < bb) return -1;
  if (aa > bb) return 1;
  return 0;
}
