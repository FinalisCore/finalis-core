import { concatBytes, hexToBytes, sha256Bytes, utf8Bytes } from '../crypto/hash.js';

function leafHash(key32: Uint8Array, value: Uint8Array): Uint8Array {
  return sha256Bytes(concatBytes(utf8Bytes('SC-SMT-LEAF-V0'), key32, sha256Bytes(value)));
}

function emptyLeafHash(): Uint8Array {
  return sha256Bytes(utf8Bytes('SC-SMT-EMPTY-V0'));
}

function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256Bytes(concatBytes(utf8Bytes('SC-SMT-NODE-V0'), left, right));
}

function bitAtMsb0(key32: Uint8Array, bitIndex: number): number {
  const byte = Math.floor(bitIndex / 8);
  const bit = 7 - (bitIndex % 8);
  return (key32[byte] >> bit) & 1;
}

export function verifySmtProof(rootHex: string, keyHex: string, valueHex: string | null, siblingsHex: string[]): boolean {
  const root = hexToBytes(rootHex);
  const key = hexToBytes(keyHex);
  if (root.length !== 32 || key.length !== 32) throw new Error('root/key must be 32 bytes');
  if (siblingsHex.length !== 256) return false;
  let cur = valueHex === null ? emptyLeafHash() : leafHash(key, hexToBytes(valueHex));
  for (let i = 0; i < siblingsHex.length; i++) {
    const sib = hexToBytes(siblingsHex[i]);
    if (sib.length !== 32) return false;
    const bitIndex = 255 - i;
    if (bitAtMsb0(key, bitIndex) === 1) cur = nodeHash(sib, cur);
    else cur = nodeHash(cur, sib);
  }
  return Buffer.from(cur).equals(Buffer.from(root));
}

