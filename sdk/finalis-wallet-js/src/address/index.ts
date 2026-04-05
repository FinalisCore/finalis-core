import { concatBytes, h160, hexToBytes, sha256dBytes, utf8Bytes } from '../crypto/hash.js';

const ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

function base32Encode(data: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const b of data) {
    buffer = (buffer << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(buffer >> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += ALPHABET[(buffer << (5 - bits)) & 0x1f];
  }
  return out;
}

function base32Decode(s: string): Uint8Array {
  let buffer = 0;
  let bits = 0;
  const out: number[] = [];
  for (const ch of s) {
    const v = ALPHABET.indexOf(ch);
    if (v < 0) throw new Error('invalid base32');
    buffer = (buffer << 5) | v;
    bits += 5;
    while (bits >= 8) {
      out.push((buffer >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (bits > 0) {
    const rem = buffer & ((1 << bits) - 1);
    if (rem !== 0) throw new Error('non-canonical base32 tail');
  }
  return Uint8Array.from(out);
}

function checksumHash(hrp: string, payload: Uint8Array): Uint8Array {
  return sha256dBytes(concatBytes(utf8Bytes(hrp), Uint8Array.from([0]), payload));
}

export function encodeP2PKHAddress(hrp: 'sc' | 'tsc', pubkeyHash: Uint8Array): string {
  if (pubkeyHash.length !== 20) throw new Error('pubkey hash must be 20 bytes');
  const payload = concatBytes(Uint8Array.from([0x00]), pubkeyHash);
  const chk = checksumHash(hrp, payload).slice(0, 4);
  return `${hrp}1${base32Encode(concatBytes(payload, chk))}`;
}

export interface DecodedAddress {
  hrp: 'sc' | 'tsc';
  addrType: number;
  pubkeyHash: Uint8Array;
}

export function decodeAddress(address: string): DecodedAddress {
  const sep = address.indexOf('1');
  if (sep <= 0) throw new Error('missing separator');
  const hrp = address.slice(0, sep);
  if (hrp !== 'sc' && hrp !== 'tsc') throw new Error('unsupported hrp');
  const data = base32Decode(address.slice(sep + 1));
  if (data.length !== 25) throw new Error('decoded size mismatch');
  const payload = data.slice(0, 21);
  const checksum = data.slice(21);
  const expected = checksumHash(hrp, payload).slice(0, 4);
  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== expected[i]) throw new Error('checksum mismatch');
  }
  if (payload[0] !== 0x00) throw new Error('unsupported address type');
  return { hrp, addrType: 0x00, pubkeyHash: payload.slice(1) };
}

export function deriveAddressFromPubkey(pubkeyHex: string, hrp: 'sc' | 'tsc' = 'tsc'): string {
  const pub = hexToBytes(pubkeyHex);
  if (pub.length !== 32) throw new Error('pubkey must be 32 bytes');
  return encodeP2PKHAddress(hrp, h160(pub));
}
