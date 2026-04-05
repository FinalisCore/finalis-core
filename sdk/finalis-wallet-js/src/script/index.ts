import { decodeAddress } from '../address/index.js';
import { bytesToHex, concatBytes, hexToBytes, sha256Bytes } from '../crypto/hash.js';

export function p2pkhScriptPubKey(pubkeyHash: Uint8Array): Uint8Array {
  if (pubkeyHash.length !== 20) throw new Error('pubkey hash must be 20 bytes');
  return concatBytes(Uint8Array.from([0x76, 0xa9, 0x14]), pubkeyHash, Uint8Array.from([0x88, 0xac]));
}

export function p2pkhScriptPubKeyHexFromAddress(address: string): string {
  const decoded = decodeAddress(address);
  return bytesToHex(p2pkhScriptPubKey(decoded.pubkeyHash));
}

export function scriptHashHex(scriptPubKeyHex: string): string {
  return bytesToHex(sha256Bytes(hexToBytes(scriptPubKeyHex)));
}

export function scriptHashHexFromAddress(address: string): string {
  return scriptHashHex(p2pkhScriptPubKeyHexFromAddress(address));
}
