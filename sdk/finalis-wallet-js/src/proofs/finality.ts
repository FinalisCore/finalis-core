import { verifyEd25519 } from '../crypto/ed25519.js';
import { hexToBytes } from '../crypto/hash.js';

export interface FinalitySig {
  pubkey_hex: string;
  sig_hex: string;
}

export function quorumThreshold(n: number): number {
  if (n <= 0) return 0;
  return Math.floor((2 * n) / 3) + 1;
}

export function verifyFinalityProof(blockHashHex: string, sigs: FinalitySig[], committeePubkeysHex: string[]): boolean {
  const committee = new Set(committeePubkeysHex.map((p) => p.toLowerCase()));
  if (committee.size === 0) return false;
  const need = quorumThreshold(committee.size);
  const msg = hexToBytes(blockHashHex);
  if (msg.length !== 32) return false;

  let valid = 0;
  const seen = new Set<string>();
  for (const s of sigs) {
    const pk = s.pubkey_hex.toLowerCase();
    if (seen.has(pk)) continue;
    if (!committee.has(pk)) continue;
    if (!verifyEd25519(msg, s.sig_hex.toLowerCase(), pk)) continue;
    seen.add(pk);
    valid += 1;
  }
  return valid >= need;
}
