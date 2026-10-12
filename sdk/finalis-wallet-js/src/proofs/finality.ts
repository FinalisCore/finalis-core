import { verifyEd25519 } from '../crypto/ed25519.js';
import { concatBytes, hexToBytes, sha256dBytes, u32le, u64le, utf8Bytes } from '../crypto/hash.js';

export interface FinalitySig {
  pubkey_hex: string;
  sig_hex: string;
}

// The fields of a lightserver finality certificate that the signatures commit to
// (see finality_certificate_json in src/lightserver/server.cpp).
export interface FinalityCertificateLike {
  height: number | bigint;
  round: number;
  transition_hash: string;
  signatures: FinalitySig[];
}

export function quorumThreshold(n: number): number {
  if (n <= 0) return 0;
  return Math.floor((2 * n) / 3) + 1;
}

function fixedHex(hex: string, len: number, what: string): Uint8Array {
  const b = hexToBytes(hex);
  if (b.length !== len) throw new Error(`${what} must be ${len} bytes`);
  return b;
}

// Chain domain every consensus signature covers: sha256d("SC-CHAIN-DOMAIN-V1" || network_id[16] ||
// genesis_hash[32]). Must match consensus_chain_domain in src/utxo/validate.cpp. Pin both values for
// the network you expect; taking them from the server you are checking proves nothing.
export function consensusChainDomain(networkIdHex: string, genesisHashHex: string): Uint8Array {
  return sha256dBytes(
    concatBytes(
      utf8Bytes('SC-CHAIN-DOMAIN-V1'),
      fixedHex(networkIdHex, 16, 'network id'),
      fixedHex(genesisHashHex, 32, 'genesis hash'),
    ),
  );
}

// Exactly what validators sign:
// sha256d("SC-VOTE-V1" || chain_domain || u64le(height) || u32le(round) || transition_id).
// Must match vote_signing_message in src/utxo/validate.cpp.
export function voteSigningMessage(
  chainDomainHex: string,
  height: number | bigint,
  round: number,
  transitionIdHex: string,
): Uint8Array {
  const chainDomain = fixedHex(chainDomainHex, 32, 'chain domain');
  const transitionId = fixedHex(transitionIdHex, 32, 'transition id');
  if (!Number.isInteger(round) || round < 0 || round > 0xffffffff) throw new Error('round must be a u32');
  const h = typeof height === 'bigint' ? height : BigInt(height);
  return sha256dBytes(concatBytes(utf8Bytes('SC-VOTE-V1'), chainDomain, u64le(h), u32le(round), transitionId));
}

// Verifies that a quorum of `committeePubkeysHex` signed the certificate's (height, round,
// transition_hash) on the chain `chainDomainHex` (see consensusChainDomain). The committee and the
// chain domain must come from a source the caller trusts, not from the certificate itself, or the
// check proves nothing.
export function verifyFinalityProof(
  cert: FinalityCertificateLike,
  committeePubkeysHex: string[],
  chainDomainHex: string,
): boolean {
  const committee = new Set(committeePubkeysHex.map((p) => p.toLowerCase()));
  if (committee.size === 0) return false;
  const need = quorumThreshold(committee.size);

  let msg: Uint8Array;
  try {
    msg = voteSigningMessage(chainDomainHex, cert.height, cert.round, cert.transition_hash);
  } catch {
    return false;
  }

  let valid = 0;
  const seen = new Set<string>();
  for (const s of cert.signatures) {
    const pk = s.pubkey_hex.toLowerCase();
    if (seen.has(pk)) continue;
    if (!committee.has(pk)) continue;
    let ok = false;
    try {
      ok = verifyEd25519(msg, s.sig_hex.toLowerCase(), pk);
    } catch {
      ok = false;  // malformed hex counts as an invalid signature
    }
    if (!ok) continue;
    seen.add(pk);
    valid += 1;
  }
  return valid >= need;
}
