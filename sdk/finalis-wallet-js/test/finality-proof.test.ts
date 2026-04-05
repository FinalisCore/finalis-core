import { describe, expect, it } from 'vitest';

import { keypairFromSeed32, signEd25519 } from '../src/crypto/ed25519.js';
import { bytesToHex } from '../src/crypto/hash.js';
import { quorumThreshold, verifyFinalityProof } from '../src/proofs/finality.js';

function seed(n: number): Uint8Array {
  const s = new Uint8Array(32);
  for (let i = 0; i < s.length; i++) s[i] = (n * 17 + i) & 0xff;
  return s;
}

describe('finality proof verification', () => {
  it('computes quorum threshold as floor(2N/3)+1', () => {
    expect(quorumThreshold(1)).toBe(1);
    expect(quorumThreshold(2)).toBe(2);
    expect(quorumThreshold(3)).toBe(3);
    expect(quorumThreshold(4)).toBe(3);
    expect(quorumThreshold(10)).toBe(7);
  });

  it('accepts quorum of valid committee signatures', () => {
    const blockHash = new Uint8Array(32);
    for (let i = 0; i < blockHash.length; i++) blockHash[i] = (i * 13) & 0xff;
    const blockHashHex = bytesToHex(blockHash);

    const kps = [keypairFromSeed32(seed(1)), keypairFromSeed32(seed(2)), keypairFromSeed32(seed(3)), keypairFromSeed32(seed(4))];
    const committee = kps.map((k) => k.pubkeyHex);

    const sigs = [
      { pubkey_hex: kps[0].pubkeyHex, sig_hex: bytesToHex(signEd25519(blockHash, kps[0].privkeyHex)) },
      { pubkey_hex: kps[1].pubkeyHex, sig_hex: bytesToHex(signEd25519(blockHash, kps[1].privkeyHex)) },
      { pubkey_hex: kps[2].pubkeyHex, sig_hex: bytesToHex(signEd25519(blockHash, kps[2].privkeyHex)) },
    ];

    expect(verifyFinalityProof(blockHashHex, sigs, committee)).toBe(true);
  });

  it('rejects non-committee and invalid signatures', () => {
    const blockHash = new Uint8Array(32);
    for (let i = 0; i < blockHash.length; i++) blockHash[i] = (255 - i) & 0xff;
    const blockHashHex = bytesToHex(blockHash);

    const c1 = keypairFromSeed32(seed(10));
    const c2 = keypairFromSeed32(seed(11));
    const c3 = keypairFromSeed32(seed(12));
    const outsider = keypairFromSeed32(seed(13));
    const committee = [c1.pubkeyHex, c2.pubkeyHex, c3.pubkeyHex];

    const sigs = [
      { pubkey_hex: c1.pubkeyHex, sig_hex: bytesToHex(signEd25519(blockHash, c1.privkeyHex)) },
      { pubkey_hex: outsider.pubkeyHex, sig_hex: bytesToHex(signEd25519(blockHash, outsider.privkeyHex)) },
      { pubkey_hex: c2.pubkeyHex, sig_hex: bytesToHex(new Uint8Array(64).fill(7)) },
    ];

    expect(verifyFinalityProof(blockHashHex, sigs, committee)).toBe(false);
  });

  it('rejects duplicate signer pubkeys as quorum spoofing', () => {
    const blockHash = new Uint8Array(32);
    for (let i = 0; i < blockHash.length; i++) blockHash[i] = (i * 5 + 9) & 0xff;
    const blockHashHex = bytesToHex(blockHash);

    const a = keypairFromSeed32(seed(21));
    const b = keypairFromSeed32(seed(22));
    const c = keypairFromSeed32(seed(23));
    const committee = [a.pubkeyHex, b.pubkeyHex, c.pubkeyHex];

    // quorum(3)=3; duplicate signer A should count once, so this must fail.
    const sigA = bytesToHex(signEd25519(blockHash, a.privkeyHex));
    const sigs = [
      { pubkey_hex: a.pubkeyHex, sig_hex: sigA },
      { pubkey_hex: a.pubkeyHex, sig_hex: sigA },
      { pubkey_hex: b.pubkeyHex, sig_hex: bytesToHex(signEd25519(blockHash, b.privkeyHex)) },
    ];
    expect(verifyFinalityProof(blockHashHex, sigs, committee)).toBe(false);
  });
});
