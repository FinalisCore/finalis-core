import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { decodeAddress, deriveAddressFromPubkey } from '../src/address/index.js';
import { keypairFromPrivkeyHex } from '../src/crypto/ed25519.js';

const vectors = JSON.parse(
  readFileSync(join(process.cwd(), 'test-vectors', 'vectors.json'), 'utf8'),
) as {
  address: { seed_hex: string; pubkey_hex: string; hrp: 'tsc' | 'sc'; address: string };
};

describe('address', () => {
  it('matches C++ key derivation/address vector', () => {
    const kp = keypairFromPrivkeyHex(vectors.address.seed_hex);
    expect(kp.pubkeyHex).toBe(vectors.address.pubkey_hex);
    expect(deriveAddressFromPubkey(kp.pubkeyHex, vectors.address.hrp)).toBe(vectors.address.address);
  });

  it('decodes back to same hrp and pubkey hash', () => {
    const decoded = decodeAddress(vectors.address.address);
    expect(decoded.hrp).toBe(vectors.address.hrp);
    expect(decoded.addrType).toBe(0);
    expect(decoded.pubkeyHash.length).toBe(20);
  });
});
