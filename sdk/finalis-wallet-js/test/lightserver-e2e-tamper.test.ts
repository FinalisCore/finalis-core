import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { deriveAddressFromPubkey } from '../src/address/index.js';
import { keypairFromSeed32, signEd25519 } from '../src/crypto/ed25519.js';
import { bytesToHex } from '../src/crypto/hash.js';
import { FinalisWallet } from '../src/wallet/FinalisWallet.js';

type Vector = {
  name: string;
  root_hex: string;
  key_hex: string;
  value_hex: string | null;
  siblings: string[];
};

const vectors = JSON.parse(
  readFileSync(resolve(process.cwd(), 'test-vectors/smt_vectors.json'), 'utf8'),
) as Vector[];

function seed(n: number): Uint8Array {
  const s = new Uint8Array(32);
  for (let i = 0; i < s.length; i++) s[i] = (n * 31 + i) & 0xff;
  return s;
}

function mutateHex(hex: string): string {
  if (hex.length < 2) return hex;
  const c = hex[0] === 'a' ? 'b' : 'a';
  return c + hex.slice(1);
}

type Tamper = 'none' | 'root' | 'sibling' | 'value' | 'finality';

function makeWallet(tamper: Tamper): { wallet: FinalisWallet; address: string } {
  const vec = vectors.find((v) => v.name === 'membership_key10');
  if (!vec || !vec.value_hex) throw new Error('missing membership vector');

  const owner = keypairFromSeed32(seed(1));
  const address = deriveAddressFromPubkey(owner.pubkeyHex, 'sc');

  const committeeKeys = [keypairFromSeed32(seed(11)), keypairFromSeed32(seed(12)), keypairFromSeed32(seed(13)), keypairFromSeed32(seed(14))];
  const committee = committeeKeys.map((k) => k.pubkeyHex);

  const blockHashBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) blockHashBytes[i] = (i * 7 + 3) & 0xff;
  const blockHashHex = bytesToHex(blockHashBytes);
  const finality = committeeKeys.slice(0, 3).map((k) => ({
    pubkey_hex: k.pubkeyHex,
    sig_hex: bytesToHex(signEd25519(blockHashBytes, k.privkeyHex)),
  }));
  if (tamper === 'finality') finality[0].sig_hex = bytesToHex(new Uint8Array(64).fill(1));

  let rootHex = vec.root_hex;
  let siblings = vec.siblings.slice();
  let valueHex: string | null = vec.value_hex;
  if (tamper === 'root') rootHex = mutateHex(rootHex);
  if (tamper === 'sibling') siblings[0] = mutateHex(siblings[0]);
  if (tamper === 'value' && valueHex) valueHex = mutateHex(valueHex);

  const scriptPubKeyHex = bytesToHex(FinalisWallet.addressToScriptPubKey(address));
  const fakeClient = {
    async getTip() {
      return { height: 5n, hash: blockHashHex };
    },
    async getHeaderRange() {
      return [
        {
          height: 5n,
          header_hex: '',
          block_hash: blockHashHex,
          utxo_root: rootHex,
          validators_root: undefined,
          finality_proof: finality,
        },
      ];
    },
    async getCommittee() {
      return committee;
    },
    async getUtxosByScriptHash() {
      return [
        {
          txid: '00'.repeat(32),
          vout: 0,
          value: 42n,
          height: 5n,
          script_pubkey_hex: scriptPubKeyHex,
        },
      ];
    },
    async getUtxoProof() {
      return {
        proof_format: 'smt_v0' as const,
        height: 5n,
        key_hex: vec.key_hex,
        root_hex: vec.root_hex,
        utxo_root: vec.root_hex,
        value_hex: valueHex,
        siblings_hex: siblings,
        siblings,
      };
    },
  };

  return { wallet: new FinalisWallet(fakeClient as any), address };
}

describe('trustless wallet tamper rejection', () => {
  it('accepts valid proof/finality bundle', async () => {
    const { wallet, address } = makeWallet('none');
    await expect(wallet.getBalanceTrustless(address)).resolves.toEqual(42n);
  });

  it('rejects tampered root/sibling/value as SMT_PROOF_INVALID', async () => {
    for (const t of ['root', 'sibling', 'value'] as const) {
      const { wallet, address } = makeWallet(t);
      await expect(wallet.getBalanceTrustless(address)).rejects.toThrow('SMT_PROOF_INVALID');
    }
  });

  it('rejects tampered finality as FINALITY_PROOF_INVALID', async () => {
    const { wallet, address } = makeWallet('finality');
    await expect(wallet.getBalanceTrustless(address)).rejects.toThrow('FINALITY_PROOF_INVALID');
  });
});
