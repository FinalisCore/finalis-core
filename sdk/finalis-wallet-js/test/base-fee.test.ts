import { describe, expect, it } from 'vitest';

import { deriveAddressFromPubkey } from '../src/address/index.js';
import { keypairFromPrivkeyHex } from '../src/crypto/ed25519.js';
import { hexToBytes } from '../src/crypto/hash.js';
import { p2pkhScriptPubKeyHexFromAddress } from '../src/script/index.js';
import { DEFAULT_FEE_UNITS, requiredBaseFeeUnits } from '../src/tx/tx.js';
import type { LightServerClient } from '../src/rpc/LightServerClient.js';
import { FinalisWallet } from '../src/wallet/FinalisWallet.js';

const PRIV = '11'.repeat(32);
const DOMAIN = '22'.repeat(32);

function walletWithBaseFee(baseFeePerKib: bigint): FinalisWallet {
  const kp = keypairFromPrivkeyHex(PRIV);
  const address = deriveAddressFromPubkey(kp.pubkeyHex, 'tsc');
  const script = p2pkhScriptPubKeyHexFromAddress(address);
  const client = {
    getStatus: async () => ({ base_fee_per_kib: baseFeePerKib }),
    getUtxosByScriptHash: async () =>
      [1, 2, 3].map((i) => ({ txid: String(i).repeat(64), vout: 0, value: 10_000_000n, height: 1n, script_pubkey_hex: script })),
  } as unknown as LightServerClient;
  return new FinalisWallet(client);
}

const params = { fromPrivkeyHex: PRIV, toAddress: '', amountUnits: 1_000_000n, chainDomainHex: DOMAIN };

describe('base fee', () => {
  it('counts per started KiB like consensus', () => {
    expect(requiredBaseFeeUnits(10n, 1)).toBe(10n);
    expect(requiredBaseFeeUnits(10n, 1024)).toBe(10n);
    expect(requiredBaseFeeUnits(10n, 1025)).toBe(20n);
  });

  it('pays the default fee while the base fee is low', async () => {
    const w = walletWithBaseFee(1n);
    const to = deriveAddressFromPubkey(keypairFromPrivkeyHex('33'.repeat(32)).pubkeyHex, 'tsc');
    const built = await w.buildTransaction({ ...params, toAddress: to });
    const inSum = built.inputs.reduce((s, u) => s + u.valueUnits, 0n);
    const outSum = built.outputs.reduce((s, o) => s + o.valueUnits, 0n);
    expect(inSum - outSum).toBe(DEFAULT_FEE_UNITS);
  });

  it('raises the fee to what a high base fee asks, and refuses an explicit fee below it', async () => {
    const w = walletWithBaseFee(5_000n);
    const to = deriveAddressFromPubkey(keypairFromPrivkeyHex('33'.repeat(32)).pubkeyHex, 'tsc');
    const built = await w.buildTransaction({ ...params, toAddress: to });
    const inSum = built.inputs.reduce((s, u) => s + u.valueUnits, 0n);
    const outSum = built.outputs.reduce((s, o) => s + o.valueUnits, 0n);
    expect(inSum - outSum).toBeGreaterThanOrEqual(requiredBaseFeeUnits(5_000n, hexToBytes(built.txHex).length));
    await expect(w.buildTransaction({ ...params, toAddress: to, feeUnits: 1_000n })).rejects.toThrow(/below the chain's base fee/);
  });
});
