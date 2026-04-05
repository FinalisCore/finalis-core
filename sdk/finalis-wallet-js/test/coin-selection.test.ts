import { describe, expect, it } from 'vitest';

import { deterministicLargestFirst, selectCoins } from '../src/wallet/coinSelection.js';
import type { WalletUtxo } from '../src/types/index.js';

describe('coin selection', () => {
  it('sorts by value desc then txid asc then vout asc', () => {
    const utxos: WalletUtxo[] = [
      { txid: 'bb', vout: 1, valueUnits: 500n, height: 1n, scriptPubKeyHex: 'aa' },
      { txid: 'aa', vout: 3, valueUnits: 500n, height: 1n, scriptPubKeyHex: 'aa' },
      { txid: 'aa', vout: 2, valueUnits: 500n, height: 1n, scriptPubKeyHex: 'aa' },
      { txid: 'cc', vout: 0, valueUnits: 1000n, height: 1n, scriptPubKeyHex: 'aa' },
    ];
    const sorted = deterministicLargestFirst(utxos);
    expect(sorted.map((u) => `${u.valueUnits}:${u.txid}:${u.vout}`)).toEqual([
      '1000:cc:0',
      '500:aa:2',
      '500:aa:3',
      '500:bb:1',
    ]);
  });

  it('selects deterministically until target met', () => {
    const utxos: WalletUtxo[] = [
      { txid: '01', vout: 0, valueUnits: 5n, height: 1n, scriptPubKeyHex: 'aa' },
      { txid: '02', vout: 0, valueUnits: 7n, height: 1n, scriptPubKeyHex: 'aa' },
      { txid: '03', vout: 0, valueUnits: 3n, height: 1n, scriptPubKeyHex: 'aa' },
    ];
    const selected = selectCoins(utxos, 10n);
    expect(selected.map((u) => u.txid)).toEqual(['02', '01']);
  });
});
