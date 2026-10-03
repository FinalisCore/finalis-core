import { describe, expect, it } from 'vitest';

import { FinalisWallet } from '../src/wallet/FinalisWallet.js';

// SMT and finality-signature tamper rejection are covered by smt-proof.test.ts
// and finality-proof.test.ts. The wallet-level trustless flow is disabled until
// the lightserver exposes a finality-bound utxo_root (see RECOMMENDED_ROADMAP.md #7).
describe('trustless wallet balance', () => {
  it('fails closed with TRUSTLESS_NOT_SUPPORTED and makes no RPC calls', async () => {
    const fakeClient = new Proxy(
      {},
      {
        get() {
          throw new Error('unexpected RPC call');
        },
      },
    );
    const wallet = new FinalisWallet(fakeClient as any);
    await expect(wallet.getBalanceTrustless('unused')).rejects.toThrow('TRUSTLESS_NOT_SUPPORTED');
  });
});
