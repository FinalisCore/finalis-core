import { describe, expect, it } from 'vitest';

import { FinalisWallet, LightServerClient } from '../src/index.js';

const RUN = process.env.FINALIS_SDK_IT === '1';
const BASE_URL = process.env.FINALIS_LIGHTSERVER_URL ?? 'http://127.0.0.1:19444';
const FUNDING_PRIV = process.env.FINALIS_FUNDING_PRIVKEY;
const DEST_ADDRESS = process.env.FINALIS_IT_DEST_ADDRESS;

describe('integration devnet', () => {
  it.skipIf(!RUN)('builds, broadcasts, and observes finality via lightserver', async () => {
    if (!FUNDING_PRIV || !DEST_ADDRESS) {
      throw new Error('missing FINALIS_FUNDING_PRIVKEY or FINALIS_IT_DEST_ADDRESS');
    }

    const client = new LightServerClient(BASE_URL, { timeoutMs: 6000 });
    const wallet = new FinalisWallet(client);

    const sender = FinalisWallet.importPrivkeyHex(FUNDING_PRIV);
    const fromAddress = FinalisWallet.deriveAddress(sender.pubkeyHex, 'tsc');
    const before = await wallet.getBalance(fromAddress);
    expect(before > 0n).toBe(true);

    const sent = await wallet.sendTransaction({
      fromPrivkeyHex: FUNDING_PRIV,
      toAddress: DEST_ADDRESS,
      amountUnits: 1_000n,
      feeUnits: 1_000n,
      hrp: 'tsc',
    });

    const finalized = await wallet.waitForFinality(sent.txid, { timeoutMs: 180000, pollIntervalMs: 2000 });
    expect(finalized.height > 0n).toBe(true);

    const destUtxos = await wallet.listUtxos(DEST_ADDRESS);
    expect(destUtxos.some((u) => u.txid === sent.txid)).toBe(true);
  });
});
