import { afterEach, describe, expect, it, vi } from 'vitest';

import { LightServerClient } from '../src/rpc/LightServerClient.js';
import { FinalisWallet } from '../src/wallet/FinalisWallet.js';

const TXID = 'ab'.repeat(32);

// Answers JSON-RPC calls by method name; a function value receives the params.
function mockRpc(handlers: Record<string, unknown>) {
  vi.stubGlobal('fetch', async (_url: string, init: { body: string }) => {
    const req = JSON.parse(init.body) as { method: string; params: unknown };
    const h = handlers[req.method];
    const body =
      typeof h === 'function' ? (h as (p: unknown) => unknown)(req.params) : h ?? { error: { code: -32601, message: 'method not found' } };
    return { ok: true, status: 200, json: async () => body };
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('submitted, not final', () => {
  it('broadcastTx reports accepted_for_relay as not finalized', async () => {
    mockRpc({ broadcast_tx: { result: { accepted: true, txid: TXID.toUpperCase(), status: 'accepted_for_relay' } } });
    const r = await new LightServerClient('http://ls').broadcastTx('00');
    expect(r).toMatchObject({ accepted: true, finalized: false, txid: TXID, status: 'accepted_for_relay' });
  });

  it('broadcastTx surfaces the node mempool rejection code', async () => {
    mockRpc({
      broadcast_tx: {
        result: {
          accepted: false,
          txid: TXID,
          status: 'rejected',
          error_code: 'tx_conflict_in_mempool',
          error_message: 'double spend in mempool',
          retryable: false,
        },
      },
    });
    const r = await new LightServerClient('http://ls').broadcastTx('00');
    expect(r).toMatchObject({ accepted: false, errorCode: 'tx_conflict_in_mempool', error: 'double spend in mempool' });
  });

  it('getTxStatus maps certified_ingress and rejected', async () => {
    mockRpc({
      get_tx_status: (p: unknown) =>
        (p as { txid: string }).txid === TXID
          ? { result: { txid: TXID, status: 'certified_ingress', finalized: false, credit_safe: false, finalized_depth: 0 } }
          : { result: { txid: 'cd'.repeat(32), status: 'rejected', finalized: false, credit_safe: false, rejected_height: 42 } },
    });
    const client = new LightServerClient('http://ls');
    expect(await client.getTxStatus(TXID)).toMatchObject({ status: 'certified_ingress', finalized: false, creditSafe: false });
    expect(await client.getTxStatus('cd'.repeat(32))).toMatchObject({ status: 'rejected', rejectedHeight: 42n });
  });

  it('waitForFinality stops at a rejection instead of timing out', async () => {
    mockRpc({
      get_tx: { error: { code: -32001, message: 'not found' } },
      get_tx_status: { result: { txid: TXID, status: 'rejected', finalized: false, credit_safe: false, rejected_height: 7 } },
    });
    const wallet = new FinalisWallet(new LightServerClient('http://ls', { retries: 0 }));
    await expect(wallet.waitForFinality(TXID, { timeoutMs: 5000, pollIntervalMs: 10 })).rejects.toThrow(
      'rejected at finality (height 7)',
    );
  });
});
