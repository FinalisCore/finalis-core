import { cmpHexAsc } from '../crypto/hash.js';
import type { WalletUtxo } from '../types/index.js';

export function deterministicLargestFirst(utxos: WalletUtxo[]): WalletUtxo[] {
  return [...utxos].sort((a, b) => {
    if (a.valueUnits !== b.valueUnits) return a.valueUnits > b.valueUnits ? -1 : 1;
    const txCmp = cmpHexAsc(a.txid, b.txid);
    if (txCmp !== 0) return txCmp;
    return a.vout - b.vout;
  });
}

export function selectCoins(utxos: WalletUtxo[], target: bigint): WalletUtxo[] {
  const sorted = deterministicLargestFirst(utxos);
  const out: WalletUtxo[] = [];
  let sum = 0n;
  for (const u of sorted) {
    out.push(u);
    sum += u.valueUnits;
    if (sum >= target) return out;
  }
  throw new Error('insufficient funds');
}
