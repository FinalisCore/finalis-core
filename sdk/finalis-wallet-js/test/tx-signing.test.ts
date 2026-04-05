import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { decodeAddress } from '../src/address/index.js';
import { p2pkhScriptPubKey } from '../src/script/index.js';
import { bytesToHex } from '../src/crypto/hash.js';
import { createSignedP2PKHTransaction } from '../src/tx/tx.js';

const vectors = JSON.parse(
  readFileSync(join(process.cwd(), 'test-vectors', 'vectors.json'), 'utf8'),
) as {
  tx_signing: {
    prev_txid_hex: string;
    prev_index: number;
    from_privkey_hex: string;
    from_pubkey_hex: string;
    to_address: string;
    amount_units: string;
    fee_units: string;
    expected_txid: string;
    expected_tx_hex: string;
  };
  script: { address: string; script_pubkey_hex: string };
};

describe('tx signing interop', () => {
  it('matches C++ CLI tx_hex/txid vector exactly', () => {
    const to = decodeAddress(vectors.tx_signing.to_address);
    const change = decodeAddress(vectors.script.address);

    const amount = BigInt(vectors.tx_signing.amount_units);
    const fee = BigInt(vectors.tx_signing.fee_units);
    const prev = 1_000_000n;
    const changeAmount = prev - amount - fee;

    const tx = createSignedP2PKHTransaction({
      prevTxidHex: vectors.tx_signing.prev_txid_hex,
      prevIndex: vectors.tx_signing.prev_index,
      privkeyHex: vectors.tx_signing.from_privkey_hex,
      pubkeyHex: vectors.tx_signing.from_pubkey_hex,
      outputs: [
        { valueUnits: amount, scriptPubKeyHex: bytesToHex(p2pkhScriptPubKey(to.pubkeyHash)) },
        { valueUnits: changeAmount, scriptPubKeyHex: bytesToHex(p2pkhScriptPubKey(change.pubkeyHash)) },
      ],
    });

    expect(tx.txid).toBe(vectors.tx_signing.expected_txid);
    expect(tx.txHex).toBe(vectors.tx_signing.expected_tx_hex);
  });
});
