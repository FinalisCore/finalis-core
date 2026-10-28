import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';

import { decodeAddress } from '../src/address/index.js';
import { p2pkhScriptPubKey } from '../src/script/index.js';
import { bytesToHex } from '../src/crypto/hash.js';
import { consensusChainDomain } from '../src/proofs/finality.js';
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
    network_id_hex: string;
    genesis_hash_hex: string;
    chain_domain_hex: string;
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

    const chainDomainHex = bytesToHex(
      consensusChainDomain(vectors.tx_signing.network_id_hex, vectors.tx_signing.genesis_hash_hex),
    );
    expect(chainDomainHex).toBe(vectors.tx_signing.chain_domain_hex);

    const tx = createSignedP2PKHTransaction({
      prevTxidHex: vectors.tx_signing.prev_txid_hex,
      prevIndex: vectors.tx_signing.prev_index,
      prevOutput: { valueUnits: BigInt(vectors.tx_signing.prev_value_units), scriptPubKeyHex: vectors.script.script_pubkey_hex },
      privkeyHex: vectors.tx_signing.from_privkey_hex,
      pubkeyHex: vectors.tx_signing.from_pubkey_hex,
      outputs: [
        { valueUnits: amount, scriptPubKeyHex: bytesToHex(p2pkhScriptPubKey(to.pubkeyHash)) },
        { valueUnits: changeAmount, scriptPubKeyHex: bytesToHex(p2pkhScriptPubKey(change.pubkeyHash)) },
      ],
      chainDomainHex,
    });

    expect(tx.txid).toBe(vectors.tx_signing.expected_txid);
    expect(tx.txHex).toBe(vectors.tx_signing.expected_tx_hex);
  });

  it('signs a different transaction for another chain', () => {
    const otherDomain = bytesToHex(
      consensusChainDomain(vectors.tx_signing.network_id_hex, '33'.repeat(32)),
    );
    const to = decodeAddress(vectors.tx_signing.to_address);
    const tx = createSignedP2PKHTransaction({
      prevTxidHex: vectors.tx_signing.prev_txid_hex,
      prevIndex: vectors.tx_signing.prev_index,
      prevOutput: { valueUnits: BigInt(vectors.tx_signing.prev_value_units), scriptPubKeyHex: vectors.script.script_pubkey_hex },
      privkeyHex: vectors.tx_signing.from_privkey_hex,
      pubkeyHex: vectors.tx_signing.from_pubkey_hex,
      outputs: [{ valueUnits: 1000n, scriptPubKeyHex: bytesToHex(p2pkhScriptPubKey(to.pubkeyHash)) }],
      chainDomainHex: otherDomain,
    });
    const same = createSignedP2PKHTransaction({
      prevTxidHex: vectors.tx_signing.prev_txid_hex,
      prevIndex: vectors.tx_signing.prev_index,
      prevOutput: { valueUnits: BigInt(vectors.tx_signing.prev_value_units), scriptPubKeyHex: vectors.script.script_pubkey_hex },
      privkeyHex: vectors.tx_signing.from_privkey_hex,
      pubkeyHex: vectors.tx_signing.from_pubkey_hex,
      outputs: [{ valueUnits: 1000n, scriptPubKeyHex: bytesToHex(p2pkhScriptPubKey(to.pubkeyHash)) }],
      chainDomainHex: vectors.tx_signing.chain_domain_hex,
    });
    // Only the input signature differs (the txid covers it too).
    expect(tx.txHex).not.toBe(same.txHex);
    expect(tx.txHex.length).toBe(same.txHex.length);
  });

  it('signs over the spent output, so a misreported coin value yields an invalid signature', () => {
    const to = decodeAddress(vectors.tx_signing.to_address);
    const sign = (valueUnits: bigint) =>
      createSignedP2PKHTransaction({
        prevTxidHex: vectors.tx_signing.prev_txid_hex,
        prevIndex: vectors.tx_signing.prev_index,
        prevOutput: { valueUnits, scriptPubKeyHex: vectors.script.script_pubkey_hex },
        privkeyHex: vectors.tx_signing.from_privkey_hex,
        pubkeyHex: vectors.tx_signing.from_pubkey_hex,
        outputs: [{ valueUnits: 1000n, scriptPubKeyHex: bytesToHex(p2pkhScriptPubKey(to.pubkeyHash)) }],
        chainDomainHex: vectors.tx_signing.chain_domain_hex,
      });
    expect(sign(BigInt(vectors.tx_signing.prev_value_units)).txHex).not.toBe(sign(2000n).txHex);
  });
});
