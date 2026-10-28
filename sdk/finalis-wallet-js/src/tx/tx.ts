import { signEd25519 } from '../crypto/ed25519.js';
import { bytesToHex, concatBytes, hexToBytes, sha256dBytes, utf8Bytes } from '../crypto/hash.js';
import { Writer } from './codec.js';

export interface TxInput {
  prevTxidHex: string;
  prevIndex: number;
  scriptSigHex: string;
  sequence?: number;
}

export interface TxOutput {
  valueUnits: bigint;
  scriptPubKeyHex: string;
}

export interface Tx {
  version: number;
  inputs: TxInput[];
  outputs: TxOutput[];
  lockTime: number;
}

function normalizeHex32(hex: string, field: string): string {
  const b = hexToBytes(hex);
  if (b.length !== 32) throw new Error(`${field} must be 32 bytes hex`);
  return bytesToHex(b);
}

export function serializeTx(tx: Tx): Uint8Array {
  const w = new Writer();
  w.u32le(tx.version);
  w.varint(BigInt(tx.inputs.length));
  for (const input of tx.inputs) {
    w.bytes(hexToBytes(normalizeHex32(input.prevTxidHex, 'prevTxidHex')));
    w.u32le(input.prevIndex >>> 0);
    w.varbytes(hexToBytes(input.scriptSigHex));
    w.u32le((input.sequence ?? 0xffffffff) >>> 0);
  }
  w.varint(BigInt(tx.outputs.length));
  for (const output of tx.outputs) {
    w.u64le(output.valueUnits);
    w.varbytes(hexToBytes(output.scriptPubKeyHex));
  }
  w.u32le(tx.lockTime >>> 0);
  return w.finish();
}

export const DEFAULT_FEE_UNITS = 1_000n;

// The least fee a transaction of `sizeBytes` pays under the chain's base fee: per started KiB.
// Must match consensus::required_base_fee_units in src/consensus/monetary.cpp.
export function requiredBaseFeeUnits(baseFeePerKib: bigint, sizeBytes: number): bigint {
  return baseFeePerKib * BigInt(Math.ceil(sizeBytes / 1024));
}

export function txidHex(tx: Tx): string {
  return bytesToHex(sha256dBytes(serializeTx(tx)));
}

// sha256d("SC-SPENT-V1" || varint(n) || per spent output: u64le(value) || varbytes(script_pubkey)).
export function spentOutputsHash(spent: TxOutput[]): Uint8Array {
  const w = new Writer().bytes(utf8Bytes('SC-SPENT-V1')).varint(BigInt(spent.length));
  for (const out of spent) w.u64le(out.valueUnits).varbytes(hexToBytes(out.scriptPubKeyHex));
  return sha256dBytes(w.finish());
}

// sha256d("SC-SIG-V4" || chain_domain || u32le(input_index) || sha256d(tx without script_sigs) ||
// spentOutputsHash(spent)). The chain domain (consensusChainDomain(network_id, genesis_hash)) makes a
// transaction signed for one network invalid on every other one. `spent` is the output each input
// spends, in input order: a signer told a wrong value or script for any of them signs an invalid
// transaction instead of overpaying the fee unknowingly. Must match signing_message_for_input in
// src/utxo/validate.cpp.
export function signingMessageForInput(tx: Tx, inputIndex: number, chainDomainHex: string, spent: TxOutput[]): Uint8Array {
  if (inputIndex < 0 || inputIndex >= tx.inputs.length) throw new Error('input index out of range');
  if (spent.length !== tx.inputs.length) throw new Error('spent outputs must match the inputs');
  const chainDomain = hexToBytes(chainDomainHex);
  if (chainDomain.length !== 32) throw new Error('chain domain must be 32 bytes hex');
  const txCopy: Tx = {
    version: tx.version,
    lockTime: tx.lockTime,
    outputs: tx.outputs.map((o) => ({ ...o })),
    inputs: tx.inputs.map((i) => ({ ...i, scriptSigHex: '' })),
  };
  const txHash = sha256dBytes(serializeTx(txCopy));
  const msgPreimage = concatBytes(utf8Bytes('SC-SIG-V4'), chainDomain, new Uint8Array([
    inputIndex & 0xff,
    (inputIndex >>> 8) & 0xff,
    (inputIndex >>> 16) & 0xff,
    (inputIndex >>> 24) & 0xff,
  ]), txHash, spentOutputsHash(spent));
  return sha256dBytes(msgPreimage);
}

export function signInputP2PKH(
  tx: Tx,
  inputIndex: number,
  privkeyHex: string,
  pubkeyHex: string,
  chainDomainHex: string,
  spent: TxOutput[],
): void {
  const sig = signEd25519(signingMessageForInput(tx, inputIndex, chainDomainHex, spent), privkeyHex);
  const pub = hexToBytes(pubkeyHex);
  if (pub.length !== 32) throw new Error('pubkey must be 32 bytes hex');
  const scriptSig = new Writer().u8(0x40).bytes(sig).u8(0x20).bytes(pub).finish();
  tx.inputs[inputIndex].scriptSigHex = bytesToHex(scriptSig);
}

export function createSignedP2PKHTransaction(args: {
  prevTxidHex: string;
  prevIndex: number;
  // The output being spent, as the chain holds it (value and script); the signature covers it.
  prevOutput: TxOutput;
  privkeyHex: string;
  pubkeyHex: string;
  outputs: TxOutput[];
  chainDomainHex: string;
}): { tx: Tx; txHex: string; txid: string } {
  const tx: Tx = {
    version: 1,
    lockTime: 0,
    inputs: [
      {
        prevTxidHex: normalizeHex32(args.prevTxidHex, 'prevTxidHex'),
        prevIndex: args.prevIndex,
        scriptSigHex: '',
        sequence: 0xffffffff,
      },
    ],
    outputs: args.outputs,
  };

  signInputP2PKH(tx, 0, args.privkeyHex, args.pubkeyHex, args.chainDomainHex, [args.prevOutput]);
  const bytes = serializeTx(tx);
  return { tx, txHex: bytesToHex(bytes), txid: bytesToHex(sha256dBytes(bytes)) };
}
