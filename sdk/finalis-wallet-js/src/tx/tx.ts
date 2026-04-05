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

export function txidHex(tx: Tx): string {
  return bytesToHex(sha256dBytes(serializeTx(tx)));
}

export function signingMessageForInput(tx: Tx, inputIndex: number): Uint8Array {
  if (inputIndex < 0 || inputIndex >= tx.inputs.length) throw new Error('input index out of range');
  const txCopy: Tx = {
    version: tx.version,
    lockTime: tx.lockTime,
    outputs: tx.outputs.map((o) => ({ ...o })),
    inputs: tx.inputs.map((i) => ({ ...i, scriptSigHex: '' })),
  };
  const txHash = sha256dBytes(serializeTx(txCopy));
  const msgPreimage = concatBytes(utf8Bytes('SC-SIG-V0'), new Uint8Array([
    inputIndex & 0xff,
    (inputIndex >>> 8) & 0xff,
    (inputIndex >>> 16) & 0xff,
    (inputIndex >>> 24) & 0xff,
  ]), txHash);
  return sha256dBytes(msgPreimage);
}

export function signInputP2PKH(tx: Tx, inputIndex: number, privkeyHex: string, pubkeyHex: string): void {
  const sig = signEd25519(signingMessageForInput(tx, inputIndex), privkeyHex);
  const pub = hexToBytes(pubkeyHex);
  if (pub.length !== 32) throw new Error('pubkey must be 32 bytes hex');
  const scriptSig = new Writer().u8(0x40).bytes(sig).u8(0x20).bytes(pub).finish();
  tx.inputs[inputIndex].scriptSigHex = bytesToHex(scriptSig);
}

export function createSignedP2PKHTransaction(args: {
  prevTxidHex: string;
  prevIndex: number;
  privkeyHex: string;
  pubkeyHex: string;
  outputs: TxOutput[];
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

  signInputP2PKH(tx, 0, args.privkeyHex, args.pubkeyHex);
  const bytes = serializeTx(tx);
  return { tx, txHex: bytesToHex(bytes), txid: bytesToHex(sha256dBytes(bytes)) };
}
