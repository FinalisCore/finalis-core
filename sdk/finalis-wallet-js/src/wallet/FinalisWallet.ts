import { decodeAddress, deriveAddressFromPubkey } from '../address/index.js';
import { keypairFromPrivkeyHex, keypairFromSeed32 } from '../crypto/ed25519.js';
import { bytesToHex, hexToBytes } from '../crypto/hash.js';
import { verifyFinalityProof } from '../proofs/finality.js';
import { verifySmtProof } from '../proofs/smt.js';
import { LightServerClient } from '../rpc/LightServerClient.js';
import { p2pkhScriptPubKeyHexFromAddress, scriptHashHex, scriptHashHexFromAddress } from '../script/index.js';
import { signInputP2PKH, type Tx, txidHex, serializeTx } from '../tx/tx.js';
import type {
  BuildTxParams,
  BuildTxResult,
  Keypair,
  WaitForFinalityOptions,
  WalletUtxo,
} from '../types/index.js';
import { selectCoins } from './coinSelection.js';

export class FinalisWallet {
  constructor(public readonly client: LightServerClient) {}

  static generateKeypair(): Keypair {
    const cryptoApi = globalThis.crypto;
    if (!cryptoApi || typeof cryptoApi.getRandomValues !== 'function') {
      throw new Error('secure random source unavailable (crypto.getRandomValues required)');
    }
    const seed = new Uint8Array(32);
    cryptoApi.getRandomValues(seed);
    return keypairFromSeed32(seed);
  }

  static importPrivkeyHex(privkeyHex: string): Keypair {
    return keypairFromPrivkeyHex(privkeyHex);
  }

  static deriveAddress(pubkeyHex: string, hrp: 'sc' | 'tsc'): string {
    return deriveAddressFromPubkey(pubkeyHex, hrp);
  }

  static addressToScriptPubKey(address: string): Uint8Array {
    return hexToBytes(p2pkhScriptPubKeyHexFromAddress(address));
  }

  computeScriptHashFromAddress(address: string): string {
    return scriptHashHexFromAddress(address);
  }

  async listUtxos(address: string): Promise<WalletUtxo[]> {
    const sh = scriptHashHexFromAddress(address);
    const scriptHex = p2pkhScriptPubKeyHexFromAddress(address);
    const utxos = await this.client.getUtxosByScriptHash(sh);
    return utxos
      .filter((u) => u.script_pubkey_hex === scriptHex)
      .map((u) => ({
        txid: u.txid,
        vout: u.vout,
        valueUnits: u.value,
        height: u.height,
        scriptPubKeyHex: u.script_pubkey_hex,
      }));
  }

  async getBalance(address: string): Promise<bigint> {
    const utxos = await this.listUtxos(address);
    return utxos.reduce((sum, u) => sum + u.valueUnits, 0n);
  }

  async getBalanceTrustless(address: string): Promise<bigint> {
    const utxos = await this.listUtxos(address);
    if (utxos.length === 0) return 0n;
    const tip = await this.client.getTip();
    const headers = await this.client.getHeaderRange(tip.height, tip.height);
    if (headers.length !== 1) throw new Error('FINALITY_PROOF_INVALID');
    const head = headers[0];
    if (!head.utxo_root) throw new Error('TRUSTLESS_NOT_SUPPORTED');
    if (head.block_hash !== tip.hash) throw new Error('FINALITY_PROOF_INVALID');
    const committee = await this.client.getCommittee(tip.height);
    if (!verifyFinalityProof(head.block_hash, head.finality_proof, committee)) {
      throw new Error('FINALITY_PROOF_INVALID');
    }

    let sum = 0n;
    for (const u of utxos) {
      const p = await this.client.getUtxoProof(u.txid, u.vout, tip.height);
      if (p.utxo_root !== head.utxo_root) {
        throw new Error('SMT_PROOF_INVALID');
      }
      if (!verifySmtProof(head.utxo_root, p.key_hex, p.value_hex, p.siblings)) {
        throw new Error('SMT_PROOF_INVALID');
      }
      sum += u.valueUnits;
    }
    return sum;
  }

  async buildTransaction(params: BuildTxParams): Promise<BuildTxResult> {
    if (params.amountUnits <= 0n) throw new Error('amountUnits must be positive');
    if (params.feeUnits < 0n) throw new Error('feeUnits must be >= 0');

    const kp = keypairFromPrivkeyHex(params.fromPrivkeyHex);
    const to = decodeAddress(params.toAddress);
    const hrp = (params.hrp ?? to.hrp) as 'sc' | 'tsc';

    const fromAddress = deriveAddressFromPubkey(kp.pubkeyHex, hrp);
    const target = params.amountUnits + params.feeUnits;

    const all = await this.listUtxos(fromAddress);
    const selected = selectCoins(all, target);
    const inSum = selected.reduce((sum, u) => sum + u.valueUnits, 0n);
    const change = inSum - target;

    const tx: Tx = {
      version: 1,
      lockTime: 0,
      inputs: selected.map((u) => ({
        prevTxidHex: u.txid,
        prevIndex: u.vout,
        scriptSigHex: '',
        sequence: 0xffffffff,
      })),
      outputs: [
        {
          valueUnits: params.amountUnits,
          scriptPubKeyHex: p2pkhScriptPubKeyHexFromAddress(params.toAddress),
        },
      ],
    };

    const dust = params.dustThresholdUnits ?? 546n;
    if (change > dust) {
      const chAddr = params.changeAddress ?? fromAddress;
      tx.outputs.push({ valueUnits: change, scriptPubKeyHex: p2pkhScriptPubKeyHexFromAddress(chAddr) });
    }

    for (let i = 0; i < tx.inputs.length; i++) {
      signInputP2PKH(tx, i, kp.privkeyHex, kp.pubkeyHex);
    }

    const txHex = bytesToHex(serializeTx(tx));
    return {
      txHex,
      txid: txidHex(tx),
      inputs: selected,
      outputs: tx.outputs,
      changeUnits: change > dust ? change : 0n,
    };
  }

  async sendTransaction(params: BuildTxParams): Promise<{ txid: string; txHex: string }> {
    const built = await this.buildTransaction(params);
    const b = await this.client.broadcastTx(built.txHex);
    if (!b.accepted) throw new Error(b.error ?? 'broadcast rejected');
    return { txid: b.txid ?? built.txid, txHex: built.txHex };
  }

  async waitForFinality(txid: string, options: WaitForFinalityOptions = {}): Promise<{ height: bigint; txHex: string }> {
    const timeoutMs = options.timeoutMs ?? 180000;
    const pollMs = options.pollIntervalMs ?? 2000;
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      const tx = await this.client.getTx(txid);
      if (tx) return { height: tx.height, txHex: tx.tx_hex };
      await new Promise((r) => setTimeout(r, pollMs));
    }
    throw new Error('waitForFinality timeout');
  }
}

export function computeScriptHashFromAddress(address: string): string {
  return scriptHashHex(p2pkhScriptPubKeyHexFromAddress(address));
}
