import { decodeAddress, deriveAddressFromPubkey } from '../address/index.js';
import { keypairFromPrivkeyHex, keypairFromSeed32 } from '../crypto/ed25519.js';
import { bytesToHex, hexToBytes } from '../crypto/hash.js';
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

  // Not available against the current lightserver: there is no header RPC that
  // binds a utxo_root to a finality certificate, and validators sign
  // vote_signing_message(height, round, transition_id), not a raw block hash.
  // Fails closed rather than returning an unverified balance.
  async getBalanceTrustless(_address: string): Promise<bigint> {
    throw new Error('TRUSTLESS_NOT_SUPPORTED');
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
