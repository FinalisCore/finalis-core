export type Hex = string;

export interface RpcErrorShape {
  code: number;
  message: string;
}

export interface Tip {
  height: bigint;
  hash: Hex;
}

export interface Status {
  network_name: string;
  protocol_version: number;
  feature_flags: bigint;
  tip: Tip;
  peers: number | null;
  mempool_size: number | null;
  uptime_s: bigint;
  version: string;
}

export interface FinalitySig {
  pubkey_hex: Hex;
  sig_hex: Hex;
}

export interface HeaderEntry {
  height: bigint;
  header_hex: Hex;
  block_hash: Hex;
  utxo_root?: Hex;
  validators_root?: Hex;
  finality_proof: FinalitySig[];
}

export interface RootPair {
  height: bigint;
  utxo_root: Hex;
  validators_root: Hex;
}

export interface UtxoProof {
  proof_format: 'smt_v0';
  height: bigint;
  key_hex: Hex;
  root_hex: Hex;
  utxo_root: Hex;
  value_hex: Hex | null;
  siblings_hex: Hex[];
  siblings: Hex[];
}

export interface ValidatorProof {
  proof_format: 'smt_v0';
  height: bigint;
  key_hex: Hex;
  root_hex: Hex;
  validators_root: Hex;
  value_hex: Hex | null;
  siblings_hex: Hex[];
  siblings: Hex[];
}

export interface TxLookup {
  height: bigint;
  tx_hex: Hex;
}

export interface RpcUtxo {
  txid: Hex;
  vout: number;
  value: bigint;
  height: bigint;
  script_pubkey_hex: Hex;
}

export interface BroadcastResult {
  accepted: boolean;
  txid?: Hex;
  error?: string;
}

export interface Keypair {
  privkeyHex: Hex;
  pubkeyHex: Hex;
}

export interface WalletUtxo {
  txid: Hex;
  vout: number;
  valueUnits: bigint;
  height: bigint;
  scriptPubKeyHex: Hex;
}

export interface BuildTxParams {
  fromPrivkeyHex: Hex;
  toAddress: string;
  amountUnits: bigint;
  feeUnits: bigint;
  changeAddress?: string;
  hrp?: 'sc' | 'tsc';
  dustThresholdUnits?: bigint;
}

export interface BuildTxResult {
  txHex: Hex;
  txid: Hex;
  inputs: WalletUtxo[];
  outputs: Array<{ valueUnits: bigint; scriptPubKeyHex: Hex }>;
  changeUnits: bigint;
}

export interface WaitForFinalityOptions {
  timeoutMs?: number;
  pollIntervalMs?: number;
}
