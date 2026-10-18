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

// accepted=true means a node's mempool took the transaction: submitted, not final. Only a
// finalized status (getTxStatus / waitForFinality) means paid.
export interface BroadcastResult {
  accepted: boolean;
  finalized: false;
  txid?: Hex;
  status?: string;
  error?: string;
  errorCode?: string;
  retryable?: boolean;
}

// get_tx_status: finalized (paid), certified_ingress (submitted, not final), rejected (final, moved
// no funds), not_found (unknown to the node; a just-submitted tx may still be pending).
export type TxStatusName = 'finalized' | 'certified_ingress' | 'rejected' | 'not_found';

export interface TxStatus {
  txid: Hex;
  status: TxStatusName;
  finalized: boolean;
  creditSafe: boolean;
  height?: bigint;
  rejectedHeight?: bigint;
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
  // Chain the transaction is signed for: bytesToHex(consensusChainDomain(networkIdHex, genesisHashHex)).
  // Pin the network's values; a transaction signed for another chain is rejected.
  chainDomainHex: Hex;
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
