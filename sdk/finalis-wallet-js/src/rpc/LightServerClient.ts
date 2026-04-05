import type {
  BroadcastResult,
  HeaderEntry,
  RootPair,
  RpcUtxo,
  Status,
  Tip,
  TxLookup,
  UtxoProof,
  ValidatorProof,
} from '../types/index.js';

export interface ClientOptions {
  timeoutMs?: number;
  quorumMode?: 'off' | 'cross-check-tip';
  retries?: number;
  requiredTipMatches?: number;
}

class RpcError extends Error {
  constructor(public readonly code: number, message: string) {
    super(message);
    this.name = 'RpcError';
  }
}

export class LightServerClient {
  private readonly urls: string[];
  private readonly timeoutMs: number;
  private readonly quorumMode: 'off' | 'cross-check-tip';
  private readonly retries: number;
  private readonly requiredTipMatches: number;

  constructor(urls: string[] | string, options: ClientOptions = {}) {
    this.urls = Array.isArray(urls) ? urls : [urls];
    if (this.urls.length === 0) throw new Error('at least one url is required');
    this.timeoutMs = options.timeoutMs ?? 6000;
    this.quorumMode = options.quorumMode ?? 'off';
    this.retries = options.retries ?? 1;
    this.requiredTipMatches = options.requiredTipMatches ?? 2;
  }

  private async rpcCall<T>(url: string, method: string, params: Record<string, unknown>): Promise<T> {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const resp = await fetch(`${url.replace(/\/$/, '')}/rpc`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        signal: controller.signal,
      });
      if (!resp.ok) throw new Error(`http ${resp.status}`);
      const json = (await resp.json()) as { result?: T; error?: { code: number; message: string } };
      if (json.error) throw new RpcError(json.error.code, json.error.message);
      if (json.result === undefined) throw new Error('missing result');
      return json.result;
    } finally {
      clearTimeout(t);
    }
  }

  private async callWithRetry<T>(url: string, method: string, params: Record<string, unknown>): Promise<T> {
    let lastErr: unknown;
    for (let i = 0; i <= this.retries; i++) {
      try {
        return await this.rpcCall<T>(url, method, params);
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr;
  }

  private toTip(raw: { height: number; hash: string }): Tip {
    return { height: BigInt(raw.height), hash: raw.hash.toLowerCase() };
  }

  private toStatus(raw: {
    network_name: string;
    protocol_version: number;
    feature_flags: number;
    tip: { height: number; hash: string };
    peers: number | null;
    mempool_size: number | null;
    uptime_s: number;
    version: string;
  }): Status {
    return {
      network_name: raw.network_name,
      protocol_version: raw.protocol_version,
      feature_flags: BigInt(raw.feature_flags),
      tip: this.toTip(raw.tip),
      peers: raw.peers,
      mempool_size: raw.mempool_size,
      uptime_s: BigInt(raw.uptime_s),
      version: raw.version,
    };
  }

  async getTip(): Promise<Tip> {
    if (this.quorumMode === 'cross-check-tip' && this.urls.length >= this.requiredTipMatches) {
      const tips = await Promise.all(this.urls.map((u) => this.callWithRetry<{ height: number; hash: string }>(u, 'get_tip', {})));
      const counts = new Map<string, number>();
      for (const t of tips) {
        const key = `${t.height}:${t.hash.toLowerCase()}`;
        counts.set(key, (counts.get(key) ?? 0) + 1);
      }
      const best = [...counts.entries()].sort((a, b) => b[1] - a[1])[0];
      if (!best || best[1] < this.requiredTipMatches) {
        throw new Error('tip quorum mismatch across lightservers');
      }
      const [heightStr, hash] = best[0].split(':');
      return { height: BigInt(heightStr), hash };
    }
    return this.toTip(await this.callWithRetry(this.urls[0], 'get_tip', {}));
  }

  async getStatus(): Promise<Status> {
    if (this.quorumMode === 'cross-check-tip' && this.urls.length >= this.requiredTipMatches) {
      await this.getTip();
    }
    return this.toStatus(await this.callWithRetry(this.urls[0], 'get_status', {}));
  }

  async getHeaders(fromHeight: bigint, count: bigint): Promise<HeaderEntry[]> {
    const raw = await this.callWithRetry<Array<{
      height: number;
      header_hex: string;
      block_hash: string;
      utxo_root?: string;
      validators_root?: string;
      finality_proof: Array<{ pubkey_hex: string; sig_hex: string }>;
    }>>(this.urls[0], 'get_headers', {
      from_height: Number(fromHeight),
      count: Number(count),
    });
    return raw.map((r) => ({
      height: BigInt(r.height),
      header_hex: r.header_hex.toLowerCase(),
      block_hash: r.block_hash.toLowerCase(),
      utxo_root: r.utxo_root?.toLowerCase(),
      validators_root: r.validators_root?.toLowerCase(),
      finality_proof: r.finality_proof.map((f) => ({ pubkey_hex: f.pubkey_hex.toLowerCase(), sig_hex: f.sig_hex.toLowerCase() })),
    }));
  }

  async getHeaderRange(startHeight: bigint, endHeight: bigint): Promise<HeaderEntry[]> {
    const raw = await this.callWithRetry<Array<{
      height: number;
      header_hex: string;
      block_hash: string;
      utxo_root?: string;
      validators_root?: string;
      finality_proof: Array<{ pubkey_hex: string; sig_hex: string }>;
    }>>(this.urls[0], 'get_header_range', {
      start_height: Number(startHeight),
      end_height: Number(endHeight),
    });
    return raw.map((r) => ({
      height: BigInt(r.height),
      header_hex: r.header_hex.toLowerCase(),
      block_hash: r.block_hash.toLowerCase(),
      utxo_root: r.utxo_root?.toLowerCase(),
      validators_root: r.validators_root?.toLowerCase(),
      finality_proof: r.finality_proof.map((f) => ({ pubkey_hex: f.pubkey_hex.toLowerCase(), sig_hex: f.sig_hex.toLowerCase() })),
    }));
  }

  async getBlock(hash: string): Promise<{ block_hex: string }> {
    return this.callWithRetry(this.urls[0], 'get_block', { hash: hash.toLowerCase() });
  }

  async getTx(txid: string): Promise<TxLookup | null> {
    try {
      const raw = await this.callWithRetry<{ height: number; tx_hex: string }>(this.urls[0], 'get_tx', {
        txid: txid.toLowerCase(),
      });
      return { height: BigInt(raw.height), tx_hex: raw.tx_hex.toLowerCase() };
    } catch (err) {
      if (err instanceof RpcError && err.code === -32001) return null;
      throw err;
    }
  }

  async getUtxosByScriptHash(scripthashHex: string): Promise<RpcUtxo[]> {
    const raw = await this.callWithRetry<Array<{
      txid: string;
      vout: number;
      value: number;
      height: number;
      script_pubkey_hex: string;
    }>>(this.urls[0], 'get_utxos', {
      scripthash_hex: scripthashHex.toLowerCase(),
    });
    return raw.map((u) => ({
      txid: u.txid.toLowerCase(),
      vout: u.vout,
      value: BigInt(u.value),
      height: BigInt(u.height),
      script_pubkey_hex: u.script_pubkey_hex.toLowerCase(),
    }));
  }

  async getCommittee(height: bigint): Promise<string[]> {
    const raw = await this.callWithRetry<string[]>(this.urls[0], 'get_committee', { height: Number(height) });
    return raw.map((p) => p.toLowerCase());
  }

  async getRoots(height: bigint): Promise<RootPair> {
    const raw = await this.callWithRetry<{ height: number; utxo_root: string; validators_root: string }>(
      this.urls[0],
      'get_roots',
      { height: Number(height) },
    );
    return {
      height: BigInt(raw.height),
      utxo_root: raw.utxo_root.toLowerCase(),
      validators_root: raw.validators_root.toLowerCase(),
    };
  }

  async getUtxoProof(txid: string, vout: number, height?: bigint): Promise<UtxoProof> {
    const params: Record<string, unknown> = { txid: txid.toLowerCase(), vout };
    if (height !== undefined) params.height = Number(height);
    const raw = await this.callWithRetry<{
      proof_format?: string;
      height: number;
      key_hex: string;
      root_hex?: string;
      utxo_root: string;
      value_hex: string | null;
      siblings_hex?: string[];
      siblings: string[];
    }>(this.urls[0], 'get_utxo_proof', params);
    const siblings = (raw.siblings_hex ?? raw.siblings).map((s) => s.toLowerCase());
    return {
      proof_format: 'smt_v0',
      height: BigInt(raw.height),
      key_hex: raw.key_hex.toLowerCase(),
      root_hex: (raw.root_hex ?? raw.utxo_root).toLowerCase(),
      utxo_root: raw.utxo_root.toLowerCase(),
      value_hex: raw.value_hex ? raw.value_hex.toLowerCase() : null,
      siblings_hex: siblings,
      siblings,
    };
  }

  async getValidatorProof(pubkeyHex: string, height?: bigint): Promise<ValidatorProof> {
    const params: Record<string, unknown> = { pubkey_hex: pubkeyHex.toLowerCase() };
    if (height !== undefined) params.height = Number(height);
    const raw = await this.callWithRetry<{
      proof_format?: string;
      height: number;
      key_hex: string;
      root_hex?: string;
      validators_root: string;
      value_hex: string | null;
      siblings_hex?: string[];
      siblings: string[];
    }>(this.urls[0], 'get_validator_proof', params);
    const siblings = (raw.siblings_hex ?? raw.siblings).map((s) => s.toLowerCase());
    return {
      proof_format: 'smt_v0',
      height: BigInt(raw.height),
      key_hex: raw.key_hex.toLowerCase(),
      root_hex: (raw.root_hex ?? raw.validators_root).toLowerCase(),
      validators_root: raw.validators_root.toLowerCase(),
      value_hex: raw.value_hex ? raw.value_hex.toLowerCase() : null,
      siblings_hex: siblings,
      siblings,
    };
  }

  async broadcastTx(txHex: string): Promise<BroadcastResult> {
    const r = await this.callWithRetry<BroadcastResult>(this.urls[0], 'broadcast_tx', { tx_hex: txHex.toLowerCase() });
    return {
      accepted: r.accepted,
      txid: r.txid?.toLowerCase(),
      error: r.error,
    };
  }
}
