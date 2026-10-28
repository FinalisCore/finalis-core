# finalis-wallet-js

Reference TypeScript SDK for Finalis Wallet API v1.

Current mainnet identity reference:

- `network_name = mainnet`
- `network_id = fe561911730912cced1e83bc273fab13`
- `genesis_hash`: published at launch (mainnet has not launched)

Features:
- non-custodial key management (Ed25519 seed/private key)
- address derivation matching core (`sc` / `tsc`)
- P2PKH script + single-SHA256 scripthash helpers
- lightserver JSON-RPC client (`get_status`, `get_tip`, `get_tx`, `get_tx_status`, `get_utxos`, `get_committee`, `get_roots`, `get_utxo_proof`, `get_validator_proof`, `broadcast_tx`)
- `getBalanceTrustless` currently fails closed with `TRUSTLESS_NOT_SUPPORTED` (no finality-bound `utxo_root` RPC yet)
- deterministic UTXO discovery, balance, coin selection, tx build/sign/broadcast/finality wait
- optional multi-server tip quorum cross-check mode

Current scope note:

- this SDK is oriented around the transparent address / UTXO flow
- it is not the authoritative wallet surface for local confidential account,
  request-URI, or imported confidential-coin UX
- callers should always confirm `network_id` and `genesis_hash` from
  `get_status` before using a server as current mainnet

## Install

```bash
cd sdk/finalis-wallet-js
npm install
```

## Build

```bash
npm run build
```

## Unit tests

```bash
npm test
```

## Integration test (requires running lightserver)

```bash
FINALIS_SDK_IT=1 \
FINALIS_LIGHTSERVER_URL=http://127.0.0.1:19444 \
FINALIS_FUNDING_PRIVKEY=<hex32> \
FINALIS_IT_DEST_ADDRESS=<tsc1...> \
npm run test:integration
```

## Usage

```ts
import { FinalisWallet, LightServerClient, bytesToHex, consensusChainDomain } from 'finalis-wallet-js';

const client = new LightServerClient(['http://127.0.0.1:19444'], {
  quorumMode: 'cross-check-tip',
  requiredTipMatches: 2,
});
const wallet = new FinalisWallet(client);

const keypair = FinalisWallet.generateKeypair();
const address = FinalisWallet.deriveAddress(keypair.pubkeyHex, 'tsc');

const balance = await wallet.getBalance(address);

// Transactions are signed for one chain. Pin the network id and genesis hash you expect (the
// testnet's are in testnet/README.md); do not take them from the server you send to.
const chainDomainHex = bytesToHex(consensusChainDomain(NETWORK_ID_HEX, GENESIS_HASH_HEX));

// Resolves with status 'submitted_not_final': a node's mempool accepted it, nothing is paid yet.
const { txid } = await wallet.sendTransaction({
  fromPrivkeyHex: keypair.privkeyHex,
  toAddress: 'tsc1...',
  amountUnits: 1000n,
  // feeUnits omitted: the SDK pays the default fee, or what the chain's base fee asks if more
  // (getStatus().base_fee_per_kib, units per started KiB). An explicit feeUnits below it is refused.
  hrp: 'tsc',
  chainDomainHex,
});

// Paid only once this resolves. Throws if the transaction was rejected at finality.
await wallet.waitForFinality(txid);

// Or poll: finalized | certified_ingress (submitted, not final) | rejected | not_found
const status = await client.getTxStatus(txid);
```
