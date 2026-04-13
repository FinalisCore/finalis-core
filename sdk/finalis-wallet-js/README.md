# finalis-wallet-js

Reference TypeScript SDK for Finalis Wallet API v1.

Current restarted mainnet identity reference:

- `network_name = mainnet`
- `network_id = 258038c123a1c9b08475216e5f53a503`
- `genesis_hash = fd5570810b163e43a90ef5e8203e8aef34c89072f5f261c4de74aa724a615211`

Features:
- non-custodial key management (Ed25519 seed/private key)
- address derivation matching core (`sc` / `tsc`)
- P2PKH script + single-SHA256 scripthash helpers
- lightserver JSON-RPC client (`get_status`, `get_tip`, `get_headers`, `get_block`, `get_tx`, `get_utxos`, `get_committee`, `broadcast_tx`)
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
import { FinalisWallet, LightServerClient } from 'finalis-wallet-js';

const client = new LightServerClient(['http://127.0.0.1:19444'], {
  quorumMode: 'cross-check-tip',
  requiredTipMatches: 2,
});
const wallet = new FinalisWallet(client);

const keypair = FinalisWallet.generateKeypair();
const address = FinalisWallet.deriveAddress(keypair.pubkeyHex, 'tsc');

const balance = await wallet.getBalance(address);

const { txid } = await wallet.sendTransaction({
  fromPrivkeyHex: keypair.privkeyHex,
  toAddress: 'tsc1...',
  amountUnits: 1000n,
  feeUnits: 1000n,
  hrp: 'tsc',
});

await wallet.waitForFinality(txid);
```
