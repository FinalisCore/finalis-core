import { LightServerClient, scriptHashHexFromAddress } from '../src/index.js';

async function main() {
  const url = process.env.FINALIS_LIGHTSERVER_URL ?? 'http://127.0.0.1:19444';
  const address = process.env.FINALIS_WATCH_ADDRESS;
  if (!address) {
    throw new Error('set FINALIS_WATCH_ADDRESS');
  }

  const client = new LightServerClient(url, { timeoutMs: 5000 });
  const sh = scriptHashHexFromAddress(address);
  let lastKey = '';

  while (true) {
    const utxos = await client.getUtxosByScriptHash(sh);
    for (const u of utxos) {
      const key = `${u.txid}:${u.vout}:${u.value.toString()}`;
      if (key > lastKey) {
        console.log(`utxo txid=${u.txid} vout=${u.vout} value=${u.value.toString()} height=${u.height.toString()}`);
      }
      if (key > lastKey) lastKey = key;
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
