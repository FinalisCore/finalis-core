import { FinalisWallet, LightServerClient } from '../src/index.js';

async function main() {
  const url = process.env.FINALIS_LIGHTSERVER_URL ?? 'http://127.0.0.1:19444';
  const client = new LightServerClient([url], { quorumMode: 'off', timeoutMs: 5000 });
  const wallet = new FinalisWallet(client);

  const keypair = FinalisWallet.generateKeypair();
  const address = FinalisWallet.deriveAddress(keypair.pubkeyHex, 'tsc');
  console.log('generated address:', address);

  const balance = await wallet.getBalance(address);
  console.log('balance units:', balance.toString());

  const toAddress = process.env.FINALIS_TO_ADDRESS;
  if (!toAddress) {
    console.log('set FINALIS_TO_ADDRESS to send a tx');
    return;
  }

  const sent = await wallet.sendTransaction({
    fromPrivkeyHex: keypair.privkeyHex,
    toAddress,
    amountUnits: BigInt(process.env.FINALIS_AMOUNT_UNITS ?? '1000'),
    feeUnits: BigInt(process.env.FINALIS_FEE_UNITS ?? '1000'),
    hrp: 'tsc',
  });
  console.log('broadcast txid:', sent.txid);

  const finalized = await wallet.waitForFinality(sent.txid, { timeoutMs: 120000, pollIntervalMs: 2000 });
  console.log('finalized at height:', finalized.height.toString());
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
