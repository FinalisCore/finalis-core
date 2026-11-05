# What is Finalis?

Finalis is a blockchain I am building in the open. Its coin is FLS. It has three ideas:

1. **When a payment is confirmed, it is final.** There are no reorganizations and no waiting for
   "6 confirmations".
2. **Amounts can be private.** Confidential payments hide how much was sent, and that has been part of
   the base layer since the first block.
3. **Your wallet checks the chain itself.** It doesn't have to trust the server it talks to.

It is **not launched yet.** A public test network (testnet-3) has been running since
29 October 2026 on the same rules mainnet will use. Its coins have no value.

## The problem

Most blockchains make you choose between speed, certainty and privacy:

- **Certainty:** on many chains a confirmed payment can still be undone if the chain reorganizes, so
  exchanges and shops wait for several blocks before they trust it.
- **Privacy:** on most chains every amount and every balance is public forever. Privacy is usually an
  optional add-on that few people use.
- **Trust:** most wallets show you whatever a server tells them. If the server lies or is hacked,
  the wallet can't tell.

## How Finalis answers it

**Final means final.** A group of validators (the committee) votes on each block. Once more than
two-thirds of them sign it, the block is final and nothing can replace it. The rules behind this are
written as a formal model (TLA+) and checked by machine on every change.

**Private by default where it matters.** Confidential payments hide the amount with cryptographic
commitments, the same family of techniques used by Monero and Liquid. Each payment goes to a
fresh one-time address. The network can still verify that no coins were created from nothing.

**A wallet that checks, not trusts.** The wallet ships with the chain's starting point built in. It
follows each change of validator committee and checks its balance against the validators'
signatures. A server can't invent coins for you, and one honest server is enough to expose a
hidden one.

**Payments that wait.** Besides normal sends, Finalis supports:
- payments that only open at a chosen future block,
- an inheritance lock (you can spend any time; your heir can spend after a chosen block),
- sealed messages that stay encrypted until a chosen block.

## Fair launch, no insiders

- **No premine, no token sale, no ICO, no presale, no airdrop.** FLS exist only as rewards for
  validators who produce blocks.
- **Fixed supply:** 7,000,000 FLS maximum, released over 12 years, then validators are paid from fees.
- **Anyone can become a validator** by locking ("bonding") FLS on chain. Nobody gets a slot by being
  chosen. At launch, a faucet pays the bond for the first 128 validators, in public queue order.
- **Built to outlive its founder.** Mainnet starts with one validator (mine). Once one other validator is
  active, I can no longer finalize blocks alone. From 4 independent validators it keeps running without me, and I
  can switch mine off for good. Details: [GOVERNANCE.md](../GOVERNANCE.md).

There is no company, no foundation and nobody is paid. The code is MIT-licensed.

## Where it is today

| | |
|---|---|
| Test network | live since 29 Oct 2026, with independent validators joining |
| Releases | regular tagged releases for Linux, Windows and Docker |
| Testing | about 900 automated tests, continuous fuzzing, nightly crash and attack simulations |
| Mainnet | not launched; no date yet |

Watch it live on the [explorer](https://finalis.self-link.com).

## How to take part

- **Run a node or a validator** on the test network. It's free; the faucet provides the bond.
  [testnet/JOIN.md](../testnet/JOIN.md)
- **Try the wallet** and report anything confusing or broken on
  [GitHub](https://github.com/FinalisCore/finalis-core/issues).
- **Try to break it.** [REVIEWING.md](REVIEWING.md) lists the exact claims I want tested.
- **Explain it.** Plain-language write-ups like this one are welcome. Share them in Discord.

## Official channels

Finalis is only these:

- **Website:** https://www.finaliscore.org
- **Code and releases:** https://github.com/FinalisCore/finalis-core
- **Chat:** Discord, https://discord.gg/8rKfKc7QR9
- **Explorer:** https://finalis.self-link.com
- **X:** https://x.com/finalis_core

**There is no official Telegram, token sale, presale, airdrop, whitelist or "team wallet".** Nobody can
sell you FLS before mainnet, and nobody from Finalis will ask you to send coins, keys or a seed
phrase. If someone does, it's a scam. Please report it in Discord.

Anyone may write about Finalis or run their own community. Community-run groups are unofficial and
don't speak for the project.
