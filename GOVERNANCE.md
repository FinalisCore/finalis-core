# Governance

This file says who decides what today, and how that changes as more people take part. It describes
the current state honestly rather than the state we want.

## Today: one maintainer

Finalis Core has one maintainer, who merges pull requests, cuts releases and runs the launch
process. There is no company, foundation, token sale or premine, and nobody is paid.

One maintainer is a single point of failure, and it means "community-owned" is a goal, not yet a
fact. The rest of this file is how we get from one to many.

## What the maintainer does not control

These hold now and are not up to the maintainer:

- The rules are the code and the specs in `docs/spec/`. Anyone can fork under the MIT license.
- Genesis validators are chosen by the public, verifiable ceremony in
  [mainnet/GENESIS_VALIDATOR_CEREMONY.md](mainnet/GENESIS_VALIDATOR_CEREMONY.md). The maintainer
  holds at most `f` of the genesis keys, so the other validators can finalize without them.
- After launch, consensus rules change only when validators run a release that changes them. No
  key, flag or server lets the maintainer change a live network.
- Launch waits for the published checklist
  ([mainnet/THREAT_MODEL_AND_LAUNCH_CHECKLIST.md](mainnet/THREAT_MODEL_AND_LAUNCH_CHECKLIST.md)),
  including an external review of the consensus protocol.

## How decisions are made

- Pull requests: any contributor can propose; the maintainer reviews and merges. Consensus,
  cryptography and economics changes need a spec update and tests, and are open for comment for at
  least 7 days before merge.
- Larger changes (protocol, economics, launch): proposed in a GitHub Discussion first, with the
  reasoning written down. Decisions and their reasons stay public.
- Security reports: private, per [SECURITY.md](SECURITY.md).

## From one maintainer to several

- A contributor who has landed several non-trivial pull requests and reviewed others' can be
  invited as a maintainer with merge rights.
- With two or more maintainers, changes to consensus, cryptography or economics need approval from
  a maintainer other than the author.
- With three or more, releases are tagged only after two maintainers reproduce the build.
- Maintainers who stop participating for 6 months step back to contributor, and can return.

## If the maintainer disappears

The code, specs, TLA+ model, chaos harness and this repository's history are public under MIT.
Anyone may continue the project in a fork; a fork that the validators run is the project.
