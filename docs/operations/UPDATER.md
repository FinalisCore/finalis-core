# Release signing and `finalis-updater`

Design: [SIGNALED_ACTIVATION §9](../spec/SIGNALED_ACTIVATION.md#9-installing-releases-updater-and-release-signing).
Code: `src/common/release_manifest.{hpp,cpp}`, `apps/finalis-updater/`, `finalis-cli release-*`.

The chain decides **when** rules switch (signaled activation). This decides **which code** a node
accepts: a release is trusted only when enough of the keys in the operator's trust policy signed it.
Nothing here is consensus. Today the policy is one key, the maintainer's (1-of-1). When more
maintainers join, they add their keys and the threshold goes up by agreement. That changes only the
policy file, never the manifest format.

## Files

| File | Who writes it | Content |
|---|---|---|
| `manifest.txt` | release maintainer | version, network, rules fingerprint, upgrade ids, sha256 of each artifact (canonical text, format in `release_manifest.hpp`) |
| `manifest.sig` | each signer appends a line | `sig <pubkey> <signature>` per signer |
| `/etc/finalis/release-trust.txt` | node operator | `threshold <n>` and one `key <pubkey> [label]` line per trusted maintainer |

A signature covers a domain tag and the exact manifest text. The manifest has a single canonical
spelling, so a signature cannot be reused for a manifest that reads differently.

## Maintainer: sign a release

Keep the release key offline: an encrypted keystore on a machine that does not hold node keys and is
not a CI runner.

```bash
# once
finalis-cli release-keygen --out ~/finalis-release-key.json --pass-prompt
# prints release_pubkey=<hex>; publish it (README, website, Discord) so operators can pin it

# per release, from the built artifacts
finalis-cli release-manifest --version 2.3.0 --network mainnet \
  --out manifest.txt finalis-node finalis-cli finalis-lightserver
finalis-cli release-sign --manifest manifest.txt --key ~/finalis-release-key.json --pass-prompt
# publish manifest.txt and manifest.sig next to the artifacts
```

Pass `--upgrade-id <hex>` (repeatable) for the signaled-activation upgrades the release implements, and
`--rules-fingerprint` when the release changes the consensus rules fingerprint.

Co-signers (later): each runs `release-sign` on the same `manifest.txt`. Lines are appended to
`manifest.sig`, and running it again with the same key replaces that key's line.

## Operator: trust policy and checks

```text
# /etc/finalis/release-trust.txt
threshold 1
key <maintainer release pubkey> founder
```

```bash
# verify downloaded files before installing them by hand
finalis-updater verify --manifest manifest.txt --sigs manifest.sig --artifacts-dir .
# notify mode: is there a newer trusted release? (fetches <url>/manifest.txt and <url>/manifest.sig)
finalis-updater check --url https://<release-host>/finalis/latest --network mainnet
```

`verify` exits 0 only if the policy threshold is met and, with `--artifacts-dir`, every artifact
matches its hash. `check` prints `status=update-available|up-to-date|untrusted|fetch-failed|other-network`.
It only reports: nothing is installed. It fetches over `https://` only and does not follow redirects,
so point `--url` at a host that serves the files directly.

Raising the threshold (for example 2-of-3) means editing the policy on every node. A release signed by
fewer keys is then reported `untrusted`.

## Not yet

- Install mode (versioned directory, symlink switch, DB backup, randomized restart, health-check
  rollback, never below an ACTIVE upgrade): §9.2–9.3.
- The early-adopter gate for unattended install (§9.3).
- Reproducible builds with independent builders (§9.1).
