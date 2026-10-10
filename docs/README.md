# Finalis Documentation

Start with [REVIEWING.md](REVIEWING.md) if you are reviewing the protocol or the
cryptography, or [ARCHITECTURE_ORIENTATION.md](ARCHITECTURE_ORIENTATION.md) if you
are new to the code. Documents in `spec/` are normative; the others describe or
explain.

## Normative specifications — [spec/](spec/)

- [TWO_PHASE_FINALITY.md](spec/TWO_PHASE_FINALITY.md): BFT voting rules (prevote, lock, precommit) and safety argument
- [CONFIDENTIAL_UTXO_SPEC.md](spec/CONFIDENTIAL_UTXO_SPEC.md): confidential transactions, encoding and validation
- [CHECKPOINT_DERIVATION_SPEC.md](spec/CHECKPOINT_DERIVATION_SPEC.md): next-epoch committee derivation
- [AVAILABILITY_STATE_COMPLETENESS.md](spec/AVAILABILITY_STATE_COMPLETENESS.md): consensus-relevant availability state

## Protocol

- [PROTOCOL-SPEC.md](PROTOCOL-SPEC.md): protocol overview
- [LIVE_PROTOCOL.md](LIVE_PROTOCOL.md): network identity and live protocol facts
- [CONSENSUS.md](CONSENSUS.md): finalized-tip BFT path
- [NODE-EXECUTION-MODEL.md](NODE-EXECUTION-MODEL.md): finalized execution path in the node
- [COMMITTEE-SELECTION.md](COMMITTEE-SELECTION.md): committee from finalized checkpoints
- [OPERATOR-MODEL.md](OPERATOR-MODEL.md): operator aggregation
- [ONBOARDING-PROTOCOL.md](ONBOARDING-PROTOCOL.md): pre-validator onboarding
- [AVAILABILITY_STATUS.md](AVAILABILITY_STATUS.md): what the availability layer does
- [POW-AND-DIFFICULTY.md](POW-AND-DIFFICULTY.md): ticket PoW in committee selection
- [ADDRESSES.md](ADDRESSES.md): keys and address encoding
- [ECONOMICS.md](ECONOMICS.md): supply, emission and fees (source of truth)
- [REWARD-SETTLEMENT.md](REWARD-SETTLEMENT.md): accrual and epoch settlement

## Security analysis

- [REVIEWING.md](REVIEWING.md): claims, reading order, how to test
- [ADVERSARIAL_MODEL.md](ADVERSARIAL_MODEL.md): attacker classes and assumptions
- [SYBIL-RESISTANCE.md](SYBIL-RESISTANCE.md): sybil-resistance design
- [QUANTITATIVE_ATTACK_MODEL.md](QUANTITATIVE_ATTACK_MODEL.md): quantitative attack analysis
- [PROTOCOL_ATTACK_SIMULATOR.md](PROTOCOL_ATTACK_SIMULATOR.md): adversarial simulator
- [../formal/README.md](../formal/README.md): TLA+ models
- [../SECURITY.md](../SECURITY.md): reporting vulnerabilities

## Code and contributing

- [ARCHITECTURE_ORIENTATION.md](ARCHITECTURE_ORIENTATION.md): orientation for new developers
- [CODEBASE_MAP.md](CODEBASE_MAP.md): where code lives and where to add it
- [PHYSICAL_DESIGN_GUIDELINES.md](PHYSICAL_DESIGN_GUIDELINES.md): C++ layout rules
- [NODE_CPP_DECOMPOSITION.md](NODE_CPP_DECOMPOSITION.md): proposal to split the node runtime
- [STRUCTURE_CONSOLIDATION_PROPOSAL.md](STRUCTURE_CONSOLIDATION_PROPOSAL.md): proposal for folder consolidation
- [LICENSE_POLICY.md](LICENSE_POLICY.md): license headers
- [../CONTRIBUTING.md](../CONTRIBUTING.md)

## Operating a node — [operations/](operations/)

- [MAINNET.md](MAINNET.md): mainnet access and operations reference
- [operations/QUICK_START.md](operations/QUICK_START.md): install to validator registration
- [operations/LIGHTSERVER-OPERATIONS.md](operations/LIGHTSERVER-OPERATIONS.md): lightserver RPC, limits, fail-stop states
- [operations/DEVNET-TESTING-GUIDE.md](operations/DEVNET-TESTING-GUIDE.md): local devnet testing
- [operations/WINDOWS_INSTALLER_BUILD.md](operations/WINDOWS_INSTALLER_BUILD.md): building the Windows installer

## Exchanges and partners — [integrations/](integrations/)

- [integrations/EXCHANGE_INTEGRATION.md](integrations/EXCHANGE_INTEGRATION.md): start here
- [integrations/EXCHANGE_CHECKLIST.md](integrations/EXCHANGE_CHECKLIST.md), [integrations/EXCHANGE_OPERATOR_RUNBOOK.md](integrations/EXCHANGE_OPERATOR_RUNBOOK.md), [integrations/EXCHANGE_API_EXAMPLES.md](integrations/EXCHANGE_API_EXAMPLES.md)
- [integrations/PARTNER_API_V1.md](integrations/PARTNER_API_V1.md), [integrations/PARTNER_API_REFERENCE.md](integrations/PARTNER_API_REFERENCE.md) (generated), [integrations/PARTNER_API_CHANGELOG.md](integrations/PARTNER_API_CHANGELOG.md)

## Background

- [whitepaper/WHITEPAPER.md](whitepaper/WHITEPAPER.md) ([PDF](whitepaper/WHITEPAPER.pdf))
- [releases/](releases/): release notes from earlier development networks (historical)
- [reports/](reports/): test reports (historical)
