# Exchange Certification Pack

This pack provides reproducible evidence for partner/API readiness checks.

## Included evidence

- partner contract test run logs
- v1 contract alias test logs
- webhook GC/DLQ behavior logs
- build log and summary manifest

## Generate evidence

```bash
scripts/run_exchange_certification_pack.sh
```

Optional output directory:

```bash
scripts/run_exchange_certification_pack.sh /tmp/finalis-exchange-cert
```

## Output layout

- `build.log`
- `explorer_partner.log`
- `api_v1.log`
- `gc_prunes.log`
- `SUMMARY.txt`

## Required review checks

- all included test logs end with `all tests passed`
- no partner API governance CI failures
- OpenAPI reference drift gate passes
