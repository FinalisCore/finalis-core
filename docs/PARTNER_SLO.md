# Partner API SLO and Alerting

## Scope

Applies to `finalis-explorer` partner endpoints under `/api/v1/*`.

## Suggested SLOs

- Availability SLO: `>= 99.9%` monthly for `GET /api/v1/status`
- Latency SLO: `p95 < 500ms` and `p99 < 1s` for read endpoints
- Error budget policy: pause non-essential deploys when 30-day burn rate exceeds 2x budget

## Core signals

From `/metrics`:

- `finalis_http_requests_total{route,status}`
- `finalis_partner_auth_failures_total`
- `finalis_partner_rate_limited_total`
- `finalis_partner_withdrawal_submissions_total`
- `finalis_partner_webhook_deliveries_total`
- `finalis_partner_webhook_failures_total`
- `finalis_partner_webhook_dlq_total`
- `finalis_partner_webhook_replays_total`
- `finalis_partner_webhook_queue_depth`
- `finalis_partner_webhook_dlq_depth`
- `finalis_partner_webhook_oldest_age_seconds`
- `finalis_http_request_duration_milliseconds_bucket`

## Minimum alerts

- `status` route availability below target
- sustained `5xx` increase on `/api/v1/*`
- high auth failure rate spike
- high rate-limit hit spike
- finalized height stall (from `get_status.finalized_height` polling)
- endpoint divergence on `finalized_transition_hash` at same height

## Runbook linkage

Use with:

- `docs/EXCHANGE_OPERATOR_RUNBOOK.md`
- `docs/EXCHANGE_CHECKLIST.md`
