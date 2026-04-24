# Partner API Reference

_Generated from `openapi/finalis-partner-v1.yaml`. Do not edit manually._

| Method | Path | Auth | Summary |
|---|---|---|---|
| `GET` | `/api/v1/status` | `public` | Finalized status snapshot |
| `GET` | `/api/v1/committee` | `auth` | Finalized committee snapshot |
| `GET` | `/api/v1/recent-tx` | `auth` | Recent finalized transaction summaries |
| `GET` | `/api/v1/tx/{txid}` | `auth` | Finalized transaction lookup by txid |
| `GET` | `/api/v1/transition/{id}` | `auth` | Finalized transition lookup by height or hash |
| `GET` | `/api/v1/address/{address}` | `auth` | Finalized address balance and paginated history |
| `GET` | `/api/v1/search` | `auth` | Finalized identifier search (txid, transition, address) |
| `POST` | `/api/v1/transactions/status:batch` | `auth` | Batch transaction status lookup |
| `POST` | `/api/v1/withdrawals` | `auth` | Idempotent withdrawal submission |
| `GET` | `/api/v1/withdrawals/{id}` | `auth` | Read canonical withdrawal lifecycle state |
| `GET` | `/api/v1/events/finalized` | `auth` | Replayable finalized event feed |
| `GET` | `/api/v1/fees/recommendation` | `public` | Withdrawal fee policy guidance |
| `GET` | `/api/v1/webhooks/dlq` | `auth` | List partner webhook dead-letter queue entries |
| `POST` | `/api/v1/webhooks/dlq/replay` | `auth` | Replay a dead-lettered webhook delivery by sequence or delivery_id |
