# Partner API Reference

_Generated from `openapi/finalis-partner-v1.yaml`. Do not edit manually._

| Method | Path | Auth | Summary |
|---|---|---|---|
| `GET` | `/api/v1/status` | `public` | Finalized status snapshot |
| `POST` | `/api/v1/transactions/status:batch` | `auth` | Batch transaction status lookup |
| `POST` | `/api/v1/withdrawals` | `auth` | Idempotent withdrawal submission |
| `GET` | `/api/v1/withdrawals/{id}` | `auth` | Read canonical withdrawal lifecycle state |
| `GET` | `/api/v1/events/finalized` | `auth` | Replayable finalized event feed |
| `GET` | `/api/v1/fees/recommendation` | `public` | Withdrawal fee policy guidance |
| `GET` | `/api/v1/webhooks/dlq` | `auth` | List partner webhook dead-letter queue entries |
| `POST` | `/api/v1/webhooks/dlq/replay` | `auth` | Replay a dead-lettered webhook delivery by sequence |
