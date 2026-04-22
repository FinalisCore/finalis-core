# Partner API Compatibility Policy

## Scope

Applies to the exchange-facing contract in:

- `openapi/finalis-partner-v1.yaml`
- `/api/v1/*` partner endpoints implemented by `finalis-explorer`

## Compatibility Classes

- **Breaking**
  - removing an existing operation (`method + path`)
  - removing an existing success response (`2xx`) from an operation
  - adding new required request headers for an existing operation
  - adding new required request body fields for an existing operation
  - changing an operation from public (`security: []`) to authenticated
- **Non-breaking**
  - adding new operations
  - adding optional request fields
  - adding response fields
  - adding additional response status codes without removing existing ones
  - documentation/summary-only changes

## Versioning Rules

- Contract follows SemVer via `info.version` in OpenAPI.
- Any OpenAPI contract change MUST increment `info.version`.
- Breaking changes MUST increment the major version.
- Non-breaking changes MUST increment minor or patch.

## Documentation Rules

- Every OpenAPI contract change MUST update:
  - `docs/PARTNER_API_CHANGELOG.md`
- Breaking changes MUST also update:
  - `docs/PARTNER_API_DEPRECATIONS.md`

## CI Enforcement

GitHub Actions workflow `partner-api-governance.yml` enforces:

- OpenAPI base/head diff detection
- compatibility classification
- required SemVer bump policy
- changelog/deprecation update requirements

Failing this workflow blocks merge for governed branches.
