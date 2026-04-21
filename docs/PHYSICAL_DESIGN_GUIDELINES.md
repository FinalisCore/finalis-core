# Physical Design Guidelines (Lakos-Inspired)

This repository uses pragmatic large-scale C++ physical design principles.

## Goals

- Make code placement predictable.
- Make dependency direction explicit.
- Reduce onboarding cost for contributors.

## Folder And Component Rules

- A folder should represent a stable responsibility boundary.
- Avoid creating a folder for one or two files unless there is a clear boundary reason.
- Prefer co-locating tightly coupled entities within an existing component.
- Every non-trivial source folder should contain a short README.

## Dependency Rules

- Depend inward on stable abstractions.
- Avoid cyclical dependencies between components.
- Keep high-level policy out of low-level utility code.
- Keep application/UI concerns out of core protocol components.

## Interface Rules

- Keep public headers minimal and focused.
- Separate implementation details from public surface area.
- Prefer explicit data flow and ownership over implicit global coupling.

## Pull Request Expectations

When introducing a new folder or moving files:

- State the boundary rationale in the PR description.
- Update relevant README files and `docs/CODEBASE_MAP.md`.
- Confirm dependency direction remains coherent.

## Anti-Patterns To Avoid

- "Utility" dumping grounds with unclear ownership.
- Feature code split across many micro-folders without boundary justification.
- Cross-layer includes that violate component direction.
