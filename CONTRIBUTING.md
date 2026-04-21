# Contributing To Finalis Core

This guide focuses on codebase readability, discoverability, and safe changes.

## Principles

- Keep behavior changes and structure changes in separate pull requests when possible.
- Prefer clear component boundaries over convenience includes.
- Document intent at module level, not only in commit messages.
- Avoid introducing new folders unless they represent a stable architectural boundary.

## Before You Start

1. Read `README.md` for project context.
2. Read `docs/CODEBASE_MAP.md` for layout and ownership guidance.
3. Read `docs/ARCHITECTURE_ORIENTATION.md` for execution model and boundaries.
4. For protocol-sensitive work, read `docs/LIVE_PROTOCOL.md` and relevant docs in `docs/spec/`.

## Pull Request Checklist

- Scope is clear: protocol change, runtime change, refactor, docs, or tooling.
- Affected module README files are updated when ownership or behavior changes.
- New folders are justified in the PR description with boundary rationale.
- New source files follow the repository license policy in `docs/LICENSE_POLICY.md`.
- Tests are updated or rationale is provided for unchanged tests.

## Documentation Expectations

For each new module or folder, add a short README that states:

- Purpose and non-goals.
- Primary public interfaces.
- Dependency direction (what it can import and what can import it).
- Threading and ownership assumptions if relevant.

## Physical Design Guidance

We follow Lakos-inspired physical design principles:

- Components should have clear, minimal responsibilities.
- Dependency direction should be intentional and easy to explain.
- Physical layout should help new contributors answer: "Where does this belong?"

See `docs/PHYSICAL_DESIGN_GUIDELINES.md` for details.
