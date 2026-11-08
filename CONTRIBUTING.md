# Contributing to VX6

VX6 is being developed as a networking project with a narrow initial scope and a long technical runway. Contributions should improve correctness, clarity, and operational confidence.

## Project Priorities

- Keep IPv6 behavior explicit.
- Prefer simple designs over speculative abstraction.
- Build stable transport primitives before layering discovery or routing features.
- Document behavioral changes in the same change set as the code.

## Development Baseline

- Go 1.22 or newer
- Linux-first workflow
- An environment where IPv6 can be tested directly

## Repository Conventions

- `cmd/` contains executable entrypoints.
- `internal/` contains implementation packages.
- `docs/` contains architecture, roadmap, and protocol notes.

## Pull Requests

Keep pull requests focused. A good change set should:

- solve one clearly defined problem
- include tests when behavior can be exercised automatically
- update documentation when commands, structure, or semantics change
- explain operational impact in plain language

## Coding Standards

- Run `gofmt` on all Go changes.
- Keep exported APIs minimal.
- Return contextual errors.
- Do not silently fall back from IPv6 to IPv4.
- Avoid introducing dependencies without a clear payoff.

## Design Changes

Open an issue or short design note before changing:

- wire formats
- identity semantics
- routing behavior
- discovery models
- configuration layout

## Security

Do not commit private keys, captured traffic, credentials, or lab secrets. If a change affects trust boundaries or transport guarantees, document the assumptions directly in the pull request.

## Contribution Licensing

Review `LICENSE-COMMERCIAL.md` before contributing. Commercial licensing
authority belongs to Suryansh Deshwal, as described there. A contribution does
not by itself transfer copyright or patent ownership; any such transfer must
be agreed in writing.
