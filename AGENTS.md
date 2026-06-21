# AGENTS.md — NexoIA

## Commands

```bash
cargo build          # Build main binary
cargo test           # Run all tests
cargo fmt --check    # Format check (CI enforced, must pass before build/test)
cargo run            # Run main → produces state.json, evidence.jsonl, decisions.jsonl, manifest.json
cargo run --bin nex -- examples/hello.nex   # Run nex language interpreter
cargo run --bin verify                      # Run verification binary
```

**CI order**: `cargo fmt --check` → `cargo build` → `cargo test`. All must pass.

## Structure

- `src/lib.rs` — re-exports all modules (decision, evidence, explain, hash, nex, provenance, quality, state, sync)
- `src/main.rs` — main binary: loads state, hashes, writes EPA artifacts
- `src/bin/nex.rs` — nex language interpreter
- `src/bin/verify.rs` — verification binary
- `src/nex/` — nex language parser and evaluator
- `src/provenance/` — provenance tracking

## Key Modules

| Module | Purpose |
|--------|---------|
| `hash` | BLAKE3 canonical hashing for stable digests |
| `state` | Input loading and normalized run state |
| `evidence` | Evidence record creation and hashing |
| `decision` | Deterministic decision classification |
| `quality` | `EvidenceStrength` scoring (Unverifiable → Anchored) |
| `sync` | Compare two decision records |

## nex Language

Custom DSL for typed evidence nodes. See `docs/NEX_GRAMMAR.md` and `docs/NEX_SEMANTICS.md`.

Example constructs:
- `let id = node expr strength` — create evidence node
- `assert id >= strength` — strength gate
- `act id = action requires strength` — decision record

## Conventions

- All output must be deterministic and reproducible
- EvidenceStrength levels are ordered: Unverifiable < Local < Witnessed < Signed < Anchored
- JSONL format for evidence and decisions
- BLAKE3 for all canonical hashing
- Rust edition 2021
