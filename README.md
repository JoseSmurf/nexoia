# NexoIA

## What is NexoIA
NexoIA is a small Rust project that produces deterministic EPA artifacts from a local input state.
It loads the run state, hashes canonical data with BLAKE3, writes evidence and decision records in JSONL, and emits a manifest that ties the run together.
The output is designed to be reproducible, auditable, and easy to inspect offline.

## The EPA Concept
In NexoIA, an EPA is the compact artifact bundle that records what input was used, what evidence was produced, what decision was taken, and which hashes anchor the run.

An EPA is an object that can remember why it believes what it believes.

## Architecture
The crate is organized into six modules:

- `hash` - canonical BLAKE3 hashing for stable digests
- `state` - input loading and normalized run state
- `evidence` - evidence record creation and hashing
- `decision` - deterministic decision classification and decision hashing
- `quality` - `EvidenceStrength` scoring and divergence resolution
- `sync` - comparison of two decision records through the quality contract

## How to run

```bash
cargo run
```

Running the program produces:

- `state.json`
- `evidence.jsonl`
- `decisions.jsonl`
- `manifest.json`

## How to test

```bash
cargo test
```

## EvidenceStrength levels
From lowest to highest, NexoIA uses these five levels:

1. `Unverifiable`
2. `Local`
3. `Witnessed`
4. `Signed`
5. `Anchored`

The ordering matters because stronger evidence wins when quality diverges.

## nex language

nex is the small deterministic language inside this crate for expressing typed
evidence nodes, witness upgrades, imports, assertions, and final action
decisions. Version `1.0.0` is the stable language contract.

| Construct | Purpose |
| --- | --- |
| `// nex-version: 1.0.0` | Optional source version gate. |
| `use path` | Imports another `.nex` program by dot path. |
| `let id = node expr strength` | Creates a typed evidence node. |
| `let id = left derive right as type` | Derives a value from two nodes. |
| `attest id with n external bool` | Upgrades signed evidence with witnesses. |
| `assert id >= strength` | Fails unless evidence is strong enough. |
| `act id = action requires strength` | Records an allow, deny, or escalate decision. |

Quick start:

```bash
cargo run --bin nex -- examples/hello.nex
```

Language references:

- [nex grammar](docs/NEX_GRAMMAR.md)
- [nex semantics](docs/NEX_SEMANTICS.md)
