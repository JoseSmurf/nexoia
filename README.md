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
