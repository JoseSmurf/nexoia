# nexoia

`nexoia` is a small Rust project that generates deterministic decision artifacts.

## Output

Running `cargo run` creates these files in the project root:

- `state.json`
- `evidence.jsonl`
- `decisions.jsonl`
- `manifest.json`

## Status values

- `OK`
- `VIOLACAO`
- `ABSTERSE`

## Environment variables

- `NEXOIA_SCENARIO` - `auto`, `ok`, `violacao`, or `absterse`
- `NEXOIA_THRESHOLD` - numeric threshold, default `50`
- `NEXOIA_INPUT_VALUE` - optional numeric input, default `60`
- `NEXOIA_SUBJECT` - subject label, default `default-evaluation`

## Notes

- Evidence records include deterministic BLAKE3 hashes of their canonical JSON content.
- The manifest records hashes for all generated artifact files.
