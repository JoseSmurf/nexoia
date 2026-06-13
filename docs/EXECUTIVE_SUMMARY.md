# Executive Summary

## What is NexoIA
NexoIA is a small Rust project that turns a local evaluation state into deterministic EPA artifacts.
It produces a normalized state file, evidence records, decision records, and a manifest that ties the run together.
The result is meant to be inspectable offline and easy to audit without hidden runtime dependencies.

## What makes it deterministic
NexoIA is deterministic at the logic layer because it uses explicit input fields, fixed decision rules, and canonical BLAKE3 hashes over stable JSON serialization.
The `run_id` is derived from the normalized state, so equal inputs produce the same logical identity.
The main caveat is that wall-clock timestamps are still recorded in the artifacts, so byte-for-byte output can vary between runs even when the decision path does not.

## What problem does it solve
NexoIA solves the problem of producing a compact, reproducible, local-first decision trail.
It keeps the decision, the evidence, and the manifest close together so an operator can review what happened, why it happened, and how the output was hashed.
That makes the system easier to inspect than a purely implicit or stateful workflow.

## Evidence that it works
The repository currently contains 18 tests in total. The 15 core tests below cover the EPA pipeline that this summary is focused on.

### Seven commits
1. `1da8438` - initial commit: nexoia artifact generator
2. `b062707` - feat: EPA v0 - deterministic evidence, decision, and manifest with BLAKE3
3. `503d191` - feat: add QualityEvaluator with EvidenceStrength levels and ResolutionReport
4. `396459e` - ci: add GitHub Actions workflow
5. `05b493c` - refactor: dynamic EvidenceStrength evaluation in decision
6. `c08ef8c` - feat: add SyncContract for EPA divergence resolution
7. `8420bc6` - docs: update README with complete EPA architecture

### Fifteen core tests
1. `hash::tests::canonical_hash_is_stable_for_same_input` - identical input produces the same BLAKE3 hash
2. `hash::tests::canonical_hash_changes_for_different_input` - different input produces a different hash
3. `state::tests::deterministic_run_id_is_stable` - equal inputs produce the same run ID
4. `state::tests::deterministic_run_id_changes_when_inputs_change` - changing inputs changes the run ID
5. `state::tests::scenario_as_str_matches_output_contract` - scenario serialization matches the output contract
6. `quality::tests::evaluate_maps_known_kinds` - kind strings map to the expected evidence strength
7. `quality::tests::resolve_prefers_stronger_side` - stronger evidence wins the divergence resolution
8. `decision::tests::classify_auto_ok` - auto mode accepts a value above the threshold
9. `decision::tests::classify_auto_violacao` - auto mode rejects a value below the threshold
10. `decision::tests::classify_absterse` - abstain mode resolves to `ABSTERSE`
11. `decision::tests::evaluate_uses_dynamic_kinds_signed_vs_local` - decision evaluation uses dynamic kinds
12. `decision::tests::evaluate_uses_dynamic_kinds_witness_vs_anchored` - stronger right-side evidence is selected
13. `decision::tests::evaluate_uses_dynamic_kinds_tie_on_equal_strength` - equal evidence resolves to a tie
14. `evidence::tests::evidence_body_hash_is_present` - each evidence body produces a hash
15. `evidence::tests::build_records_creates_two_evidence_lines` - the evaluator emits the two expected evidence records

## Top 5 remaining weaknesses
1. Runtime timestamps are still part of the artifacts, so exact bytes are not fully stable across runs.
2. The `sync` module is a local contract, not yet a full runtime path in the main execution flow.
3. There is no separate offline verifier executable in this repository yet.
4. Environment-driven inputs make reproducibility depend on configuration hygiene.
5. The artifact schema is still small and would benefit from explicit versioning once it stabilizes.

## What a serious reviewer should look at first
Start with `src/state.rs`, `src/hash.rs`, `src/decision.rs`, and `src/evidence.rs`.
Those files define the input normalization, the canonical hash, the decision semantics, and the audit artifact shape.
Then review `src/quality.rs` and `src/sync.rs` to confirm that divergence resolution is consistent and does not weaken the core EPA path.

