# NexoIA Threat Model

This document describes three concrete threat classes that matter for the current NexoIA EPA pipeline.
The current system is local-first, deterministic, and intentionally narrow, but that does not remove the need to reason about abuse cases.

## Evidence Inflation

### Attack description
An attacker tries to make the system look stronger than it really is by repeatedly submitting redundant evidence, overreporting support, or producing many low-value records that appear to confirm the same claim.
The goal is to bias review, hide weak inputs under volume, or create the impression of broader support than actually exists.

### What the system currently does
NexoIA does not aggregate evidence from a network of peers at runtime.
It produces a fixed pair of evidence records from the current state and decision, and each record is hashed deterministically.
The current flow makes the evidence trail reproducible and easy to inspect, but it does not implement global deduplication, rate limiting, or a separate anti-spam layer.

### Remaining risk
Evidence inflation is still possible at the operational layer if an upstream actor keeps generating new runs with manipulated but valid-looking inputs.
The local hash chain proves integrity of each run, not the legitimacy or uniqueness of the underlying claim.

## Anchor Laundering

### Attack description
An attacker takes weak or untrusted material and relabels it as anchored, signed, or externally verified in order to inflate its perceived strength.
This is especially dangerous when systems treat labels as proof instead of treating them as claims that must be verified.

### What the system currently does
The current `quality` module maps evidence strength from a kind string, and the decision flow compares strengths through the same local contract.
There is no runtime path in the trust core that verifies an external anchor, chain of custody, or third-party signature for the evidence kinds used today.
That keeps the implementation simple and deterministic, but it also means the system currently trusts its own labels rather than an independent verifier.

### Remaining risk
If a future adapter or integration accepts external kind labels without a verifier, anchor laundering becomes a direct bypass of the intended quality model.
Even today, the risk is that reviewers may misread a label such as `Anchored` as proof of external verification when it is only a local classification unless the surrounding contract is explicit.

## Evidence Monoculture

### Attack description
An attacker or design flaw exploits overreliance on one evidence format, one hash function, or one serialization path.
When everything depends on the same representation, a single bug or compromise can affect the entire audit trail at once.

### What the system currently does
NexoIA currently uses one canonical serialization path and one hash primitive, BLAKE3, across the EPA artifacts.
That is good for determinism and reproducibility, but it also means the current trust core is concentrated around a single representation and a single hashing implementation.
The `sync` contract and the decision pipeline also reuse the same local quality model, so there is no independent diversity of evidence semantics yet.

### Remaining risk
A defect in the canonical serialization, the hash implementation, or the shared quality model could propagate across the entire artifact chain.
The system is deterministic, but determinism alone does not protect against correlated failure.
