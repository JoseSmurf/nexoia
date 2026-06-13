# nex Semantics v1.0.0

## Strength Lattice

nex evidence strength is totally ordered:

`Unverifiable < Local < Witnessed < Signed < Anchored`

Runtime checks use this order directly. A value satisfies a required strength
when `actual >= required`.

## Construct Behavior

| Construct | Runtime behavior |
| --- | --- |
| Version header | Optional parse-time gate. `// nex-version: 1.0.0` is accepted; any other version is rejected before evaluation. |
| `use path` | Loads `path` from the current source directory, mapping dots to directories and using the `.nex` extension. Imports are expanded before the local body. |
| `let id = node expr strength` | Resolves `expr`, creates a deterministic typed node for `id`, records a node trace entry, and stores the value in the environment. |
| `let id = left derive right as type` | Resolves both inputs, requires values compatible with `type`, derives a new typed node, and assigns the minimum input strength. |
| `attest id with n external bool` | Requires `id` to be `Signed`, creates deterministic synthetic witnesses, and upgrades the node to `Anchored` if witness validation succeeds. |
| `assert id >= strength` | Fails closed unless `id` exists and its actual strength is at least `strength`; records the current node when the assertion succeeds. |
| `act id = action requires strength` | Records a deterministic action decision. The checked subject is `id` when it names a node; otherwise it is the most recently produced node. If strength is sufficient, `granted` is `true`; otherwise `granted` is `false` with reason `ActionDenied`, and evaluation continues. |

## Determinism

For the same expanded source program, nex v1.0.0 guarantees:

- `program_hash` is stable because it hashes the canonical serialized program.
- `node_id` values are deterministic from the node identifier and resolved value.
- `decision_id` values are deterministic from the target identifier, action, and required strength.
- Synthetic witness IDs and timestamps are deterministic.
- Import expansion is deterministic for the same file tree.

## Failure Modes

| Failure | When it occurs | Runtime result |
| --- | --- | --- |
| `UnsupportedVersion` | Header version is present and not `1.0.0`. | Parse fails. |
| Syntax error | A line does not match the grammar. | Parse fails. |
| `MissingImport` | Imported `.nex` file is absent. | Evaluation fails before execution. |
| `CircularImport` | Import expansion finds a cycle. | Evaluation fails before execution. |
| `ImportError` | Import cannot be read or parsed. | Evaluation fails before execution. |
| `UnknownIdentifier` | A statement references a missing identifier. | Evaluation fails. |
| `AttestationRequiresSigned` | `attest` targets a node below `Signed`. | Evaluation fails. |
| `AttestationFailed` | Witness validation rejects attestation. | Evaluation fails. |
| `AssertionFailed` | `assert` observes weaker evidence than required. | Evaluation fails. |
| `UnsupportedType` | A derive type is not executable. | Evaluation fails. |
| `TypeMismatch` | `derive` inputs do not match the declared type. | Evaluation fails. |
| `ActionDenied` | `act` observes weaker evidence than required. | Action is recorded with `granted: false`; evaluation continues. |
