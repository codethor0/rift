# RIFT Algorithm Contract: Static Reference Kernel

Status: preliminary containment revision, awaiting independent falsification. The implementation is executable but is **not formally proven**.

## State and flow

Let Sigma be a finite, directed multigraph whose nodes may hold facts. Each fact has a sensitivity level. Policy P declares forbidden sinks, a protection threshold, and explicit exceptions. Directed edges describe **modeled executable transfer possibilities**, not merely policy permission.

`Bad(Sigma,P)` is the set of `(source, fact, sink)` triples for which the source actually holds a protected fact, the sink is protected, and a directed path exists without an applicable exception. Zero-hop occupancy of a protected sink counts in this particular model.

Let `Candidate(Sigma,a)` applies an authorized proposal to an immutable candidate state, including authorized policy changes. An arbitrary change to the modeled graph is *not* an authorized RIFT action.

### Clean-state contract (default)

    CERTIFY(Sigma,a) = ALLOW  iff  Bad(Candidate(Sigma,a)) = empty

subject to valid input, authenticated authorization, complete modeled coverage, supported semantics, and version consistency.

### No-new-violation contract (weaker alternative)

    CERTIFY_NO_NEW(Sigma,a) = ALLOW  iff
        Bad(Candidate(Sigma,a)) minus Bad(Sigma) = empty

These are distinct contracts. Neither justifies a claim about unmodeled physical data channels.

## Decision handling

`ALLOW`: the modeled candidate satisfies the selected contract and can be committed in the single-process reference monitor. `DENY`: an established violation or unauthorized/invalid action. `UNKNOWN`: coverage, state consistency, or supported semantics are insufficient to certify. `UNKNOWN` does not commit.

## Unsupported or unproven

Temporal paths, delegation depth, purpose controls, authoritative deletion/sanitization, distributed enforcement, external-effect atomicity, side channels, unobserved flows, scalable enterprise latency, and formal proof are **out of scope** for the current kernel. See `docs/AUDIT_STATUS.md`.

## Historical flow containment (required invariant)

A removal of an edge does **not** establish erasure of information transferred while the edge existed. An earlier static implementation approved such a removal, allowing an APPROVE/REMOVE/APPROVE sequence to reach a protected sink without any remaining forbidden graph path. This violates the intended history-sensitive security property.

Until an explicit persistent `may-have-held` state and verified purge semantics are implemented and independently checked, actions with `remove_edge_ids` return `UNKNOWN` and are not committed. Node removal, holding removal, temporal effects, and delegation remain unsupported. Graph changes must be mediated by the reference monitor. New nodes and new holding assertions are validated as exact data structures; fact sensitivity declarations and policy replacement require policy-admin authorization.

This conservative containment is *not* a formal temporal proof. `CLEAN` means no forbidden reachability within the current complete trusted model; an external implementation must enforce effects in the same order and cover all real transfer paths. A transition that returns `UNKNOWN` is not permission to apply an external edit.

## In-process security boundary

The reference monitor serializes operations and snapshots its own state to avoid shared object aliases, but arbitrary hostile code executing in the same Python process can inspect or mutate monitor internals. The reference monitor does not claim tamper resistance, durable nonce storage, crash recovery, or distributed enforcement.
