# RIFT Algorithm Contract: Static Reference Kernel

Status: draft for independent falsification. The implementation is executable but is **not formally proven**.

## State and flow

Let Sigma be a finite, directed multigraph whose nodes may hold facts. Each fact has a sensitivity level. Policy P declares forbidden sinks, a protection threshold, and explicit exceptions. Directed edges describe **modeled executable transfer possibilities**, not merely policy permission.

`Bad(Sigma,P)` is the set of `(source, fact, sink)` triples for which the source actually holds a protected fact, the sink is protected, and a directed path exists without an applicable exception. Zero-hop occupancy of a protected sink counts in this particular model.

Let `Candidate(Sigma,a)` apply an authorized proposal to an immutable candidate state, including policy changes.

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
