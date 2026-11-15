# Audit Status and Open Claims

Status: revision under independent verification. This file is a factual research ledger, not an assertion of formal verification.

## Legacy RIFT v2.1

Previous analysis identified potential or demonstrated issues with incremental distance propagation, mixed revocations and additions, treatment of hypothetical versus actual source labels, error handling, and non-atomic updates. The historical implementation is preserved for comparison and is not the accepted kernel. A minimal 1-hop test (H=1) of adding a direct SECRET-source to protected-sink edge returns an unsafe ALLOW in the supplied v2.1 implementation. Reproduce with `python3 legacy/reproduce_horizon_false_allow.py`. Each report finding requires independent reproduction before being treated as established.

## Static candidate (containment revision)

A prior candidate has a confirmed sequential false-ALLOW: adding a possible flow from an original secret holder to an intermediate node, deleting that edge, and then adding a path from that intermediate node to a protected sink are each individually ALLOW, even though the intermediate node may have retained the secret. This is a **history-sensitive correctness violation** and is release-blocking for that candidate.

The provisional correction fails closed for *all* `remove_edge_ids` actions (`UNKNOWN`, no commit), including mixed add/remove batches. It also tightens exact-type validation, version/coverage checks, fact-label authorization, the monitor's state isolation, and shortest-path witness computation. A recorded test run of the 37-case suite includes the previously reported sequence and the original 512-state static oracle. Passing these tests is not universal verification.

Do not claim the full temporal algorithm has been repaired. Instead, a narrower monotonic static kernel is under review. An explicit persistent may-have-held model, verified purge semantics, and a separate trust-boundary analysis are required to support general edge revocation.

Other security issues for verification: runtime integration and external enforcement atomicity, in-process hostile-code tampering, authorization of fact creation, invalid input fail-closed behavior, performance on long paths, incomplete graph coverage, and baseline initialization. The code is research-only and must not be used to enforce production confidentiality.

## Required before claiming formal verification

1. Specify the exact threat model, label semantics, and clean-state invariant.
2. Independently model-check the state transition kernel and version/commit behavior.
3. Evaluate alternative-predicate policy exceptions and error-handling edge cases.
4. Increase differential and property-based coverage using reproducible seeds.
5. Verify that external enforcement implements the same state transitions it models.
6. Measure false blocks and p50/p95/p99 latency under declared workloads.
7. Complete a separate prior-art and intellectual-property review.

Do not assign invented performance numbers or claim novelty without evidence.
