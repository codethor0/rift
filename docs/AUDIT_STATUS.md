# Audit Status and Open Claims

Status: independent review pending. This file is a factual research ledger, not an assertion of formal verification.

## Legacy RIFT v2.1

An external agent report and an earlier inspection identify potential or demonstrated issues with incremental distance propagation, mixed revocations and additions, treatment of hypothetical versus actual source labels, error handling, and non-atomic updates. The historical implementation is preserved for comparison and is not the accepted kernel. A minimal 1-hop test (H=1) of adding a direct SECRET-source to protected-sink edge returns an unsafe ALLOW in the supplied v2.1 implementation. Reproduce with `python3 legacy/reproduce_horizon_false_allow.py`. Each report finding requires independent reproduction before being treated as established.

## Static candidate

The available unittest suite passes locally in the creation environment. The suite includes an independent DFS comparison for one narrowly defined finite state space. It does not establish correctness for temporal paths, delegation, distributed effects, or incomplete observation.

## Required before claiming formal verification

1. Specify the exact threat model, label semantics, and clean-state invariant.
2. Independently model-check the state transition kernel and version/commit behavior.
3. Evaluate alternative-predicate policy exceptions and error-handling edge cases.
4. Increase differential and property-based coverage using reproducible seeds.
5. Verify that external enforcement implements the same state transitions it models.
6. Measure false blocks and p50/p95/p99 latency under declared workloads.
7. Complete a separate prior-art and intellectual-property review.

Do not assign invented performance numbers or claim novelty without evidence.
