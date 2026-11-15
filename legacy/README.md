# Historical RIFT v2.1 algorithm (not for enforcement)

This directory preserves the older, known-incomplete v2.1 algorithm as an
unchanged comparison baseline. Do not import this code into a production
reference monitor. Known correctness gaps include H-bounded distance handling,
revocation ordering, source-state ambiguity, and transaction safety.

`rift_v21_phase_a.py` is a streamlined version intended for blind code audit.
`rift_v21_legacy.py` retains the original explanatory comments and test harness.
`reproduce_horizon_false_allow.py` demonstrates a direct one-hop false ALLOW at H=1.

Current candidate algorithm: `../src/rift_v3_static_candidate.py`.
