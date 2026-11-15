# RIFT: Reach-Invariant Firewall for Trust

Research code and algorithm specification. Private working tree, awaiting independent regression review.

**Research author:** Thor Thor  
**GitHub identity:** `codethor0`

## Scope

The currently tested kernel models static, directed information-flow paths between nodes holding classified facts and protected destinations. It evaluates a complete candidate graph before admitting a modeled change. It is a research candidate, **not a production security control**. Edge deletion is not currently certifiable: the kernel returns `UNKNOWN` rather than erasing possible historical information flows.

The original RIFT v2.1 algorithm is retained separately for adversarial comparison. Its bounded-path incremental logic contains unresolved false-ALLOW defects and must not be used as an enforcement mechanism.

## Run

```sh
./run_tests.sh
python3 src/rift_v3_static_candidate.py
```

## Research record

- `ALGORITHM.md`: normative scope and mathematical decision contract.
- `src/rift_v3_static_candidate.py`: static reference implementation.
- `tests/test_rift_v3_static_candidate.py`: tests and independent bounded DFS comparison.
- `legacy/`: preserved v2.1 research baselines, explicitly not production code.
- `docs/REPRODUCIBILITY.md`: execution and test boundaries.
- `docs/AUDIT_STATUS.md`: open scientific and implementation issues.
- `docs/RELEASE_GATE.md`: controls for later public code and DOI publication.

Private working materials are excluded from the research repository.

No public release, license grant, Zenodo DOI, patent filing, or production claim is made by this private research snapshot. A license will be selected before any public open-source release.
