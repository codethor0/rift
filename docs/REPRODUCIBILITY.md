# Reproducibility

## Prerequisites

Python 3.10 or newer. No third-party Python packages required for the initial test suite.

## Run from the repository root

```sh
./run_tests.sh
python3 src/rift_v3_static_candidate.py
python3 legacy/reproduce_horizon_false_allow.py  # demonstrates known legacy failure
```

The test runner adds `src` to `PYTHONPATH` so tests still import the algorithm when launched from a different directory. This corrects the common module-import error caused by running a moved test file directly from Downloads.

## Scope of existing bounded tests

The supplied tests include 27 unittest cases and an independent DFS comparison over 512 states and 3,072 single-edge proposals in a **three-node, single-secret, unbounded static-graph subspace**. The script does not implement the separate review protocol's multilevel-label or H-bounded temporal search space.

Report the exact Python version, Git commit SHA, test counts, environment, and failures when sharing results. Test success is not an unrestricted proof.

## Agent review

Use the bootstrap script's `review` command to create local flat files in `private_review/`, which is ignored by Git. Send the algorithm alone for Phase A; send the tests and legacy comparisons after the independent findings are recorded.
