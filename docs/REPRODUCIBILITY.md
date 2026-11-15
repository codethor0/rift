# Reproducibility

## Prerequisites

Python 3.10 or newer. No third-party Python packages required for the initial test suite.

## Run from the repository root

```sh
./run_tests.sh
python3 src/rift_v3_static_candidate.py
PYTHONPATH=src python3 examples/minimal_example.py  # prints ALLOW, DENY, UNKNOWN
python3 legacy/reproduce_horizon_false_allow.py  # demonstrates known legacy failure
```

The test runner adds `src` to `PYTHONPATH` so tests still import the algorithm when launched from a different directory. This corrects the common module-import error caused by running a moved test file directly from Downloads.

## Scope of existing bounded tests

The supplied tests include 37 unittest cases, including an independent DFS comparison over 512 states and 3,072 single-edge proposals and a regression that refuses historical edge erasure in a **three-node, single-secret, unbounded static-graph subspace**. The script does not implement the separate review protocol's multilevel-label or H-bounded temporal search space.

Report the exact Python version, Git commit SHA, test counts, environment, and failures when sharing results. Test success is not an unrestricted proof.

## Verification status

The earlier candidate exhibited a sequential false-ALLOW involving edge removal. This contained revision makes all edge-removal actions UNKNOWN and noncommitting. The revised tests passed before the v0.1.1 release; independent reproduction and review by others are invited. Record the full Python version, code hash and test results for any external verification.
