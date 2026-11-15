# RIFT: Reach-Invariant Firewall for Trust

**An Executable Static Kernel for Pre-Commit Information-Flow Certification**

**Research author:** Thor Thor
**ORCID:** [0009-0001-6573-385X](https://orcid.org/0009-0001-6573-385X)
**GitHub:** [codethor0/rift](https://github.com/codethor0/rift)
**Research paper:** [Read the illustrated paper (PDF)](docs/paper/RIFT_Research_Paper.pdf)
**Zenodo DOI:** [10.5281/zenodo.24239735](https://doi.org/10.5281/zenodo.24239735) (v0.1.1; all versions: [10.5281/zenodo.24239734](https://doi.org/10.5281/zenodo.24239734))

<p align="center">
  <img src="docs/paper/RIFT_Sphere_Flow_Figure.png" width="640" alt="Black-and-white RIFT information-flow boundary illustration with an irregular network of nodes and curved paths surrounding a sphere." />
</p>

## Abstract

RIFT provides an executable Python kernel for pre-commit certification over a finite, trusted, static information-flow graph. For a supported mutation, it constructs a candidate state and decides ALLOW, DENY, or UNKNOWN using reachability from actual protected holdings to forbidden sinks. A counterexample found during adversarial review showed that topology deletion can erase evidence of a possible earlier transfer. The hardened kernel contains this defect by refusing every edge removal: secure revocation and persistent taint are not implemented. The artifact includes source code, shortest-path witnesses, 37 regression tests, and an independent bounded DFS test oracle. These are model-relative results, not machine-checked verification or production enforcement.

## Execute the research artifact

Python 3.10+; no external Python dependencies.

```bash
./run_tests.sh
python3 src/rift_v3_static_candidate.py
PYTHONPATH=src python3 examples/minimal_example.py
```

The package includes **37 regression tests**, including a separately implemented bounded DFS oracle covering **512 finite static states** and **3,072 single-edge proposals**. The earlier baseline contained 27 tests, followed by ten hardening regressions. These results do not constitute formal verification or production security assurances.

## What is certified

For a trusted static graph, RIFT checks whether actual protected facts have a potential directed path to a forbidden sink in a fully constructed candidate state. The default **CLEAN** rule requires zero forbidden flows; **NO_NEW** is a weaker, separately identified contract. A supported local mutation receives `ALLOW`, `DENY`, or noncommitting `UNKNOWN`.

**Critical limitation:** Every edge removal returns `UNKNOWN`. This prevents the known historical-flow defect but means **revocation is structurally unsupported in this release**, not merely delayed. Persistent `may_hold_facts`, secure purge, declassification, and temporal enforcement have not been implemented.

The accuracy of model-relative decisions also depends on trusted graph completeness, faithful fact holdings and sensitivity labels, authenticated writers, and mediation of real effects. Output witnesses can disclose protected paths to authorized writers; runtime integration requires its own access controls.

## Research resources

- [Research paper](docs/paper/RIFT_Research_Paper.pdf) | [LaTeX source](docs/paper/RIFT_Research_Paper.tex)
- [Algorithm specification](ALGORITHM.md)
- [Reproduction procedure](docs/REPRODUCIBILITY.md)
- [Audit status and open obligations](docs/AUDIT_STATUS.md)
- [Executable source](src/rift_v3_static_candidate.py)
- [Test suite](tests/test_rift_v3_static_candidate.py)
- [Executable example](examples/minimal_example.py)

### Reproducibility anchor

Hardened source baseline: [`763a41ff8588a545ee548b9c1562173cbc32aad5`](https://github.com/codethor0/rift/commit/763a41ff8588a545ee548b9c1562173cbc32aad5). The signed public release may include a later publication-only commit; verify its exact source archive against the deposited `SHA256SUMS.txt` manifest. The source and test SHA-256 values are stated in the paper.

## Scope, prior art and scientific challenge

RIFT is a bounded reference algorithm, not a deployed firewall or a claim to have invented information-flow control. The paper positions the kernel alongside earlier approaches, including Denning, Jif, Flow Caml, and LIO. Independent counterexamples and corrections are welcome. Please report a minimal runnable state, action, principal, expected decision, actual result, and source hash.

## Citation

If you use RIFT, please cite the archived software record:

> Thor, T. (2026). *RIFT: Reach-Invariant Firewall for Trust - An Executable Static Kernel for Pre-Commit Information-Flow Certification* (Version 0.1.1) [Computer software]. Zenodo. https://doi.org/10.5281/zenodo.24239735

```bibtex
@software{thor_2026_rift,
  author    = {Thor, Thor},
  title     = {{RIFT: Reach-Invariant Firewall for Trust - An Executable Static Kernel for Pre-Commit Information-Flow Certification}},
  year      = {2026},
  version   = {0.1.1},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.24239735},
  url       = {https://doi.org/10.5281/zenodo.24239735}
}
```

Citation metadata is also provided in [CITATION.cff](CITATION.cff).

## License and attribution

This software is released under the **MIT** license; see [LICENSE](LICENSE). The academic author is **Thor Thor**; signed Git commits use **codethor0**. Research developed independently on the author's own time, not sponsored by or representative of an employer.
