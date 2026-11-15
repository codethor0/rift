# RIFT v0.1.1 - Code-first research release

The released object is a finite static graph certification kernel, not an operational firewall.

- Research author: Thor Thor; source commits: codethor0.
- Hardened source baseline: 763a41ff8588a545ee548b9c1562173cbc32aad5.
- 37 tests, including bounded independent DFS oracle over 512 states and 3,072 single-edge proposals.
- Runnable `examples/minimal_example.py` mirrors Section 5 of the paper and returns `ALLOW`, `DENY`, `UNKNOWN`.
- Known historical-flow defect is contained by noncommitting UNKNOWN on every edge deletion.
- Secure revocation, durable taint, distributed enforcement, actual completeness verification, and p99 benchmarks are not available.
- Peer feedback and executable counterexamples are welcome.

## Publication

- Published on Zenodo on 2026-11-14: version DOI [10.5281/zenodo.24239735](https://doi.org/10.5281/zenodo.24239735); all-versions DOI [10.5281/zenodo.24239734](https://doi.org/10.5281/zenodo.24239734).
- GitHub release: [v0.1.1](https://github.com/codethor0/rift/releases/tag/v0.1.1), tag on signed commit `74c80299b8cab43c215095c359c147a263789f04`. The tag adds publication files to the hardened baseline; the kernel source and tests are unchanged.
- Archived files: `RIFT_Research_Paper.pdf`, `RIFT_Source_v0.1.1.zip`, `RIFT_Sphere_Flow_Figure.png` and `SHA256SUMS.txt`.
- The archived paper's release paragraph predates publication and notes that the repository might remain private during review. The repository is now public; the archived v0.1.1 files are unchanged.
