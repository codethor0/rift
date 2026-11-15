# RIFT - Code-first research release

The released object is a finite static graph certification kernel, not an operational firewall.

- Research author: Thor Thor; source commits: codethor0.
- Hardened source baseline: 763a41ff8588a545ee548b9c1562173cbc32aad5.
- 37 tests, including bounded independent DFS oracle over 512 states and 3,072 proposed edges.
- Runnable `examples/minimal_example.py` mirrors Section 5 of the paper and returns `ALLOW`, `DENY`, `UNKNOWN`.
- Known historical-flow defect is contained by noncommitting UNKNOWN on every edge deletion.
- Secure revocation, durable taint, distributed enforcement, actual completeness verification, and p99 benchmarks are not available.
- Peer feedback and executable counterexamples are welcome.
- Public Zenodo release and GitHub visibility require explicit owner confirmation after independent manuscript and IP review.
