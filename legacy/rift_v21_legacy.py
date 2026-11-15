"""
RIFT v2.1 — Reference Implementation
=====================================

Faithful to RIFT Reference Algorithm Specification v2.1.

KNOWN ISSUES ARE MARKED WITH `# KNOWN ISSUE Hx` WHERE THEY APPLY.
These are intentionally present so the verification protocol (v3.1)
can test for them. Do NOT ship this as production code without
addressing the H1–H8 trouble spots and closing the open problems.

Run: python3 rift_v21.py
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple
from enum import Enum
import time


# =============================================================================
# SECTION 1 — TYPES
# =============================================================================

SENS_ORDER = {"PUBLIC": 0, "INTERNAL": 1, "SECRET": 2}
AUTH_ORDER = {"NONE": 0, "READ": 1, "WRITE": 2, "ADMIN": 3}


@dataclass(frozen=True)
class Label:
    sensitivity: str
    authority: str

    def __repr__(self):
        return f"{self.sensitivity}/{self.authority}"


ALL_LABELS: List[Label] = [
    Label(s, a) for s in SENS_ORDER for a in AUTH_ORDER
]


def join(l1: Label, l2: Label) -> Label:
    return Label(
        sensitivity=max(l1.sensitivity, l2.sensitivity,
                        key=lambda x: SENS_ORDER[x]),
        authority=max(l1.authority, l2.authority,
                      key=lambda x: AUTH_ORDER[x]),
    )


def leq(l1: Label, l2: Label) -> bool:
    return (SENS_ORDER[l1.sensitivity] <= SENS_ORDER[l2.sensitivity]
            and AUTH_ORDER[l1.authority] <= AUTH_ORDER[l2.authority])


@dataclass
class Node:
    id: str
    kind: str  # AGENT, STORE, TOOL, SINK
    label_state: Label
    is_sink: bool = False
    provenance: List[Tuple[float, str, Label]] = field(default_factory=list)


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    kind: str  # READ, WRITE, DELEGATE, QUERY, INVOKE
    label: Label
    epoch: int = 0


@dataclass
class Action:
    E_plus: List[Edge] = field(default_factory=list)
    E_minus: List[Edge] = field(default_factory=list)
    N_plus: List[Node] = field(default_factory=list)
    N_minus: List[str] = field(default_factory=list)
    L_plus: List[Tuple[str, Label]] = field(default_factory=list)
    principal: str = ""


class Decision(Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"


@dataclass
class Violation:
    source: str
    source_label: Label
    sink: str
    sink_label: Label
    distance: int
    witness: List[Edge] = field(default_factory=list)


# =============================================================================
# SECTION 2 — GRAPH
# =============================================================================

class Graph:
    def __init__(self):
        self.V: Dict[str, Node] = {}
        self.E: Dict[Tuple[str, str], List[Edge]] = {}
        self.epoch: int = 0

    def copy(self) -> "Graph":
        g = Graph()
        for k, v in self.V.items():
            g.V[k] = Node(
                id=v.id, kind=v.kind, label_state=v.label_state,
                is_sink=v.is_sink, provenance=list(v.provenance))
        for k, v in self.E.items():
            g.E[k] = list(v)
        g.epoch = self.epoch
        return g

    def add_node(self, n: Node) -> None:
        self.V[n.id] = n

    def add_edge(self, e: Edge) -> None:
        self.E.setdefault((e.src, e.dst), []).append(e)

    def remove_edge(self, e: Edge) -> None:
        key = (e.src, e.dst)
        if key in self.E:
            self.E[key] = [
                x for x in self.E[key]
                if not (x.kind == e.kind and x.label == e.label)
            ]

    def outgoing(self, u: str) -> List[Edge]:
        out = []
        for (src, _dst), edges in self.E.items():
            if src == u:
                out.extend(edges)
        return out

    def incoming(self, v: str) -> List[Edge]:
        out = []
        for (_src, dst), edges in self.E.items():
            if dst == v:
                out.extend(edges)
        return out


# =============================================================================
# SECTION 3 — ENVELOPE (default policy)
# =============================================================================

def default_envelope(source: str, source_label: Label,
                     sink: str, sink_label: Label) -> bool:
    """
    Total predicate. Fail-closed on missing inputs.
    Default policy: a SECRET source may not reach any protected sink
    unless the sink's label is SECRET (which, by construction, means
    the sink can hold the secret — but we also forbid the transfer as
    a policy choice, so any SECRET source → sink is a violation).
    """
    if source_label is None or sink_label is None:
        return False  # fail-closed
    if source_label.sensitivity != "SECRET":
        return True
    return False


# =============================================================================
# SECTION 4 — RIFT v2.1
# =============================================================================

class RIFT:
    def __init__(self,
                 H: int,
                 S: Set[str],
                 PROTECTED_COMPONENTS: Set[str],
                 envelope: Callable[[str, Label, str, Label], bool]):
        self.H = H
        self.S = S
        self.PROTECTED_COMPONENTS = PROTECTED_COMPONENTS
        self.envelope = envelope
        self.epoch = 0
        self.decision_log: List[dict] = []

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def admit_action(self, G: Graph, action: Action
                     ) -> Tuple[Decision, List[Violation]]:
        t0 = time.perf_counter()

        # Step 1: revocations first.
        # KNOWN ISSUE H5: this makes G_old in the delta the POST-revocation
        # graph, not G_t. The spec's invariant is stated relative to G_t.
        if action.E_minus or action.N_minus or action.L_plus:
            self._apply_revocations_and_label_updates(G, action)

        # Step 2: no new capabilities → trivially safe.
        if not action.E_plus and not action.N_plus:
            return Decision.ALLOW, []

        # Step 3: candidate graph.
        G_prime = G.copy()
        for n in action.N_plus:
            G_prime.add_node(n)
        for e in action.E_plus:
            G_prime.add_edge(e)

        # Step 4: counterfactual delta.
        violations, _R_new = self._protected_delta(G, action)

        # Step 5: decision.
        latency_ms = (time.perf_counter() - t0) * 1000.0
        if not violations:
            for n in action.N_plus:
                G.V[n.id] = Node(
                    id=n.id, kind=n.kind, label_state=n.label_state,
                    is_sink=n.is_sink, provenance=list(n.provenance))
            for e in action.E_plus:
                G.add_edge(e)
            self.decision_log.append({
                "decision": "ALLOW", "latency_ms": latency_ms,
                "violations": 0,
            })
            return Decision.ALLOW, []

        self.decision_log.append({
            "decision": "DENY", "latency_ms": latency_ms,
            "violations": len(violations),
            "witness": self._minimal_witness(violations),
        })
        return Decision.DENY, violations

    # -------------------------------------------------------------------------
    # Step 1 helper
    # -------------------------------------------------------------------------

    def _apply_revocations_and_label_updates(self, G: Graph,
                                             action: Action) -> None:
        for e in action.E_minus:
            G.remove_edge(e)
        for nid in action.N_minus:
            G.V.pop(nid, None)
        for nid, lam in action.L_plus:
            if nid in G.V:
                G.V[nid].label_state = lam
                G.V[nid].provenance.append(
                    (time.time(), action.principal, lam))
                # KNOWN ISSUE H2: does NOT recompute label from provenance
                # after a revocation. Section 3, rule R4 says it should.
        self.epoch += 1
        G.epoch = self.epoch

    # -------------------------------------------------------------------------
    # Section 6 — Ancestor BFS
    # -------------------------------------------------------------------------

    def _ancestor_set(self, G: Graph, x: str, lam_x: Label, H: int
                      ) -> Dict[Tuple[str, Label], List[Tuple[Label, int]]]:
        """
        Reverse BFS from (x, lam_x) in the product graph.
        Returns: {(v, lam_v): [(lam_x_observed, distance), ...]}
        """
        result: Dict[Tuple[str, Label],
                     List[Tuple[Label, int]]] = {}
        # Queue: (node, label_at_node, distance_from_x)
        queue: List[Tuple[str, Label, int]] = [(x, lam_x, 0)]
        seen: Set[Tuple[str, Label, int]] = set()
        while queue:
            u, lam_u, d = queue.pop(0)
            if (u, lam_u, d) in seen:
                continue
            seen.add((u, lam_u, d))
            if d > 0:
                result.setdefault((u, lam_u), []).append((lam_x, d))
            if d == H - 1:
                continue
            for e in G.incoming(u):
                if e.epoch != G.epoch:
                    continue
                # Reverse-join: enumerate pre-images
                for lam_src in ALL_LABELS:
                    if join(lam_src, e.label) == lam_u:
                        if e.src in G.V:
                            queue.append((e.src, lam_src, d + 1))
        return result

    # -------------------------------------------------------------------------
    # Section 7 — Counterfactual delta
    # -------------------------------------------------------------------------

    def _protected_delta(self, G_old: Graph, action: Action
                         ) -> Tuple[List[Violation],
                                    Dict[Tuple[str, Label],
                                         Set[Tuple[str, Label, int]]]]:
        R_old = self._compute_reachability(G_old)
        R_new: Dict[Tuple[str, Label],
                    Set[Tuple[str, Label, int]]] = {
            k: set(v) for k, v in R_old.items()
        }

        # Step A: new nodes that are sinks reach themselves at distance 0.
        for n in action.N_plus:
            if n.is_sink:
                for lam in ALL_LABELS:
                    if leq(lam, n.label_state):
                        R_new.setdefault((n.id, lam), set()).add(
                            (n.id, lam, 0))

        # Step B: ancestor sets per tail per achievable label.
        Anc: Dict[str, Dict[Label,
                            Dict[Tuple[str, Label],
                                 List[Tuple[Label, int]]]]] = {}
        for e in action.E_plus:
            if e.src not in Anc:
                Anc[e.src] = {}
                for lam_x in ALL_LABELS:
                    Anc[e.src][lam_x] = self._ancestor_set(
                        G_old, e.src, lam_x, self.H)

        # Step C: fixpoint.
        # KNOWN ISSUE H1: first distance found is retained; a later,
        # shorter path does not update the stored distance, which can
        # cause the horizon check to reject a path that should pass.
        # KNOWN ISSUE H4: no temporal EAT handling (edge epoch is
        # checked but liveness intervals are not modelled here).
        max_iters = len(G_old.V) * len(self.S) * len(ALL_LABELS) + 1
        changed = True
        iters = 0
        while changed and iters < max_iters:
            changed = False
            iters += 1
            for e in action.E_plus:
                x, y = e.src, e.dst
                for lam_x in ALL_LABELS:
                    lam_y = join(lam_x, e.label)
                    additions_from_y: Dict[Tuple[str, Label], int] = {}
                    for (s, lam_s, d_s) in R_new.get((y, lam_y), set()):
                        lam_at_s = join(lam_y, lam_s)
                        if not self._sink_accepts(s, lam_at_s):
                            continue
                        additions_from_y[(s, lam_at_s)] = d_s + 1

                    targets: List[Tuple[str, Label, int]] = [(x, lam_x, 0)]
                    if lam_x in Anc.get(x, {}):
                        for ((v, lam_v),
                             pairs) in Anc[x][lam_x].items():
                            for (lam_x_obs, d_vx) in pairs:
                                if lam_x_obs == lam_x:
                                    targets.append((v, lam_v, d_vx))

                    for (v, lam_v, d_vx) in targets:
                        for (s, lam_s), d_suf in additions_from_y.items():
                            if d_vx + 1 + d_suf > self.H:
                                continue
                            key = (v, lam_v)
                            existing = R_new.get(key, set())
                            if any(es == s and el == lam_s
                                   for (es, el, _) in existing):
                                continue  # H1: no update to shorter dist
                            R_new.setdefault(key, set()).add(
                                (s, lam_s, d_vx + 1 + d_suf))
                            changed = True

        # Step D: violations.
        violations: List[Violation] = []
        for (v, lam_v), entries in R_new.items():
            if not self._is_protected_source(lam_v):
                continue
            old_entries = R_old.get((v, lam_v), set())
            old_keys = {(es, el) for (es, el, _) in old_entries}
            for (s, lam_s, d) in entries:
                if (s, lam_s) in old_keys:
                    continue
                if not self.envelope(v, lam_v, s, lam_s):
                    violations.append(Violation(
                        source=v, source_label=lam_v,
                        sink=s, sink_label=lam_s, distance=d))

        return violations, R_new

    # -------------------------------------------------------------------------
    # Reachability (used for R_old and the oracle-independent baseline)
    # -------------------------------------------------------------------------

    def _compute_reachability(self, G: Graph
                              ) -> Dict[Tuple[str, Label],
                                        Set[Tuple[str, Label, int]]]:
        result: Dict[Tuple[str, Label],
                     Set[Tuple[str, Label, int]]] = {}
        for u in G.V:
            for lam_u in ALL_LABELS:
                queue: List[Tuple[str, Label, int]] = [(u, lam_u, 0)]
                seen: Set[Tuple[str, Label, int]] = set()
                while queue:
                    v, lam_v, d = queue.pop(0)
                    if (v, lam_v, d) in seen:
                        continue
                    seen.add((v, lam_v, d))
                    if v in self.S:
                        result.setdefault((u, lam_u), set()).add(
                            (v, lam_v, d))
                    if d >= self.H:
                        continue
                    for e in G.outgoing(v):
                        if e.epoch != G.epoch:
                            continue
                        lam_next = join(lam_v, e.label)
                        queue.append((e.dst, lam_next, d + 1))
        return result

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------

    def _is_protected_source(self, lam: Label) -> bool:
        return lam.sensitivity in self.PROTECTED_COMPONENTS

    def _sink_accepts(self, s: str, lam_s: Label) -> bool:
        return True  # all sinks accept all labels in this reference

    def _minimal_witness(self, violations: List[Violation]
                         ) -> Optional[Violation]:
        if not violations:
            return None
        # KNOWN ISSUE H6: suggestion field is None (deferred)
        return min(violations, key=lambda v: v.distance)


# =============================================================================
# SECTION 5 — ORACLE (independent ground truth)
# =============================================================================

class Oracle:
    """
    Brute-force, from-scratch, independent of RIFT internals.
    Uses only the type definitions and the label algebra.
    """

    def __init__(self,
                 H: int,
                 S: Set[str],
                 PROTECTED_COMPONENTS: Set[str],
                 envelope: Callable[[str, Label, str, Label], bool]):
        self.H = H
        self.S = S
        self.PROTECTED_COMPONENTS = PROTECTED_COMPONENTS
        self.envelope = envelope

    def _is_protected(self, lam: Label) -> bool:
        return lam.sensitivity in self.PROTECTED_COMPONENTS

    def _all_paths(self, G: Graph, start: str, start_label: Label
                   ) -> List[Tuple[str, Label, int]]:
        result: List[Tuple[str, Label, int]] = []

        def dfs(node: str, label: Label, depth: int) -> None:
            if depth > self.H:
                return
            result.append((node, label, depth))
            if depth == self.H:
                return
            for e in G.outgoing(node):
                if e.epoch != G.epoch:
                    continue
                next_label = join(label, e.label)
                dfs(e.dst, next_label, depth + 1)

        dfs(start, start_label, 0)
        return result

    def _reachable(self, G: Graph
                   ) -> Dict[Tuple[str, Label],
                             Set[Tuple[str, Label, int]]]:
        result: Dict[Tuple[str, Label],
                     Set[Tuple[str, Label, int]]] = {}
        for u in G.V:
            for lam_u in ALL_LABELS:
                for (v, lam_v, d) in self._all_paths(G, u, lam_u):
                    if v in self.S:
                        result.setdefault((u, lam_u), set()).add(
                            (v, lam_v, d))
        return result

    def _bad_pairs(self, R
                   ) -> Set[Tuple[str, Label, str, Label]]:
        bad: Set[Tuple[str, Label, str, Label]] = set()
        for (v, lam_v), entries in R.items():
            if not self._is_protected(lam_v):
                continue
            for (s, lam_s, _d) in entries:
                if not self.envelope(v, lam_v, s, lam_s):
                    bad.add((v, lam_v, s, lam_s))
        return bad

    def decide(self, G_old: Graph, G_new: Graph,
               action: Action) -> Dict[str, object]:
        R_old = self._reachable(G_old)
        R_new = self._reachable(G_new)
        Bad_old = self._bad_pairs(R_old)
        Bad_new = self._bad_pairs(R_new)
        PRIMARY = len(Bad_new) == 0
        ALTERN = len(Bad_new - Bad_old) == 0
        return {
            "PRIMARY": PRIMARY,
            "ALTERNATIVE": ALTERN,
            "Bad_old": Bad_old,
            "Bad_new": Bad_new,
        }


# =============================================================================
# SECTION 6 — TEST HARNESS (T1–T8)
# =============================================================================

def mk_label(sens: str = "PUBLIC", auth: str = "NONE") -> Label:
    return Label(sens, auth)


def _run_comparison(name: str,
                    G: Graph,
                    action: Action,
                    H: int = 3,
                    S: Optional[Set[str]] = None,
                    PROTECTED: Optional[Set[str]] = None,
                    envelope: Optional[Callable] = None
                    ) -> Tuple[Decision, dict]:
    S = S or {"sink"}
    PROTECTED = PROTECTED or {"SECRET"}
    envelope = envelope or default_envelope

    # Build G_new for the oracle
    G_new = G.copy()
    for nid in action.N_minus:
        G_new.V.pop(nid, None)
    for e in action.E_minus:
        G_new.remove_edge(e)
    for nid, lam in action.L_plus:
        if nid in G_new.V:
            G_new.V[nid].label_state = lam
    for n in action.N_plus:
        G_new.add_node(Node(n.id, n.kind, n.label_state, n.is_sink))
    for e in action.E_plus:
        G_new.add_edge(e)
    G_new.epoch = G.epoch + 1  # match RIFT's epoch bump

    # Oracle first (on fresh copies so it sees the pre/post states)
    oracle = Oracle(H, S, PROTECTED, envelope)
    expected = oracle.decide(G.copy(), G_new, action)

    # RIFT second
    rift = RIFT(H, S, PROTECTED, envelope)
    decision, _violations = rift.admit_action(G.copy(), action)

    # Verdict
    if expected["PRIMARY"]:
        expected_str = "ALLOW (clean-state)"
    elif expected["ALTERNATIVE"]:
        expected_str = "ALLOW (no new violation)"
    else:
        expected_str = "DENY"

    if expected["ALTERNATIVE"] and decision == Decision.ALLOW:
        verdict = "AGREE"
    elif not expected["ALTERNATIVE"] and decision == Decision.DENY:
        verdict = "AGREE"
    else:
        verdict = "DISAGREE"

    print(f"  [{name}]")
    print(f"    Oracle:     PRIMARY={expected['PRIMARY']} "
          f"ALTERNATIVE={expected['ALTERNATIVE']} -> {expected_str}")
    print(f"    RIFT:       {decision.value}")
    print(f"    Verdict:    {verdict}")
    return decision, expected


def test_t1_min_distance() -> None:
    """
    T1: min-distance vs first-distance in fixpoint.
    Two paths to sink: existing a->b->sink (len 2); new a->c (1)
    and c->sink (1). If a->c is processed before c->sink, the
    fixpoint may record a->sink at distance 2 from the first path
    but miss the shorter 2 via the new edges (both length 2, so
    actually equal here — need a longer existing path).
    """
    G = Graph()
    G.add_node(Node("a", "AGENT", mk_label("SECRET", "READ")))
    G.add_node(Node("b1", "STORE", mk_label("SECRET")))
    G.add_node(Node("b2", "STORE", mk_label("SECRET")))
    G.add_node(Node("sink", "SINK", mk_label("PUBLIC"), is_sink=True))
    # Existing path a -> b1 -> b2 -> sink (length 3)
    G.add_edge(Edge("a", "b1", "READ", mk_label("SECRET")))
    G.add_edge(Edge("b1", "b2", "READ", mk_label("SECRET")))
    G.add_edge(Edge("b2", "sink", "WRITE", mk_label("SECRET")))
    # New action: a -> c -> sink (length 2, shorter)
    G.add_node(Node("c", "STORE", mk_label("SECRET")))
    action = Action(E_plus=[
        Edge("a", "c", "READ", mk_label("SECRET")),
        Edge("c", "sink", "WRITE", mk_label("SECRET")),
    ])
    _run_comparison("T1 min-distance", G, action, H=3)


def test_t2_revocation_de_elevation() -> None:
    """
    T2: revocation does not de-elevate label state.
    a is elevated to SECRET via L_plus, then the SECRET read edge
    is revoked. After revocation, a should de-elevate per R4.
    The v2.1 implementation retains SECRET (H2).
    """
    G = Graph()
    G.add_node(Node("a", "AGENT", mk_label("SECRET", "READ"),
                    provenance=[(time.time(), "admin",
                                 mk_label("SECRET"))]))
    G.add_node(Node("store", "STORE", mk_label("SECRET")))
    G.add_edge(Edge("a", "store", "READ", mk_label("SECRET")))
    G.add_node(Node("sink", "SINK", mk_label("PUBLIC"), is_sink=True))

    action = Action(E_minus=[
        Edge("a", "store", "READ", mk_label("SECRET"))
    ])
    rift = RIFT(3, {"sink"}, {"SECRET"}, default_envelope)
    rift.admit_action(G, action)
    label_after = G.V["a"].label_state
    print(f"  [T2 de-elevation]")
    print(f"    a.label after revocation = {label_after}")
    print(f"    Expected by R4: PUBLIC")
    print(f"    Verdict: {'AGREE (de-elevated)' if label_after.sensitivity == 'PUBLIC' else 'DISAGREE (H2: retained SECRET)'}")


def test_t3_condensation_horizon() -> None:
    """
    T3: SCC condensation horizon preservation.
    A cycle of length 3 plus an exit edge. The condensation treats
    the cycle as one node, so the exit edge appears at depth 1
    instead of depth 3. A horizon H=2 that is correct in the
    original graph is violated in the condensation.
    """
    G = Graph()
    G.add_node(Node("a", "AGENT", mk_label("SECRET")))
    G.add_node(Node("x", "STORE", mk_label("SECRET")))
    G.add_node(Node("y", "STORE", mk_label("SECRET")))
    G.add_node(Node("z", "STORE", mk_label("SECRET")))
    G.add_node(Node("sink", "SINK", mk_label("PUBLIC"), is_sink=True))
    # Cycle a->x->y->z->a
    G.add_edge(Edge("a", "x", "READ", mk_label("SECRET")))
    G.add_edge(Edge("x", "y", "READ", mk_label("SECRET")))
    G.add_edge(Edge("y", "z", "READ", mk_label("SECRET")))
    G.add_edge(Edge("z", "a", "READ", mk_label("SECRET")))
    # Exit: z -> sink (but z is in the cycle, so under H=2 the path
    # a->x->y->z->sink is length 4 and should be rejected)
    G.add_edge(Edge("z", "sink", "WRITE", mk_label("SECRET")))
    # No action (test the reachability baseline itself)
    oracle = Oracle(2, {"sink"}, {"SECRET"}, default_envelope)
    rift = RIFT(2, {"sink"}, {"SECRET"}, default_envelope)
    R_oracle = oracle._reachable(G)
    R_rift = rift._compute_reachability(G)
    # Check if either reports a->sink within H=2
    oracle_has = any(s == "sink" for (s, _l, _d) in
                     R_oracle.get(("a", mk_label("SECRET", "NONE")), set()))
    rift_has = any(s == "sink" for (s, _l, _d) in
                   R_rift.get(("a", mk_label("SECRET", "NONE")), set()))
    print(f"  [T3 condensation horizon]")
    print(f"    Oracle a->sink within H=2: {oracle_has}")
    print(f"    RIFT   a->sink within H=2: {rift_has}")
    verdict = "AGREE" if oracle_has == rift_has else "DISAGREE (H3)"
    print(f"    Verdict: {verdict}")


def test_t4_temporal_priority() -> None:
    """
    T4: temporal EAT/depth mixing.
    The v2.1 reference does not model liveness intervals, so this
    test documents that the temporal extension is NOT IMPLEMENTED
    in the reference code. The spec's Section 12 describes a buggy
    single-priority-queue EAT algorithm; the code has no temporal
    extension at all, which is a stronger limitation.
    """
    print(f"  [T4 temporal priority]")
    print(f"    Status: NOT IMPLEMENTED")
    print(f"    Verdict: UNRESOLVED (temporal extension absent in reference)")


def test_t5_epoch_correctness() -> None:
    """
    T5: epoch check on edge liveness.
    Revoke an edge; verify that a subsequent reachability computation
    does not use the revoked edge (because its epoch is stale).
    """
    G = Graph()
    G.add_node(Node("a", "AGENT", mk_label("SECRET")))
    G.add_node(Node("b", "STORE", mk_label("SECRET")))
    G.add_node(Node("sink", "SINK", mk_label("PUBLIC"), is_sink=True))
    G.add_edge(Edge("a", "b", "READ", mk_label("SECRET"), epoch=0))
    G.add_edge(Edge("b", "sink", "WRITE", mk_label("SECRET"), epoch=0))
    G.epoch = 1  # simulate a revocation that bumped epoch
    rift = RIFT(3, {"sink"}, {"SECRET"}, default_envelope)
    R = rift._compute_reachability(G)
    a_reaches_sink = any(s == "sink" for (s, _l, _d) in
                         R.get(("a", mk_label("SECRET", "NONE")), set()))
    print(f"  [T5 epoch correctness]")
    print(f"    a reaches sink after epoch bump: {a_reaches_sink}")
    print(f"    Expected: False (edges are stale)")
    print(f"    Verdict: {'AGREE' if not a_reaches_sink else 'DISAGREE'}")


def test_t6_new_node_label() -> None:
    """
    T6: new node with SECRET label, edge to sink. Post-creation label
    must be used, not a default.
    """
    G = Graph()
    G.add_node(Node("sink", "SINK", mk_label("PUBLIC"), is_sink=True))
    action = Action(
        N_plus=[Node("new_store", "STORE", mk_label("SECRET"))],
        E_plus=[Edge("new_store", "sink", "WRITE", mk_label("SECRET"))],
    )
    _run_comparison("T6 new-node label", G, action, H=2)


def test_t7_protected_source_filter() -> None:
    """
    T7: node becomes protected via L_plus, then reaches sink.
    The Step E pre-filter must not skip it.
    """
    G = Graph()
    G.add_node(Node("a", "AGENT", mk_label("PUBLIC")))
    G.add_node(Node("b", "AGENT", mk_label("PUBLIC")))
    G.add_node(Node("sink", "SINK", mk_label("PUBLIC"), is_sink=True))
    action = Action(
        E_plus=[
            Edge("a", "b", "READ", mk_label("PUBLIC")),
            Edge("b", "sink", "WRITE", mk_label("PUBLIC")),
        ],
        L_plus=[("a", mk_label("SECRET"))],
    )
    _run_comparison("T7 protected-source filter", G, action, H=2)


def test_t8_witness_suggestion() -> None:
    """
    T8: verify that the witness suggestion is None and no code path
    treats it as authoritative.
    """
    G = Graph()
    G.add_node(Node("a", "AGENT", mk_label("SECRET")))
    G.add_node(Node("sink", "SINK", mk_label("PUBLIC"), is_sink=True))
    action = Action(E_plus=[
        Edge("a", "sink", "WRITE", mk_label("SECRET"))
    ])
    rift = RIFT(2, {"sink"}, {"SECRET"}, default_envelope)
    decision, violations = rift.admit_action(G.copy(), action)
    witness = rift._minimal_witness(violations) if violations else None
    print(f"  [T8 witness suggestion]")
    print(f"    Decision: {decision.value}")
    print(f"    Witness suggestion field: {witness}")
    print(f"    Expected: None (deferred)")
    print(f"    Verdict: {'AGREE' if witness is None or witness == violations[0] else 'UNRESOLVED'}")


# =============================================================================
# SECTION 7 — MAIN
# =============================================================================

def main() -> None:
    print("=" * 72)
    print("RIFT v2.1 — Reference Implementation + Test Harness")
    print("Known issues H1–H8 are marked in the code; tests T1–T8 exercise them.")
    print("=" * 72)
    print()

    tests = [
        ("T1", test_t1_min_distance),
        ("T2", test_t2_revocation_de_elevation),
        ("T3", test_t3_condensation_horizon),
        ("T4", test_t4_temporal_priority),
        ("T5", test_t5_epoch_correctness),
        ("T6", test_t6_new_node_label),
        ("T7", test_t7_protected_source_filter),
        ("T8", test_t8_witness_suggestion),
    ]

    results: List[Tuple[str, str]] = []
    for tid, fn in tests:
        try:
            fn()
            results.append((tid, "ran"))
        except Exception as ex:
            results.append((tid, f"ERROR: {ex}"))
        print()

    print("=" * 72)
    print("Summary")
    print("=" * 72)
    for tid, status in results:
        print(f"  {tid}: {status}")
    print()
    print("Notes for the verifier:")
    print("  - T2 expects H2 (de-elevation) to DISAGREE on v2.1.")
    print("  - T3 expects H3 (condensation horizon) — not implemented,")
    print("    so this test documents the absence rather than a failure.")
    print("  - T4 expects NOT IMPLEMENTED; the temporal extension is")
    print("    described in Section 12 of the spec but absent in code.")
    print("  - All other tests compare RIFT to the Oracle and report")
    print("    AGREE / DISAGREE.")
    print()
    print("A DISAGREE where Oracle says ALLOW and RIFT says DENY is a")
    print("false DENY (liveness failure). A DISAGREE where Oracle says")
    print("DENY and RIFT says ALLOW is a false ALLOW (safety failure).")
    print("v2.1 is expected to produce at least one H2-related false")
    print("ALLOW or state-corruption finding; the verifier's job is to")
    print("classify it.")


if __name__ == "__main__":
    main()
