"""RIFT v2.1 legacy algorithm for blind adversarial code review.
This module is a research subject, not production-safe.
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
        # shorter path does not update the stored distance, which can
        # cause the horizon check to reject a path that should pass.
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
                                continue
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
        return min(violations, key=lambda v: v.distance)


# =============================================================================
