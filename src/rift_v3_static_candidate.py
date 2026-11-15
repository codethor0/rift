"""RIFT - Reach-Invariant Firewall for Trust.

Candidate v3.0 STATIC DATA-FLOW reference kernel (research code, not a product).
Python 3.10+, standard library only.

Normative mode CLEAN: admit iff the fully modeled candidate state has no
forbidden protected data flows. Optional NO_NEW mode is strictly weaker.

The finite, trusted graph encodes physically possible directed data flows.
A policy rule never deletes a physically possible edge from this graph.
No temporal channels, authority propagation, delegated privileges, purpose
constraints, information inference, remote atomicity, or automatic erasure
are claimed. Unsupported requested semantics return UNKNOWN, not ALLOW.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from enum import Enum, IntEnum
from threading import RLock
from typing import Optional


class Sensitivity(IntEnum):
    PUBLIC = 0
    INTERNAL = 1
    SECRET = 2


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"


class Contract(str, Enum):
    CLEAN = "CLEAN"      # The candidate contains no forbidden flows.
    NO_NEW = "NO_NEW"    # The candidate introduces no new forbidden triples.


@dataclass(frozen=True)
class Fact:
    id: str
    sensitivity: Sensitivity


@dataclass(frozen=True)
class Node:
    id: str
    held_facts: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Edge:
    id: str                 # Stable edge identity; parallel edges are allowed.
    src: str                # Direction is the possible DATA transfer direction.
    dst: str


@dataclass(frozen=True)
class Policy:
    protected_sinks: frozenset[str]
    allowed_exceptions: frozenset[tuple[str, str]] = frozenset()
    writers: frozenset[str] = frozenset({"security-admin"})
    policy_admins: frozenset[str] = frozenset({"security-admin"})
    min_protected: Sensitivity = Sensitivity.SECRET
    version: int = 0


@dataclass(frozen=True)
class State:
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]
    facts: tuple[Fact, ...]
    policy: Policy
    version: int = 0
    coverage_complete: bool = True  # Model claim supplied by the trusted TCB.


@dataclass(frozen=True)
class Action:
    expected_version: int
    nonce: str
    add_nodes: tuple[Node, ...] = ()
    add_edges: tuple[Edge, ...] = ()
    remove_edge_ids: tuple[str, ...] = ()
    add_facts: tuple[Fact, ...] = ()
    add_holdings: tuple[tuple[str, str], ...] = ()
    replace_policy: Optional[Policy] = None
    # Operations without certified semantics cannot silently disappear.
    remove_nodes: tuple[str, ...] = ()
    remove_holdings: tuple[tuple[str, str], ...] = ()
    requires_temporal: bool = False
    requires_delegation: bool = False


@dataclass(frozen=True)
class Witness:
    source: str
    fact: str
    sink: str
    path: tuple[str, ...]   # A shortest modeled path from source to sink.

    @property
    def key(self) -> tuple[str, str, str]:
        return self.source, self.fact, self.sink


@dataclass(frozen=True)
class Assessment:
    decision: Decision
    reason: str
    witnesses: tuple[Witness, ...] = ()
    candidate: Optional[State] = None
    old_bad_count: int = 0
    new_bad_count: int = 0


class InvalidModel(ValueError):
    pass


class UnsupportedModel(ValueError):
    pass


def _index_unique(items, title: str):
    result = {}
    for item in items:
        if not isinstance(item.id, str) or not item.id or item.id in result:
            raise InvalidModel(f"Missing or duplicate {title} id: {item.id!r}")
        result[item.id] = item
    return result


def validate_state(state: State) -> None:
    """Validate the finite closed-world model, NOT real-world completeness."""
    if not all(isinstance(x, tuple) for x in (state.nodes, state.edges, state.facts)):
        raise InvalidModel("State collections must be immutable tuples")
    if not all(isinstance(x, frozenset) for x in
               (state.policy.protected_sinks, state.policy.allowed_exceptions,
                state.policy.writers, state.policy.policy_admins)):
        raise InvalidModel("Policy sets must be immutable")
    nodes = _index_unique(state.nodes, "node")
    edges = _index_unique(state.edges, "edge")
    facts = _index_unique(state.facts, "fact")
    if state.version < 0 or state.policy.version < 0:
        raise InvalidModel("Negative version")
    if not state.policy.protected_sinks.issubset(nodes):
        raise InvalidModel("Unknown protected sink")
    for fact in facts.values():
        if not isinstance(fact.sensitivity, Sensitivity):
            raise InvalidModel("Unrecognized sensitivity")
    for node in nodes.values():
        if not isinstance(node.held_facts, frozenset):
            raise InvalidModel("Node holdings must be immutable")
        if not node.held_facts.issubset(facts):
            raise InvalidModel("Unknown fact in node holdings")
    for edge in edges.values():
        if edge.src not in nodes or edge.dst not in nodes:
            raise InvalidModel("Edge references unknown node")
    for fact_id, sink in state.policy.allowed_exceptions:
        if fact_id not in facts or sink not in state.policy.protected_sinks:
            raise InvalidModel("Invalid policy exception")
    if not isinstance(state.policy.min_protected, Sensitivity):
        raise InvalidModel("Invalid protection threshold")
    if not state.policy.policy_admins.issubset(state.policy.writers):
        raise InvalidModel("Policy admins must be writers")


def validate_action(action: Action) -> None:
    if not isinstance(action, Action):
        raise InvalidModel("Not a typed Action")
    if not isinstance(action.nonce, str) or not action.nonce:
        raise InvalidModel("Invalid transaction nonce")
    if not isinstance(action.expected_version, int) or action.expected_version < 0:
        raise InvalidModel("Invalid expected state version")
    for field_name in ("add_nodes", "add_edges", "remove_edge_ids", "add_facts",
                       "add_holdings", "remove_nodes", "remove_holdings"):
        if not isinstance(getattr(action, field_name), tuple):
            raise InvalidModel(f"Mutable action collection: {field_name}")


def construct_candidate(old: State, action: Action) -> State:
    """Pure state transition. No mutation of the committed old state."""
    validate_action(action)
    if action.remove_nodes or action.remove_holdings:
        raise UnsupportedModel("Deletion or declassification requires a separate model")
    if action.requires_temporal or action.requires_delegation:
        raise UnsupportedModel("Temporal/delegation semantics not implemented")
    nodes = _index_unique(old.nodes, "node")
    edges = _index_unique(old.edges, "edge")
    facts = _index_unique(old.facts, "fact")
    for edge_id in action.remove_edge_ids:
        if edge_id not in edges:
            raise InvalidModel(f"Cannot remove unknown edge {edge_id}")
        del edges[edge_id]
    for fact in action.add_facts:
        if fact.id in facts:
            raise InvalidModel("Fact id collision")
        facts[fact.id] = fact
    for node in action.add_nodes:
        if node.id in nodes:
            raise InvalidModel("Node id collision")
        nodes[node.id] = node
    for node_id, fact_id in action.add_holdings:
        if node_id not in nodes or fact_id not in facts:
            raise InvalidModel("Unknown node or fact in holdings update")
        n = nodes[node_id]
        nodes[node_id] = Node(n.id, n.held_facts | {fact_id})
    for edge in action.add_edges:
        if edge.id in edges:
            raise InvalidModel("Edge id collision")
        edges[edge.id] = edge
    new_policy = action.replace_policy or old.policy
    candidate = State(tuple(nodes.values()), tuple(edges.values()),
                      tuple(facts.values()), new_policy,
                      old.version + 1, old.coverage_complete)
    validate_state(candidate)
    return candidate


def forbidden_flows(state: State) -> dict[tuple[str, str, str], Witness]:
    """Exact BFS reach on a finite static DATA-flow multigraph.

    The source seeds are actual holdings, not every possible label.
    An edge is a potential flow, never removed due to authorization policy.
    Zero-hop occupancy at a protected sink counts as a forbidden flow.
    """
    validate_state(state)
    edges = {n.id: [] for n in state.nodes}
    for edge in state.edges:
        edges[edge.src].append(edge.dst)
    facts = {f.id: f for f in state.facts}
    bad = {}
    for origin in state.nodes:
        for fid in origin.held_facts:
            if facts[fid].sensitivity < state.policy.min_protected:
                continue
            queue = deque([(origin.id, (origin.id,))])
            visited = {origin.id}
            while queue:
                current, path = queue.popleft()
                if (current in state.policy.protected_sinks and
                        (fid, current) not in state.policy.allowed_exceptions):
                    w = Witness(origin.id, fid, current, path)
                    bad[w.key] = w
                for nxt in edges[current]:
                    if nxt not in visited:
                        visited.add(nxt)
                        queue.append((nxt, path + (nxt,)))
    return bad


def certify(old: State, action: Action, authenticated_principal: str,
            contract: Contract = Contract.CLEAN) -> Assessment:
    """Conditional modeled certification; actual identity proof is external."""
    try:
        validate_state(old)
        validate_action(action)
        if not old.coverage_complete:
            return Assessment(Decision.UNKNOWN, "Uncertified graph coverage")
        if action.expected_version != old.version:
            return Assessment(Decision.UNKNOWN, "Stale state version")
        if authenticated_principal not in old.policy.writers:
            return Assessment(Decision.DENY, "Mutation not authorized")
        if (action.replace_policy is not None and
                authenticated_principal not in old.policy.policy_admins):
            return Assessment(Decision.DENY, "Policy change not authorized")
        if (action.replace_policy is not None and
                action.replace_policy.version <= old.policy.version):
            return Assessment(Decision.DENY, "Policy version must increase")
        candidate = construct_candidate(old, action)
        old_bad = forbidden_flows(old)
        new_bad = forbidden_flows(candidate)
        if contract == Contract.CLEAN:
            failed = set(new_bad)
        elif contract == Contract.NO_NEW:
            failed = set(new_bad) - set(old_bad)
        else:
            return Assessment(Decision.UNKNOWN, "Unknown security contract")
        if failed:
            witnesses = tuple(new_bad[k] for k in sorted(failed))
            return Assessment(Decision.DENY, "Forbidden modeled data path",
                              witnesses, None, len(old_bad), len(new_bad))
        return Assessment(Decision.ALLOW, "Certified relative to static model",
                          (), candidate, len(old_bad), len(new_bad))
    except UnsupportedModel as exc:
        return Assessment(Decision.UNKNOWN, str(exc))
    except (InvalidModel, TypeError, KeyError, ValueError) as exc:
        return Assessment(Decision.DENY, f"Invalid input/model: {exc}")


class Monitor:
    """In-process serialized commit only; NO remote-effect atomicity claim."""

    def __init__(self, initial: State):
        validate_state(initial)
        self._state = initial
        self._used_nonces: set[str] = set()
        self._lock = RLock()

    @property
    def state(self) -> State:
        with self._lock:
            return self._state

    def submit(self, action: Action, authenticated_principal: str,
               contract: Contract = Contract.CLEAN) -> Assessment:
        with self._lock:
            try:
                validate_action(action)
            except InvalidModel as exc:
                return Assessment(Decision.DENY, f"Invalid action: {exc}")
            if action.nonce in self._used_nonces:
                return Assessment(Decision.UNKNOWN, "Replayed transaction nonce")
            outcome = certify(self._state, action, authenticated_principal,
                              contract)
            if outcome.decision == Decision.ALLOW:
                assert outcome.candidate is not None
                self._state = outcome.candidate
                self._used_nonces.add(action.nonce)
            return outcome


if __name__ == "__main__":
    p = Policy(frozenset({"external"}))
    s = State((Node("vault", frozenset({"secret1"})), Node("agent"),
               Node("external")), (), (Fact("secret1", Sensitivity.SECRET),), p)
    monitor = Monitor(s)
    a = Action(expected_version=0, nonce="demo1", add_edges=(
        Edge("read", "vault", "agent"), Edge("post", "agent", "external")))
    result = monitor.submit(a, "security-admin")
    print(result.decision.value, result.reason)
    for w in result.witnesses:
        print("witness:", " -> ".join(w.path), "fact:", w.fact)
