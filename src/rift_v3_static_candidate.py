"""RIFT - Reach-Invariant Firewall for Trust.

Candidate v3.1 STATIC DATA-FLOW reference kernel (research code, not a product).
Python 3.10+, standard library only.

Normative mode CLEAN: admit iff the fully modeled candidate state has no
forbidden protected data flows. Optional NO_NEW mode is strictly weaker.

The finite, trusted graph encodes physically possible directed data flows.
A policy rule never deletes a physically possible edge from this graph.
No temporal channels, authority propagation, delegated privileges, purpose
constraints, information inference, remote atomicity, or automatic erasure
are claimed. Edge deletion is deliberately UNSUPPORTED until historical
may-have-held information is modeled, so it returns UNKNOWN. This conservative
restriction preserves modeled CLEAN safety across allowed graph additions,
subject to a complete graph and trusted mediation of real-world effects.
Unsupported requested semantics return UNKNOWN, not ALLOW.
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


def _valid_id(value: object, title: str) -> None:
    if type(value) is not str or not value:
        raise InvalidModel(f"Invalid {title} identifier: {value!r}")


def _nonnegative_int(value: object, title: str) -> None:
    # bool, float('nan'), and arbitrary int subclasses are not version values.
    if type(value) is not int or value < 0:
        raise InvalidModel(f"Invalid {title}: {value!r}")


def _index_unique(items: tuple, title: str, item_type: type):
    result = {}
    for item in items:
        if type(item) is not item_type:
            raise InvalidModel(f"Invalid {title} object type")
        _valid_id(item.id, title)
        if item.id in result:
            raise InvalidModel(f"Duplicate {title} id: {item.id!r}")
        result[item.id] = item
    return result


def _check_node(node: Node) -> None:
    if type(node) is not Node:
        raise InvalidModel("Invalid node object type")
    _valid_id(node.id, "node")
    if type(node.held_facts) is not frozenset:
        raise InvalidModel("Node holdings must be an exact frozenset")
    for fid in node.held_facts:
        _valid_id(fid, "held fact")


def _check_fact(fact: Fact) -> None:
    if type(fact) is not Fact:
        raise InvalidModel("Invalid fact object type")
    _valid_id(fact.id, "fact")
    if type(fact.sensitivity) is not Sensitivity:
        raise InvalidModel("Unrecognized sensitivity")


def _check_edge(edge: Edge) -> None:
    if type(edge) is not Edge:
        raise InvalidModel("Invalid edge object type")
    for title, ident in (("edge", edge.id), ("source node", edge.src),
                         ("destination node", edge.dst)):
        _valid_id(ident, title)


def _check_policy_shapes(policy: Policy) -> None:
    if type(policy) is not Policy:
        raise InvalidModel("Invalid policy object type")
    for name in ("protected_sinks", "allowed_exceptions", "writers", "policy_admins"):
        if type(getattr(policy, name)) is not frozenset:
            raise InvalidModel(f"Policy {name} must be an exact frozenset")
    for name in ("protected_sinks", "writers", "policy_admins"):
        for ident in getattr(policy, name):
            _valid_id(ident, name)
    for exception in policy.allowed_exceptions:
        if type(exception) is not tuple or len(exception) != 2:
            raise InvalidModel("Invalid policy exception shape")
        _valid_id(exception[0], "exception fact")
        _valid_id(exception[1], "exception sink")
    _nonnegative_int(policy.version, "policy version")
    if type(policy.min_protected) is not Sensitivity:
        raise InvalidModel("Invalid protection threshold")
    if not policy.policy_admins.issubset(policy.writers):
        raise InvalidModel("Policy admins must be writers")


def validate_state(state: State) -> None:
    """Check a finite closed-world model, NOT real-world graph completeness.

    Exact built-in types exclude adversarial containers that misreport items,
    and prevent floats, NaNs, boolean versions, or truthy coverage strings.
    Python in-process hostile object mutation is outside the security boundary.
    """
    if type(state) is not State:
        raise InvalidModel("Not a typed State")
    if any(type(x) is not tuple for x in (state.nodes, state.edges, state.facts)):
        raise InvalidModel("State collections must be exact immutable tuples")
    _nonnegative_int(state.version, "state version")
    if type(state.coverage_complete) is not bool:
        raise InvalidModel("Coverage must be an exact boolean")
    _check_policy_shapes(state.policy)
    nodes = _index_unique(state.nodes, "node", Node)
    edges = _index_unique(state.edges, "edge", Edge)
    facts = _index_unique(state.facts, "fact", Fact)
    for fact in facts.values():
        _check_fact(fact)
    for node in nodes.values():
        _check_node(node)
        if not node.held_facts.issubset(facts):
            raise InvalidModel("Unknown fact in node holdings")
    for edge in edges.values():
        _check_edge(edge)
        if edge.src not in nodes or edge.dst not in nodes:
            raise InvalidModel("Edge references unknown node")
    if not state.policy.protected_sinks.issubset(nodes):
        raise InvalidModel("Unknown protected sink")
    for fact_id, sink in state.policy.allowed_exceptions:
        if fact_id not in facts or sink not in state.policy.protected_sinks:
            raise InvalidModel("Invalid policy exception")


def validate_action(action: Action) -> None:
    if type(action) is not Action:
        raise InvalidModel("Not a typed Action")
    _valid_id(action.nonce, "transaction nonce")
    _nonnegative_int(action.expected_version, "expected state version")
    for field_name in ("add_nodes", "add_edges", "remove_edge_ids", "add_facts",
                       "add_holdings", "remove_nodes", "remove_holdings"):
        if type(getattr(action, field_name)) is not tuple:
            raise InvalidModel(f"Mutable or invalid action collection: {field_name}")
    for node in action.add_nodes:
        _check_node(node)
    for edge in action.add_edges:
        _check_edge(edge)
    for fact in action.add_facts:
        _check_fact(fact)
    for ident in (*action.remove_edge_ids, *action.remove_nodes):
        _valid_id(ident, "removed object")
    for pair in (*action.add_holdings, *action.remove_holdings):
        if type(pair) is not tuple or len(pair) != 2:
            raise InvalidModel("Malformed holding update")
        _valid_id(pair[0], "holding node")
        _valid_id(pair[1], "holding fact")
    if action.replace_policy is not None:
        _check_policy_shapes(action.replace_policy)
    if type(action.requires_temporal) is not bool or type(action.requires_delegation) is not bool:
        raise InvalidModel("Invalid semantic capability flags")


def construct_candidate(old: State, action: Action) -> State:
    """Pure state transition. No mutation of the committed old state."""
    validate_action(action)
    if action.remove_edge_ids:
        # F1 containment: edge disappearance cannot erase historical knowledge.
        # Persistent may-have-held closure and certified purge need a separate model.
        raise UnsupportedModel("Edge removal requires historical information-flow tracking")
    if action.remove_nodes or action.remove_holdings:
        raise UnsupportedModel("Deletion or declassification requires a separate model")
    if action.requires_temporal or action.requires_delegation:
        raise UnsupportedModel("Temporal/delegation semantics not implemented")
    nodes = _index_unique(old.nodes, "node", Node)
    edges = _index_unique(old.edges, "edge", Edge)
    facts = _index_unique(old.facts, "fact", Fact)
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
            queue = deque([origin.id])
            parent: dict[str, Optional[str]] = {origin.id: None}
            while queue:
                current = queue.popleft()
                if (current in state.policy.protected_sinks and
                        (fid, current) not in state.policy.allowed_exceptions):
                    path = []
                    cursor: Optional[str] = current
                    while cursor is not None:
                        path.append(cursor)
                        cursor = parent[cursor]
                    w = Witness(origin.id, fid, current, tuple(reversed(path)))
                    bad[w.key] = w
                for nxt in edges[current]:
                    if nxt not in parent:
                        parent[nxt] = current
                        queue.append(nxt)
    return bad


def certify(old: State, action: Action, authenticated_principal: str,
            contract: Contract = Contract.CLEAN) -> Assessment:
    """Conditional modeled certification; actual identity proof is external."""
    try:
        validate_state(old)
        validate_action(action)
        if type(authenticated_principal) is not str or not authenticated_principal:
            return Assessment(Decision.DENY, "Invalid principal")
        # Authorization precedes version and coverage checks to avoid leaking
        # internal state from their ordering to unauthenticated principals.
        if authenticated_principal not in old.policy.writers:
            return Assessment(Decision.DENY, "Mutation not authorized")
        if (action.replace_policy is not None or action.add_facts) and \
                authenticated_principal not in old.policy.policy_admins:
            return Assessment(Decision.DENY, "Policy or fact metadata change not authorized")
        if not old.coverage_complete:
            return Assessment(Decision.UNKNOWN, "Uncertified graph coverage")
        if action.expected_version != old.version:
            return Assessment(Decision.UNKNOWN, "Stale state version")
        if (action.replace_policy is not None and
                action.replace_policy.version <= old.policy.version):
            return Assessment(Decision.DENY, "Policy version must increase")
        candidate = construct_candidate(old, action)
        old_bad = forbidden_flows(old)
        new_bad = forbidden_flows(candidate)
        if type(contract) is not Contract:
            return Assessment(Decision.UNKNOWN, "Unknown security contract")
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
    except (InvalidModel, TypeError, KeyError, ValueError, AttributeError) as exc:
        return Assessment(Decision.DENY, f"Invalid input/model: {exc}")


def _snapshot_state(state: State) -> State:
    """Copy model objects to avoid returning aliases of the monitor's TCB data.

    This does not make hostile in-process Python bytecode a supported adversary.
    """
    validate_state(state)
    p = state.policy
    return State(
        nodes=tuple(Node(n.id, frozenset(n.held_facts)) for n in state.nodes),
        edges=tuple(Edge(e.id, e.src, e.dst) for e in state.edges),
        facts=tuple(Fact(f.id, f.sensitivity) for f in state.facts),
        policy=Policy(frozenset(p.protected_sinks),
                      frozenset(tuple(pair) for pair in p.allowed_exceptions),
                      frozenset(p.writers), frozenset(p.policy_admins),
                      p.min_protected, p.version),
        version=state.version,
        coverage_complete=state.coverage_complete,
    )


class Monitor:
    """In-process serialized commit only; NO remote-effect atomicity claim.

    A known dirty initial state is rejected under the monitor's CLEAN baseline.
    Direct certification can still inspect dirty legacy states, but edge deletion
    is not available as an unproven declassification/purge procedure.
    """

    def __init__(self, initial: State):
        initial = _snapshot_state(initial)
        if forbidden_flows(initial):
            raise InvalidModel("Initial state has forbidden flows; CLEAN baseline required")
        self._state = initial
        self._used_nonces: set[str] = set()
        self._lock = RLock()

    @property
    def state(self) -> State:
        with self._lock:
            return _snapshot_state(self._state)

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
                self._state = _snapshot_state(outcome.candidate)
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
