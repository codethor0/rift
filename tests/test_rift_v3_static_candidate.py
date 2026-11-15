"""Executable static-model tests and structurally independent DFS oracle.

Run from this directory:
  python -m unittest -v test_rift_v3_static_candidate.py
"""
import itertools
import unittest
from concurrent.futures import ThreadPoolExecutor

from rift_v3_static_candidate import (
    Action, Contract, Decision, Edge, Fact, Monitor, Node, Policy,
    Sensitivity, State, certify, construct_candidate, forbidden_flows,
)


def oracle_bad(state):
    """Independent simple-path enumeration; does NOT call RIFT's BFS.

    Proof obligation: any directed path admits a simple subpath to the same
    destination, so no forbidden pair is lost by excluding repeated nodes.
    """
    neighbors = {}
    for e in state.edges:
        neighbors.setdefault(e.src, []).append(e.dst)
    facts = {f.id: f for f in state.facts}
    output = set()
    for node in state.nodes:
        for fid in node.held_facts:
            if facts[fid].sensitivity < state.policy.min_protected:
                continue
            stack = [(node.id, frozenset({node.id}))]
            while stack:
                at, visited = stack.pop()
                if at in state.policy.protected_sinks:
                    if (fid, at) not in state.policy.allowed_exceptions:
                        output.add((node.id, fid, at))
                for next_node in neighbors.get(at, ()):
                    if next_node not in visited:
                        stack.append((next_node, visited | {next_node}))
    return output


def make_state(*, names=("vault", "agent", "outside"), edges=(),
               holders=("vault",), sinks=("outside",),
               exceptions=(), admin="admin", version=0, coverage=True):
    nodes = tuple(Node(n, frozenset({"f"}) if n in holders else frozenset())
                  for n in names)
    edge_objs = tuple(Edge(f"e{i}", x, y) for i, (x, y) in enumerate(edges))
    policy = Policy(frozenset(sinks), frozenset(exceptions),
                    frozenset({admin}), frozenset({admin}))
    return State(nodes, edge_objs, (Fact("f", Sensitivity.SECRET),),
                 policy, version, coverage)


class CoreTests(unittest.TestCase):
    def test_benign_edge_admitted(self):
        s = make_state()
        x = certify(s, Action(0, "b1", add_edges=(Edge("x", "vault", "agent"),)), "admin")
        self.assertEqual(x.decision, Decision.ALLOW)
        self.assertEqual(s.edges, ())
        self.assertEqual(len(x.candidate.edges), 1)

    def test_direct_secret_exposure_denied(self):
        s = make_state()
        x = certify(s, Action(0, "d1", add_edges=(Edge("x", "vault", "outside"),)), "admin")
        self.assertEqual(x.decision, Decision.DENY)
        self.assertEqual(x.witnesses[0].path, ("vault", "outside"))

    def test_multi_edge_batch_exposure_denied(self):
        s = make_state()
        act = Action(0, "d2", add_edges=(Edge("a", "vault", "agent"),
                                          Edge("b", "agent", "outside")))
        self.assertEqual(certify(s, act, "admin").decision, Decision.DENY)

    def test_new_holding_existing_external_path_denied(self):
        s = make_state(edges=(("agent", "outside"),), holders=())
        a = Action(0, "h1", add_holdings=(("agent", "f"),))
        self.assertEqual(certify(s, a, "admin").decision, Decision.DENY)

    def test_revoking_read_edge_does_not_remove_taint(self):
        s = make_state(edges=(("vault", "agent"),), holders=("vault", "agent"))
        remove = Action(0, "r1", remove_edge_ids=("e0",))
        result = certify(s, remove, "admin")
        self.assertEqual(result.decision, Decision.ALLOW)
        self.assertIn("f", next(n for n in result.candidate.nodes if n.id == "agent").held_facts)
        after = result.candidate
        attempt = Action(1, "r2", add_edges=(Edge("z", "agent", "outside"),))
        self.assertEqual(certify(after, attempt, "admin").decision, Decision.DENY)

    def test_unrelated_revocation_preserves_other_edges(self):
        s = make_state(names=("vault", "agent", "outside", "a", "b"),
                       edges=(("vault", "agent"), ("a", "b")))
        a = Action(0, "r3", remove_edge_ids=("e1",),
                   add_edges=(Edge("x", "agent", "outside"),))
        self.assertEqual(certify(s, a, "admin").decision, Decision.DENY)

    def test_policy_change_recognition(self):
        s = make_state(edges=(("vault", "outside"),),
                       exceptions=(("f", "outside"),))
        restrictive = Policy(frozenset({"outside"}),
                             writers=frozenset({"admin"}),
                             policy_admins=frozenset({"admin"}), version=1)
        a = Action(0, "p1", replace_policy=restrictive)
        self.assertEqual(certify(s, a, "admin").decision, Decision.DENY)

    def test_clean_state_remediation(self):
        s = make_state(edges=(("vault", "outside"),))
        a = Action(0, "fix", remove_edge_ids=("e0",))
        self.assertEqual(certify(s, a, "admin").decision, Decision.ALLOW)

    def test_contracts_are_distinct(self):
        s = make_state(edges=(("vault", "outside"),))
        a = Action(0, "noop")
        self.assertEqual(certify(s, a, "admin", Contract.CLEAN).decision,
                         Decision.DENY)
        self.assertEqual(certify(s, a, "admin", Contract.NO_NEW).decision,
                         Decision.ALLOW)

    def test_new_node_with_secret(self):
        s = make_state()
        a = Action(0, "n1", add_nodes=(Node("new", frozenset({"f"})),),
                   add_edges=(Edge("x", "new", "outside"),))
        self.assertEqual(certify(s, a, "admin").decision, Decision.DENY)

    def test_actual_source_seeds_only(self):
        s = make_state(holders=(), edges=(("vault", "outside"),))
        self.assertEqual(forbidden_flows(s), {})

    def test_allow_explicit_exception(self):
        s = make_state(exceptions=(("f", "outside"),))
        a = Action(0, "ex", add_edges=(Edge("x", "vault", "outside"),))
        self.assertEqual(certify(s, a, "admin").decision, Decision.ALLOW)

    def test_zero_hop_occupancy_is_forbidden(self):
        s = make_state(holders=("outside",))
        self.assertEqual(len(forbidden_flows(s)), 1)

    def test_cycles_and_parallel_edges(self):
        s = make_state(edges=(("vault", "agent"), ("agent", "vault"),
                              ("vault", "agent")))
        a = Action(0, "cy", add_edges=(Edge("x", "agent", "outside"),))
        self.assertEqual(certify(s, a, "admin").decision, Decision.DENY)
        remove = Action(0, "pa", remove_edge_ids=("e0",))
        after = construct_candidate(s, remove)
        self.assertEqual(len([e for e in after.edges if e.src == "vault" and e.dst == "agent"]), 1)

    def test_unmodeled_temporal_is_unknown(self):
        s = make_state()
        a = Action(0, "time", requires_temporal=True)
        self.assertEqual(certify(s, a, "admin").decision, Decision.UNKNOWN)

    def test_unmodeled_delegation_is_unknown(self):
        s = make_state()
        a = Action(0, "deleg", requires_delegation=True)
        self.assertEqual(certify(s, a, "admin").decision, Decision.UNKNOWN)

    def test_disallowed_data_erasure_is_unknown(self):
        s = make_state()
        a = Action(0, "erase", remove_holdings=(("vault", "f"),))
        self.assertEqual(certify(s, a, "admin").decision, Decision.UNKNOWN)

    def test_incomplete_coverage_is_unknown(self):
        s = make_state(coverage=False)
        self.assertEqual(certify(s, Action(0, "uc"), "admin").decision, Decision.UNKNOWN)

    def test_unauthorized_actor_denied(self):
        s = make_state()
        self.assertEqual(certify(s, Action(0, "auth"), "untrusted").decision,
                         Decision.DENY)

    def test_stale_graph_version_is_unknown(self):
        s = make_state(version=2)
        self.assertEqual(certify(s, Action(0, "stale"), "admin").decision,
                         Decision.UNKNOWN)

    def test_failed_transaction_does_not_mutate(self):
        s = make_state()
        m = Monitor(s)
        act = Action(0, "rollback", add_edges=(Edge("x", "vault", "outside"),))
        self.assertEqual(m.submit(act, "admin").decision, Decision.DENY)
        self.assertEqual(m.state, s)

    def test_nonce_replay_does_not_double_commit(self):
        m = Monitor(make_state())
        a = Action(0, "same", add_edges=(Edge("x", "vault", "agent"),))
        self.assertEqual(m.submit(a, "admin").decision, Decision.ALLOW)
        self.assertEqual(m.submit(a, "admin").decision, Decision.UNKNOWN)
        self.assertEqual(len(m.state.edges), 1)

    def test_single_process_version_serialization(self):
        m = Monitor(make_state())
        a1 = Action(0, "one", add_edges=(Edge("x", "vault", "agent"),))
        a2 = Action(0, "two", add_edges=(Edge("y", "agent", "vault"),))
        with ThreadPoolExecutor(max_workers=2) as pool:
            x = list(pool.map(lambda a: m.submit(a, "admin"), (a1, a2)))
        self.assertEqual(sorted(r.decision for r in x),
                         sorted((Decision.ALLOW, Decision.UNKNOWN)))
        self.assertEqual(m.state.version, 1)

    def test_invalid_reference_fails_closed(self):
        s = make_state()
        a = Action(0, "bad", add_edges=(Edge("x", "missing", "outside"),))
        self.assertEqual(certify(s, a, "admin").decision, Decision.DENY)

    def test_malformed_action_nonce_fails_closed(self):
        m = Monitor(make_state())
        a = Action(0, ["not-hashable"])
        result = m.submit(a, "admin")
        self.assertEqual(result.decision, Decision.DENY)
        self.assertEqual(m.state.version, 0)

    def test_mutable_action_sequence_is_rejected(self):
        s = make_state()
        a = Action(0, "mut", add_edges=[Edge("x", "vault", "outside")])
        self.assertEqual(certify(s, a, "admin").decision, Decision.DENY)

    def test_independent_dfs_oracle_complete_small(self):
        names = ("A", "B", "C")
        all_possible_edges = tuple(itertools.permutations(names, 2))
        state_count = 0
        action_count = 0
        for edge_mask in range(1 << len(all_possible_edges)):
            pairs = tuple(e for i, e in enumerate(all_possible_edges)
                          if edge_mask & (1 << i))
            for holding_mask in range(1 << len(names)):
                holdings = tuple(n for i, n in enumerate(names)
                                 if holding_mask & (1 << i))
                s = make_state(names=names, edges=pairs, holders=holdings,
                               sinks=("C",))
                bad = set(forbidden_flows(s))
                self.assertEqual(bad, oracle_bad(s))
                state_count += 1
                for x, y in all_possible_edges:
                    # Add one parallel or new edge; oracle recomputes from scratch.
                    a = Action(0, f"add-{x}-{y}", add_edges=(Edge("new", x, y),))
                    candidate = construct_candidate(s, a)
                    oracle_expected = not oracle_bad(candidate)
                    actual = certify(s, a, "admin", Contract.CLEAN)
                    self.assertEqual(actual.decision == Decision.ALLOW,
                                     oracle_expected,
                                     (pairs, holdings, x, y))
                    action_count += 1
        print(f"  Exhaustively checked {state_count} static states and "
              f"{action_count} single-edge proposals")


if __name__ == "__main__":
    unittest.main(verbosity=2)
