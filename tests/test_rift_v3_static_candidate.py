"""Executable static-model tests and structurally independent DFS oracle.

Run from this directory:
  python -m unittest -v test_rift_v3_static_candidate.py
"""
import itertools
import math
import unittest
from concurrent.futures import ThreadPoolExecutor

from rift_v3_static_candidate import (
    Action, Contract, Decision, Edge, Fact, Monitor, Node, Policy,
    Sensitivity, State, certify, construct_candidate, forbidden_flows,
    InvalidModel, UnsupportedModel,
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

    def test_revoking_read_edge_requires_history_model(self):
        s = make_state(edges=(("vault", "agent"),), holders=("vault", "agent"))
        remove = Action(0, "r1", remove_edge_ids=("e0",))
        result = certify(s, remove, "admin")
        self.assertEqual(result.decision, Decision.UNKNOWN)
        self.assertEqual(s.version, 0)

    def test_unrelated_revocation_requires_history_model(self):
        s = make_state(names=("vault", "agent", "outside", "a", "b"),
                       edges=(("vault", "agent"), ("a", "b")))
        a = Action(0, "r3", remove_edge_ids=("e1",),
                   add_edges=(Edge("x", "agent", "outside"),))
        self.assertEqual(certify(s, a, "admin").decision, Decision.UNKNOWN)

    def test_policy_change_recognition(self):
        s = make_state(edges=(("vault", "outside"),),
                       exceptions=(("f", "outside"),))
        restrictive = Policy(frozenset({"outside"}),
                             writers=frozenset({"admin"}),
                             policy_admins=frozenset({"admin"}), version=1)
        a = Action(0, "p1", replace_policy=restrictive)
        self.assertEqual(certify(s, a, "admin").decision, Decision.DENY)

    def test_dirty_state_cannot_be_cleaned_by_unproven_edge_removal(self):
        s = make_state(edges=(("vault", "outside"),))
        a = Action(0, "fix", remove_edge_ids=("e0",))
        self.assertEqual(certify(s, a, "admin").decision, Decision.UNKNOWN)
        with self.assertRaises(InvalidModel):
            Monitor(s)

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
        with self.assertRaises(UnsupportedModel):
            construct_candidate(s, remove)

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

    def test_no_historical_erasure_across_approved_actions(self):
        m = Monitor(make_state())
        a = Action(0, "step1", add_edges=(Edge("read", "vault", "agent"),))
        self.assertEqual(m.submit(a, "admin").decision, Decision.ALLOW)
        remove = Action(1, "step2", remove_edge_ids=("read",))
        self.assertEqual(m.submit(remove, "admin").decision, Decision.UNKNOWN)
        self.assertEqual(m.state.version, 1)
        post = Action(1, "step3", add_edges=(Edge("post", "agent", "outside"),))
        self.assertEqual(m.submit(post, "admin").decision, Decision.DENY)
        self.assertEqual(m.state.version, 1)
        batch = Action(1, "batch", remove_edge_ids=("read",),
                       add_edges=(Edge("post", "agent", "outside"),))
        self.assertEqual(m.submit(batch, "admin").decision, Decision.UNKNOWN)

    def test_reject_container_subclass_with_hidden_holdings(self):
        class UntrustworthySet(frozenset):
            def __iter__(self):
                return iter(())

        s = make_state()
        n = Node("vault", UntrustworthySet({"f"}))
        evil = State((n, *s.nodes[1:]), s.edges, s.facts, s.policy)
        self.assertEqual(certify(evil, Action(0, "hidden"), "admin").decision,
                         Decision.DENY)

    def test_reject_mutable_lookalike_objects(self):
        class ForeignNode(Node):
            pass

        s = make_state()
        evil = State((ForeignNode("vault", frozenset({"f"})), *s.nodes[1:]),
                     s.edges, s.facts, s.policy)
        self.assertEqual(certify(evil, Action(0, "lookalike"), "admin").decision,
                         Decision.DENY)
        self.assertEqual(certify(s, Action(0, "bad-list", add_nodes=[Node("x")]), "admin").decision,
                         Decision.DENY)

    def test_monitor_does_not_expose_storage_aliases(self):
        s = make_state()
        m = Monitor(s)
        object.__setattr__(s.nodes[0], "held_facts", frozenset())
        self.assertIn("f", m.state.nodes[0].held_facts)
        exposed = m.state
        object.__setattr__(exposed.nodes[0], "held_facts", frozenset())
        self.assertIn("f", m.state.nodes[0].held_facts)
        outcome = m.submit(Action(0, "alice", add_edges=(Edge("x", "vault", "agent"),)), "admin")
        self.assertEqual(outcome.decision, Decision.ALLOW)
        object.__setattr__(outcome.candidate.nodes[0], "held_facts", frozenset())
        self.assertIn("f", m.state.nodes[0].held_facts)

    def test_malformed_action_shapes_denied_without_exceptions(self):
        s = make_state()
        bads = (
            Action(0, "x", add_holdings=("not-pair",)),
            Action(0, "x", add_holdings=(("vault",),)),
            Action(0, "x", add_nodes=(None,)),
            Action(0, "x", add_edges=(object(),)),
            Action(0, "x", remove_edge_ids=(1,)),
            Action(0, "x", requires_temporal="no"),
            Action(False, "x"),
        )
        for a in bads:
            with self.subTest(action=repr(a)):
                self.assertEqual(certify(s, a, "admin").decision, Decision.DENY)
                self.assertEqual(Monitor(s).submit(a, "admin").decision, Decision.DENY)

    def test_reject_float_and_nan_versions(self):
        s = make_state()
        for v in (float('nan'), 0.0, True):
            p = Policy(s.policy.protected_sinks, s.policy.allowed_exceptions,
                       s.policy.writers, s.policy.policy_admins,
                       s.policy.min_protected, v)
            bad = State(s.nodes, s.edges, s.facts, p)
            self.assertEqual(certify(bad, Action(0, "v"), "admin").decision,
                             Decision.DENY)
            self.assertEqual(certify(s, Action(v, "a"), "admin").decision,
                             Decision.DENY)
        self.assertEqual(certify(s, Action(0, "p", replace_policy=Policy(
            frozenset({"outside"}), version=math.nan)), "admin").decision,
            Decision.DENY)

    def test_reject_truthy_coverage_string(self):
        s = make_state(coverage="False")
        self.assertEqual(certify(s, Action(0, "coverage"), "admin").decision,
                         Decision.DENY)

    def test_fact_label_creation_requires_policy_admin(self):
        s = make_state()
        p = Policy(frozenset({"outside"}), writers=frozenset({"writer", "admin"}),
                   policy_admins=frozenset({"admin"}))
        s = State(s.nodes, s.edges, s.facts, p)
        act = Action(0, "add-public", add_facts=(Fact("new", Sensitivity.PUBLIC),))
        self.assertEqual(certify(s, act, "writer").decision, Decision.DENY)
        self.assertEqual(certify(s, act, "admin").decision, Decision.ALLOW)
        self.assertEqual(certify(s, Action(0, "edge", add_edges=(
            Edge("x", "vault", "agent"),)), "writer").decision, Decision.ALLOW)

    def test_unauthorized_principal_does_not_see_coverage_or_version(self):
        s = make_state(version=4, coverage=False)
        result = certify(s, Action(0, "unauth"), "outsider")
        self.assertEqual(result.decision, Decision.DENY)
        self.assertIn("not authorized", result.reason)

    def test_long_chain_shortest_witness_and_no_quadratic_path_copies(self):
        n = 1600
        names = tuple(f"n{i}" for i in range(n))
        edges = tuple(Edge(f"e{i}", names[i], names[i+1]) for i in range(n-1))
        nodes = tuple(Node(name, frozenset({"f"}) if i == 0 else frozenset())
                      for i, name in enumerate(names))
        s = State(nodes, edges, (Fact("f", Sensitivity.SECRET),),
                  Policy(frozenset({names[-1]})))
        bad = forbidden_flows(s)
        self.assertEqual(len(bad), 1)
        self.assertEqual(len(next(iter(bad.values())).path), n)

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
