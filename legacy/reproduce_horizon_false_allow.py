"""Reproduce a known unsafe ALLOW in the legacy H-bounded algorithm.

This is a negative research demonstration. It is not a security test of the
correctness-first static candidate or an implementation of a protected effect.
"""
from rift_v21_phase_a import (
    Action, Decision, Edge, Graph, Label, Node, RIFT, default_envelope,
)


def main():
    graph = Graph()
    graph.add_node(Node("secret_origin", "AGENT", Label("SECRET", "NONE")))
    graph.add_node(Node("external", "SINK", Label("PUBLIC", "NONE"), is_sink=True))
    direct = Action(E_plus=[
        Edge("secret_origin", "external", "WRITE", Label("SECRET", "NONE")),
    ])
    outcome, _ = RIFT(1, {"external"}, {"SECRET"}, default_envelope).admit_action(graph, direct)
    print("Declared horizon: 1 hop")
    print("Proposed edge: secret_origin -> external (1 hop)")
    print("Expected safe decision: DENY")
    print("Observed legacy decision:", outcome.value)
    if outcome == Decision.ALLOW:
        print("CONFIRMED: legacy algorithm permits a forbidden modeled one-hop flow")
        return 0
    print("NOT REPRODUCED: inspect code and test assumptions")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
