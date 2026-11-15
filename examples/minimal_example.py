from rift_v3_static_candidate import *
p = Policy(frozenset({'external'}))
s = State((Node('vault', frozenset({'f'})),
           Node('agent'), Node('external')),
          (), (Fact('f', Sensitivity.SECRET),), p)
m = Monitor(s)
print(m.submit(Action(0, 'a', add_edges=(
    Edge('read', 'vault', 'agent'),)), 'security-admin').decision.value)
print(m.submit(Action(1, 'b', add_edges=(
    Edge('send', 'agent', 'external'),)), 'security-admin').decision.value)
print(m.submit(Action(1, 'c', remove_edge_ids=('read',)),
               'security-admin').decision.value)
# ALLOW, DENY, UNKNOWN
