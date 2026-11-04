"""Full-information research replay, not IPS/DR estimation from deterministic production logs."""
from adaptive_waf.contracts import AttackClass
from adaptive_waf.runtime.routing import RoutingContext, labeled_reward


def validate_population(rows, role, forbidden_ids=(), forbidden_groups=()):
    seen=set()
    for row in rows:
        if row.get("population")!=role or row.get("label_source")!="VERIFIED":
            raise ValueError("replay requires explicitly separated populations and verified labels")
        identifier,group=row["request_id"],row["group_id"]
        if not identifier or not group or identifier in seen or identifier in forbidden_ids or group in forbidden_groups:
            raise ValueError("duplicate or overlapping request/application-template-session group")
        seen.add(identifier)
        AttackClass(row["expected"])
        RoutingContext(**row["pre_action_context"]).vector()
        if not row["outcomes"]:
            raise ValueError("measured route outcomes required")
        for outcome in row["outcomes"].values():
            AttackClass(outcome["predicted"])
            labeled_reward(row["expected"],outcome["predicted"],outcome["latency_ms"],outcome["compute_cost"])


def replay(rows, policy, learn=False, constrained=True,deadline=None):
    records=[]
    for row in rows:
        if deadline is not None:
            from time import monotonic
            if monotonic()>deadline:raise ValueError('offline replay time budget reached')
        context=RoutingContext(**row["pre_action_context"])
        action,propensities=policy.select(context,row["outcomes"],conservative=constrained)
        outcome=row["outcomes"][action]
        reward=labeled_reward(row["expected"],outcome["predicted"],outcome["latency_ms"],outcome["compute_cost"])
        if learn:
            policy.update(context,action,reward,"VERIFIED")
        records.append({"request_id":row["request_id"],"expected":row["expected"],"route":action,"outcome":outcome,
            "reward":reward,"propensities":propensities})
    return records
