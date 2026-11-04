import json
import unittest
from adaptive_waf.runtime.routing import LinUCB,RoutingContext
from adaptive_waf.runtime.replay import replay,validate_population


class RoutingReplayTests(unittest.TestCase):
    def row(self):
        return {"request_id":"dev-1","group_id":"app-a/template-a/session-a","population":"development","label_source":"VERIFIED",
            "expected":"XSS","pre_action_context":{"fast_risk":.8,"entropy":.8,"margin":.1},
            "outcomes":{"FAST_ONLY":{"predicted":"BENIGN","latency_ms":1,"compute_cost":.01},
                "BOTH":{"predicted":"XSS","latency_ms":2,"compute_cost":.02}}}

    def test_constrained_full_information_replay_and_serialization(self):
        row=self.row()
        validate_population([row],"development")
        policy=LinUCB(seed=641)
        records=replay([row],policy,learn=True)
        self.assertEqual(records[0]["route"],"BOTH")
        state=json.loads(json.dumps(policy.state(),allow_nan=False))
        restored=LinUCB.from_state(state)
        context=RoutingContext(.1,.1,.9)
        self.assertEqual(policy.select(context,{"FAST_ONLY","BOTH"}),restored.select(context,{"FAST_ONLY","BOTH"}))
        state["a"]["BOTH"][0][0]=-1
        with self.assertRaises(ValueError):
            LinUCB.from_state(state)

    def test_populations_reject_unverified_labels_duplicates_and_group_leakage(self):
        row=self.row()
        with self.assertRaises(ValueError):
            validate_population([row,row],"development")
        with self.assertRaises(ValueError):
            validate_population([row],"evaluation")
        with self.assertRaises(ValueError):
            validate_population([row],"development",forbidden_groups={row["group_id"]})
        row["label_source"]="DEEP_PREDICTION"
        with self.assertRaises(ValueError):
            validate_population([row],"development")
