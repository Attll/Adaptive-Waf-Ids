import unittest
from scripts.prepare_candidate_protocol import allocate_groups


class CandidateProtocolTests(unittest.TestCase):
    def test_rare_classes_remain_group_disjoint_and_deterministic(self):
        groups={'XSS':['a','b','c'],'BENIGN':[str(i) for i in range(100)]}
        result=allocate_groups(groups)
        self.assertEqual(result,allocate_groups(groups))
        self.assertEqual({role for label,role in result.values() if label=='XSS'},{'train','tune','evaluation'})
        self.assertEqual(len(result),103)
        with self.assertRaises(ValueError):allocate_groups({'XSS':['a','b']})
