import unittest
import tempfile
from pathlib import Path
from adaptive_waf.runtime.session_risk import SessionRiskStore, RiskRevision, private_session_key
from adaptive_waf.runtime.profiles import EndpointProfiles
from adaptive_waf.contracts import HttpRequestRecord


class SessionProfileTests(unittest.TestCase):
    def test_reviewed_profiles_round_trip_freeze_and_preserve_rollback_file(self):
        profiles=EndpointProfiles("reviewed-v1")
        request=HttpRequestRecord("GET","/search","q=ordinary")
        for index in range(5):
            profiles.observe(request,str(index),"VERIFIED_BENIGN")
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"profile.json"
            profiles.save(path,"fixture-reviewed-benign")
            restored=EndpointProfiles.load(path)
            self.assertEqual(profiles.score(request),restored.score(request))
            with self.assertRaises(ValueError):
                restored.observe(request,"new","VERIFIED_BENIGN")
            with self.assertRaises(FileExistsError):
                profiles.save(path,"fixture-reviewed-benign")
            self.assertFalse(restored.score(HttpRequestRecord("GET","/search",'&'.join('q=x' for _ in range(513))))["available"])

    def test_profile_memory_bounds_preserve_duplicate_idempotency(self):
        profiles = EndpointProfiles("bounded", maximum_observations=2, maximum_values=2)
        request = HttpRequestRecord("GET", "/search", "q=x")
        profiles.observe(request, "a", "VERIFIED_BENIGN")
        profiles.observe(request, "a", "VERIFIED_BENIGN")
        profiles.observe(request, "b", "VERIFIED_BENIGN")
        with self.assertRaises(ValueError):
            profiles.observe(request, "c", "VERIFIED_BENIGN")
        self.assertEqual(profiles.profiles["/search"]["count"], 2)
        with self.assertRaises(ValueError):
            EndpointProfiles("bad", maximum_values=0)

    def test_decay_expiry_and_verified_correction_preserve_original_revision(self):
        now = [0]
        store = SessionRiskStore(ttl_seconds=100, half_life_seconds=10, clock=lambda: now[0])
        key = private_session_key("x" * 32, "session-a")
        original = RiskRevision("r1","deep-1","model1","policy1",.9,False,0)
        self.assertEqual(store.revise(key, original), .9)
        store.revise(key, original)
        self.assertEqual(len(store.history(key)), 1)
        now[0] = 10
        self.assertAlmostEqual(store.risk(key), .45)
        store.revise(key, RiskRevision("r1","operator-1","model1","policy1",0,True,10))
        self.assertEqual(store.risk(key), 0)
        self.assertEqual(store.history(key)[0], original)
        self.assertEqual(store.risk(private_session_key("x" * 32,"unrelated-user-same-ip")),0)
        now[0] = 111
        self.assertFalse(store.history(key))

    def test_endpoint_updates_reject_unverified_labels_and_anomalies_are_evidence_only(self):
        profiles = EndpointProfiles("verified-v1")
        request = HttpRequestRecord("GET","/search","q=ordinary")
        with self.assertRaises(ValueError):
            profiles.observe(request,"poison","MODEL_BENIGN")
        for index in range(5):
            profiles.observe(request,str(index),"VERIFIED_BENIGN")
        self.assertEqual(profiles.score(request)["score"],0)
        self.assertGreater(profiles.score(HttpRequestRecord("POST","/search","unexpected=x"))["score"],0)
        self.assertFalse(profiles.score(HttpRequestRecord("GET","/new"))["available"])
