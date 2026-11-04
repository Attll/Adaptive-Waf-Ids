from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import time
import subprocess
import sys
import unittest
from uuid import uuid4

from adaptive_waf.contracts import HttpRequestRecord, DeepOutput, AttackClass
from adaptive_waf.service.durable_escalation import DurableEscalationWorker, JobStore
from test_escalation import _result


@unittest.skipUnless(os.environ.get("WAF_TEST_POSTGRES_PORT"), "isolated broker/database fixture required")
class DurableEscalationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsn = f"postgresql://waf_fixture:local-fixture-only@127.0.0.1:{os.environ['WAF_TEST_POSTGRES_PORT']}/waf_fixture"
        cls.url = f"amqp://guest:guest@127.0.0.1:{os.environ['WAF_TEST_RABBIT_PORT']}/%2F"
        cls.store = JobStore(cls.dsn)

    def worker(self, **kwargs):
        return DurableEscalationWorker(self.dsn, self.url, queue_limit=8, ttl_seconds=3, timeout_ms=200, **kwargs)

    def test_broker_job_survives_producer_restart_and_is_processed_once(self):
        producer = self.worker()
        identifier = str(uuid4())
        request = HttpRequestRecord("GET", "/development", query="sensitive=query")
        self.assertTrue(producer.submit(identifier, request, _result()))
        producer.close()
        processed, reported = [], []
        consumer = self.worker(reporter=lambda outcome: reported.append(outcome.as_payload()) or True)
        consumer.bind(lambda req: (processed.append(req.request_id) or DeepOutput(AttackClass.XSS, .99, .99, "d"), 1))
        consumer.start()
        try:
            self.await_state(identifier, "COMPLETED")
            self.assertEqual(processed, [request.request_id])
            self.assertNotIn("sensitive=query", json.dumps(self.store.get(identifier)["outcome"]))
            # Deliver a duplicate with no request payload; the terminal row must make it a no-op.
            with consumer._connection() as connection:
                connection.channel().basic_publish("", consumer.queue, json.dumps({"job_id": identifier}).encode())
            time.sleep(.2)
            self.assertEqual(len(processed), 1)
        finally:
            consumer.close()

    def test_failure_retries_are_bounded_and_terminal(self):
        worker = self.worker(max_attempts=2)
        worker.bind(lambda request: (_ for _ in ()).throw(RuntimeError("private-content")))
        worker.start()
        identifier = str(uuid4())
        try:
            self.assertTrue(worker.submit(identifier, HttpRequestRecord("GET", "/development"), _result()))
            row = self.await_state(identifier, "FAILED")
            self.assertEqual(row["attempts"], 2)
            self.assertNotIn("private-content", json.dumps(row["outcome"]))
            self.assertFalse(worker.submit(identifier,HttpRequestRecord("GET","/development"),_result()),
                "a terminal failed job must not be reported as a newly pending submission")
        finally:
            worker.close()

    def test_orphaned_pending_job_and_stale_lease_expire(self):
        identifier = str(uuid4())
        self.store.create(identifier, str(uuid4()), "d", -1, 8)
        self.store.expire()
        self.assertEqual(self.store.get(identifier)["state"], "EXPIRED")

        identifier = str(uuid4())
        self.store.create(identifier, str(uuid4()), "d", 3, 8)
        owner = str(uuid4())
        self.assertIsNotNone(self.store.claim(identifier, owner, -.1, 3))
        self.assertIsNotNone(self.store.claim(identifier, str(uuid4()), 1, 3))
        self.assertFalse(self.store.finish(identifier, owner, "COMPLETED", {}))
        with self.store.connect() as db:
            db.execute("update deep_analysis_jobs set expires_at=now()-interval '1 second' where job_id=%s", (identifier,))
        self.store.expire()
        self.assertEqual(self.store.get(identifier)["state"], "EXPIRED")

    def test_unacknowledged_delivery_recovers_after_worker_process_crash(self):
        producer = self.worker()
        identifier = str(uuid4())
        self.assertTrue(producer.submit(identifier, HttpRequestRecord("GET", "/crash-fixture"), _result()))
        # The child owns a real broker delivery and DB lease, then dies without ACK or cleanup.
        child = '''import json, os, sys
from adaptive_waf.service.durable_escalation import DurableEscalationWorker
from uuid import uuid4
dsn, url, identifier = json.loads(sys.stdin.read())
worker = DurableEscalationWorker(dsn, url, queue_limit=8, ttl_seconds=3)
connection = worker._connection()
channel = connection.channel()
method, _, body = channel.basic_get(worker.queue, auto_ack=False)
assert method is not None and json.loads(body)["job_id"] == identifier
assert worker.store.claim(identifier, str(uuid4()), .2, 3) is not None
os._exit(27)
'''
        process = subprocess.run([sys.executable,"-c",child],input=json.dumps([self.dsn,self.url,identifier]),text=True,capture_output=True,timeout=5)
        self.assertEqual(process.returncode,27,process.stderr)
        consumer = self.worker()
        consumer.bind(lambda req:(DeepOutput(AttackClass.XSS,.99,.99,"d"),1))
        consumer.start()
        try:
            row = self.await_state(identifier,"COMPLETED")
            self.assertEqual(row["attempts"],2)
        finally:
            consumer.close()
            producer.close()

    def test_capacity_rejects_without_overwriting_job_and_outbox_retries(self):
        producer = self.worker()
        producer.store.expire()
        identifiers = [str(uuid4()) for _ in range(9)]
        try:
            for identifier in identifiers[:8]:
                self.assertTrue(producer.submit(identifier,HttpRequestRecord("GET","/capacity"),_result()))
            self.assertFalse(producer.submit(identifiers[8],HttpRequestRecord("GET","/capacity"),_result()))
            self.assertIsNone(self.store.get(identifiers[8]))
            reports = []
            consumer = self.worker(reporter=lambda outcome: reports.append(outcome.as_payload()) or len(reports)>1)
            consumer.bind(lambda req:(DeepOutput(AttackClass.BENIGN,.99,0.,"d"),1))
            consumer.start()
            try:
                for identifier in identifiers[:8]:
                    self.await_state(identifier,"COMPLETED")
                deadline=time.monotonic()+5
                while time.monotonic()<deadline and not all(self.store.get(identifier)["reported"] for identifier in identifiers[:8]):
                    time.sleep(.1)
                self.assertTrue(all(self.store.get(identifier)["reported"] for identifier in identifiers[:8]))
                self.assertGreaterEqual(len(reports),9)
            finally:
                consumer.close()
        finally:
            producer.close()

    def await_state(self, identifier, state):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            row = self.store.get(identifier)
            if row["state"] == state:
                return row
            time.sleep(.05)
        self.fail(f"job did not reach {state}")
