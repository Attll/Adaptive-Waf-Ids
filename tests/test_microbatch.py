from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event
from time import monotonic, sleep
import unittest

from adaptive_waf.runtime.microbatch import MicrobatchPredictor, BatchBusyError


class MicrobatchTests(unittest.TestCase):
    def test_coalescing_preserves_order_and_bounded_batches(self):
        class Predictor:
            batches = []
            def predict_many(self,requests):
                self.batches.append(list(requests))
                return [value*10 for value in requests]
        predictor = Predictor()
        adapter = MicrobatchPredictor(predictor,max_batch=4,wait_ms=10,timeout_seconds=2)
        barrier = Barrier(8)
        def invoke(value):
            barrier.wait(timeout=2)
            return adapter(value)
        try:
            with ThreadPoolExecutor(8) as pool:
                self.assertEqual(list(pool.map(invoke,range(8))),[value*10 for value in range(8)])
            self.assertEqual(sum(map(len,predictor.batches)),8)
            self.assertTrue(any(len(batch)>1 for batch in predictor.batches))
            self.assertTrue(all(len(batch)<=4 for batch in predictor.batches))
            self.assertEqual(adapter.statistics()['completed'],8)
        finally:
            adapter.close()
        self.assertFalse(adapter.thread.is_alive())
        with self.assertRaisesRegex(RuntimeError,'closed'):adapter(1)

    def test_saturation_and_close_release_queued_and_inflight_callers(self):
        entered, release = Event(), Event()
        class Predictor:
            def predict_many(self,requests):
                entered.set()
                release.wait(timeout=2)
                return requests
        adapter = MicrobatchPredictor(Predictor(),max_batch=2,wait_ms=0,queue_limit=1,timeout_seconds=3)
        with ThreadPoolExecutor(2) as pool:
            try:
                first = pool.submit(adapter,1)
                self.assertTrue(entered.wait(timeout=1))
                second = pool.submit(adapter,2)
                until = monotonic()+1
                while adapter.statistics()['queue_depth'] != 1 and monotonic()<until:sleep(.001)
                self.assertEqual(adapter.statistics()['queue_depth'],1)
                with self.assertRaises(BatchBusyError):adapter(3)
                adapter.close()
                for future in (first,second):
                    with self.assertRaisesRegex(RuntimeError,'closed'):future.result(timeout=1)
                self.assertEqual(adapter.statistics()['rejected'],1)
            finally:
                release.set()
                adapter.close()

    def test_expired_queued_work_is_not_sent_to_model(self):
        entered, release = Event(), Event()
        class Predictor:
            requests = []
            def predict_many(self,requests):
                self.requests.extend(requests)
                entered.set()
                release.wait(timeout=2)
                return requests
        predictor = Predictor()
        adapter = MicrobatchPredictor(predictor,max_batch=2,wait_ms=0,timeout_seconds=2)
        try:
            with ThreadPoolExecutor(1) as pool:
                first = pool.submit(adapter,1)
                self.assertTrue(entered.wait(timeout=1))
                with self.assertRaises(TimeoutError):adapter.predict(2,.01)
                release.set()
                self.assertEqual(first.result(timeout=1),1)
            self.assertEqual(adapter(3),3)
            self.assertEqual(predictor.requests,[1,3])
            self.assertEqual(adapter.statistics()['caller_timeouts'],1)
        finally:
            release.set()
            adapter.close()

    def test_malformed_batch_result_fails_call_instead_of_misassociation(self):
        class Predictor:
            def predict_many(self,requests):return []
        adapter = MicrobatchPredictor(Predictor(),max_batch=2,wait_ms=0)
        try:
            with self.assertRaisesRegex(ValueError,'cardinality'):adapter(1)
        finally:
            adapter.close()
