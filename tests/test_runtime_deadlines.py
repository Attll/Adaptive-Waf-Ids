from concurrent.futures import ThreadPoolExecutor
from threading import Event
from time import monotonic
import unittest

from adaptive_waf.service.runtime import RuntimeStore, InferenceBusyError, InferenceTimeoutError


class RuntimeDeadlineTests(unittest.TestCase):
    def test_deadline_returns_before_native_work_and_capacity_remains_occupied(self):
        release = Event()
        entered = Event()

        class Pipeline:
            def detect(self, *args):
                entered.set()
                release.wait(2)
                return "done"

        store = RuntimeStore(Pipeline, lambda: object(), 30, 100, queue_limit=0)
        store.start()
        try:
            start = monotonic()
            with self.assertRaises(InferenceTimeoutError):
                store.detect(None, None, None, None)
            self.assertTrue(entered.is_set())
            self.assertLess(monotonic() - start, .5)
            with self.assertRaises(InferenceBusyError):
                store.detect(None, None, None, None)
        finally:
            release.set()
            store.close()

    def test_network_does_not_wait_for_http_execution(self):
        entered, release = Event(), Event()

        class Pipeline:
            def detect(self, *args):
                entered.set()
                release.wait(2)

        class Network:
            def detect(self, features):
                return "network"

        store = RuntimeStore(Pipeline, Network, 1000, 100)
        store.start()
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(store.detect, None, None, None, None)
                self.assertTrue(entered.wait(.5))
                try:
                    result, _ = store.detect_network({})
                    self.assertEqual(result, "network")
                finally:
                    release.set()
                pending.result(1)
        finally:
            release.set()
            store.close()

    def test_queued_request_deadline_includes_queue_wait(self):
        entered, release = Event(), Event()
        calls = []

        class Pipeline:
            def detect(self, value, *args):
                calls.append(value)
                entered.set()
                release.wait(2)

        store = RuntimeStore(Pipeline, lambda: object(), 50, 100, queue_limit=1)
        store.start()
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                pending = pool.submit(store.detect, "first", None, None, None)
                self.assertTrue(entered.wait(.5))
                with self.assertRaises(InferenceTimeoutError):
                    store.detect("cancelled", None, None, None)
                release.set()
                try:
                    pending.result(1)
                except InferenceTimeoutError:
                    pass  # the first caller may already have reached its independent deadline
            self.assertEqual(calls, ["first"])
        finally:
            release.set()
            store.close()
