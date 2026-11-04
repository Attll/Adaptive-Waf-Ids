import unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from threading import Thread
from scripts.research_probe import invoke,local_url, summarize


class ResearchProbeTests(unittest.TestCase):
    def test_post_transport_preserves_encoded_query_cookies_headers_and_utf8_body(self):
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.server.seen=(self.path,self.rfile.read(int(self.headers['Content-Length'])),self.headers.get('Cookie'),self.headers.get('Content-Type'))
                self.send_response(200)
                self.send_header('X-WAF-Action','ALLOW')
                self.send_header('X-WAF-Inspection-Status','FULLY_INSPECTED')
                self.end_headers()
            def log_message(self,*args): pass
        server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            result=invoke('gateway',f'http://127.0.0.1:{server.server_port}',('custom',{
                'method':'POST','path':'/echo','query':'x=1&x=2&z=%252f','body':'café',
                'headers':{'Content-Type':'text/plain;charset=UTF-8'},'cookies':{'session':'fixture'},'expected_attack':'BENIGN'}))
            self.assertTrue(result['completed'])
            self.assertEqual(server.seen,('/backend/echo?x=1&x=2&z=%252f','café'.encode(),'session=fixture','text/plain;charset=UTF-8'))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_remote_and_credential_urls_are_rejected(self):
        for target in ("http://example.com", "http://192.0.2.1", "http://user:pass@127.0.0.1", "https://127.0.0.1"):
            with self.assertRaises(ValueError):
                local_url(target)
        self.assertEqual(local_url("http://127.0.0.1:8000/"), "http://127.0.0.1:8000")

    def test_bypasses_are_not_counted_as_successful_inspections(self):
        rows = [{"expected": "SQL_INJECTION", "completed": True, "http_status": 200, "inspection_status": "DETECTION_UNAVAILABLE",
                 "predicted_attack": None, "action": "ALLOW", "round_trip_ms": 1},
                {"expected": "BENIGN", "completed": True, "http_status": 200, "inspection_status": "FULLY_INSPECTED",
                 "predicted_attack": "BENIGN", "action": "ALLOW", "round_trip_ms": 2},
                {"expected": "XSS", "completed": True, "http_status": 200, "inspection_status": "PARTIALLY_INSPECTED",
                 "predicted_attack": "XSS", "action": "ALLOW", "round_trip_ms": 3}]
        metrics = summarize(rows, 2)
        self.assertEqual(metrics["fully_inspected"], 1)
        self.assertEqual(metrics["unresolved"], 2)
        self.assertEqual(metrics["completed_rps"], 1.5)
        self.assertEqual(metrics["fully_inspected_rps"], .5)
        self.assertAlmostEqual(metrics["exact_class_accuracy_all_submitted"],2/3)
        self.assertEqual(metrics["enforcement_confusion"]["attack"]["ALLOW"], 2)

    def test_missing_classification_does_not_create_benign_evidence(self):
        metrics = summarize([{"expected": "SQL_INJECTION", "completed": False, "http_status": 0,
                              "inspection_status": "UNKNOWN", "action": "UNKNOWN", "round_trip_ms": 10}], 1)
        self.assertIsNone(metrics["attack_detection_recall_all_submitted"])
        self.assertEqual(metrics["unresolved"], 1)
