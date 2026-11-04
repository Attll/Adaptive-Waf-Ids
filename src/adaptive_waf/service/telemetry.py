from collections import Counter, deque
from threading import Lock
from time import monotonic
import os
import sys


class InferenceTelemetry:
    def __init__(self):
        from adaptive_waf.adaptation.monitoring import EvidenceMonitor
        self.monitor = EvidenceMonitor()
        self.lock, self.requests, self.stages = Lock(), deque(maxlen=10000), {}
        self.routes, self.coverage = Counter(), Counter()

    def record(self, result):
        self.monitor.record(result)
        status = result.decision_context.get("inspection_status") or ("PARTIALLY_INSPECTED" if result.deep_escalation_pending else "FULLY_INSPECTED")
        with self.lock:
            self.requests.append((monotonic(), status))
            self.routes[" > ".join(result.routing_path)] += 1
            self.coverage[status] += 1
            for stage, value in result.latency_by_stage_ms.items():
                self.stages.setdefault(stage, deque(maxlen=500)).append(float(value))

    def snapshot(self):
        from adaptive_waf.runtime.benchmark import _percentile
        with self.lock:
            now = monotonic()
            window = [entry for entry in self.requests if now-entry[0] <= 60]
            values = {"window_seconds": 60, "completed_inference_rps": len(window)/60,
                      "fully_inspected_rps": sum(status == "FULLY_INSPECTED" for _,status in window)/60,
                      "window_truncated": len(self.requests) == self.requests.maxlen and bool(self.requests) and now-self.requests[0][0] < 60,
                      "routes_since_start": dict(self.routes), "coverage_since_start": dict(self.coverage),
                      "stage_latency_ms": {name: {"count_retained":len(samples), "p50":_percentile(list(samples),50), "p95":_percentile(list(samples),95)}
                                           for name,samples in self.stages.items()}}
        try:
            import psutil
            process = psutil.Process(os.getpid())
            values["process"] = {"rss_bytes":process.memory_info().rss, "cpu_seconds":sum(process.cpu_times()[:2])}
        except ImportError:
            values["process"] = {"available":False}
        torch = sys.modules.get("torch")
        values["gpu"] = {"available":bool(torch and torch.cuda.is_available()), "utilization_percent":None}
        values["research_monitoring"] = self.monitor.snapshot()
        if values["gpu"]["available"]:
            values["gpu"].update(allocated_bytes=torch.cuda.memory_allocated(), reserved_bytes=torch.cuda.memory_reserved())
        return values
