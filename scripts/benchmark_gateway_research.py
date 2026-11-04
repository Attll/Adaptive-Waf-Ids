"""Matched local gateway experiment. Owns all HTTP processes; never targets external applications."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
from pathlib import Path
import random
import re
import secrets
import socket
import subprocess
from threading import Thread
from threading import Event
import time
import zipfile
from urllib.request import Request, urlopen
from urllib.parse import quote

from scripts.evaluate_phase10 import CASES
from scripts.research_probe import invoke, summarize, LABELS


class GpuSamples:
    """Whole-device observations, which can include unrelated GPU workloads."""
    def __init__(self):
        self.samples, self.stop = [], Event()
        self.thread = Thread(target=self._sample, daemon=True)
    def _sample(self):
        while not self.stop.is_set():
            try:
                result = subprocess.run(["nvidia-smi", "--query-gpu=utilization.gpu,memory.used,power.draw", "--format=csv,noheader,nounits"],capture_output=True,text=True,timeout=2,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                if result.returncode == 0:
                    values = result.stdout.splitlines()[0].split(',')
                    self.samples.append({"gpu_percent":float(values[0]),"device_memory_mib":float(values[1]),"device_power_watts":float(values[2])})
            except (OSError,ValueError,IndexError,subprocess.TimeoutExpired):
                pass
            self.stop.wait(.25)
    def __enter__(self):
        self.thread.start()
        return self
    def __exit__(self,*args):
        self.stop.set()
        self.thread.join(timeout=3)


def free_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]

def file_hash(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source,'sha256').hexdigest()


def wait_http(url, process=None):
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process and process.poll() is not None:
            raise RuntimeError("owned fixture exited during startup; inspect its log")
        try:
            with urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except OSError:
            time.sleep(.1)
    raise RuntimeError("owned fixture did not become ready")


def java_service(root, component, environment, output, cleanup):
    port = free_port()
    jar = root / component / "target" / (component + "-0.1.0.jar")
    if not jar.exists():
        raise ValueError(f"package {component} with mvn -o package -DskipTests first")
    log = cleanup.enter_context((output / (component + ".log")).open("w"))
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    properties = subprocess.check_output(["java", "-XshowSettings:properties", "-version"], stderr=subprocess.STDOUT, text=True)
    java_home = re.search(r"java.home\s*=\s*(.+)", properties).group(1).strip()
    java_executable = Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java")
    process = subprocess.Popen([str(java_executable), "-jar", str(jar), "--server.address=127.0.0.1", f"--server.port={port}"],
                               cwd=root, env={**os.environ, **environment}, stdout=log, stderr=subprocess.STDOUT, creationflags=flags)
    def stop():
        import psutil
        try:
            for child in psutil.Process(process.pid).children(recursive=True):
                child.terminate()
        except psutil.Error:
            pass
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    cleanup.callback(stop)
    base = f"http://127.0.0.1:{port}"
    wait_http(base + ("/health" if component == "demo-backend" else "/actuator/health"), process)
    return base, process


def control_request(base, path, payload=None):
    headers = {"Authorization": "Basic " + base64.b64encode(b"fixture-admin:local-fixture-only").decode()}
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = Request(base + path, json.dumps(payload).encode() if payload is not None else None,
                      headers=headers, method="PUT" if payload is not None else "GET")
    with urlopen(request, timeout=5) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--concurrency", default="1,4")
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--seed", type=int, default=641)
    parser.add_argument("--input",type=Path,help="Reviewed development JSON envelope with population, id and cases")
    parser.add_argument("--additional-strategies",default="",help="Comma-separated available experimental static strategies")
    parser.add_argument("--only-modes",default="",help="Optional subset of the constructed experimental modes")
    parser.add_argument("--http-workers",type=int,default=1,help="Owned detection fixture worker count, recorded separately from client concurrency")
    parser.add_argument("--torch-threads",type=int,help="Optional fixed inference thread count")
    args = parser.parse_args()
    concurrency = [int(value) for value in args.concurrency.split(",")]
    if args.output.exists() or not 1 <= args.repeats <= 10 or not concurrency or min(concurrency) < 1 or max(concurrency) > 8:
        parser.error("new output directory, repeats 1..10 and concurrency 1..8 required")
    if not 1 <= args.http_workers <= 8 or args.torch_threads is not None and not 1 <= args.torch_threads <= 4:
        parser.error("fixture HTTP workers 1..8 and torch threads 1..4 required")
    for name in ("WAF_TEST_REDIS_PORT", "WAF_TEST_RABBIT_PORT", "WAF_TEST_POSTGRES_PORT"):
        if not os.environ.get(name, "").isdigit():
            parser.error("isolated fixture ports required: " + name)
    args.output.mkdir(parents=True)
    root = Path(__file__).resolve().parents[1]
    files = list((root/"configs").rglob("*.toml")) + list((root/"src/adaptive_waf").rglob("*.py")) + list((root/"scripts").glob("*.py"))
    files += [root/component/"target"/(component+"-0.1.0.jar") for component in ("gateway-service","security-control-service","demo-backend")]
    manifest = json.loads((root/"research/results/artifact_manifest.json").read_text(encoding="utf-8"))
    files += [root/row["path"] for row in manifest["artifacts"]]
    provenance = {"python":platform.python_version(), "platform":platform.platform(),
        "git_revision":subprocess.check_output(["git","rev-parse","HEAD"],cwd=root,text=True).strip(),
        "runtime_flags":{name:os.environ.get(name) for name in ("WAF_MODEL_THREADS","WAF_DEEP_DEVICE","WAF_CONTEXT_MODE",
            "WAF_DEEP_BATCH_SIZE","WAF_DEEP_BATCH_WAIT_MS","WAF_DEEP_BATCH_QUEUE","WAF_DEEP_BATCH_TIMEOUT_SECONDS")},
        "http_workers":args.http_workers,"torch_threads":args.torch_threads,
        "sha256":{str(path.relative_to(root)):file_hash(path) for path in files if path.is_file()}}
    # Preserve measured source even while this working branch has uncommitted research changes.
    source_files=[path for path in files if path.suffix in {'.py','.toml'}]
    for component in ("gateway-service","security-control-service","demo-backend"):
        source_files += list((root/component/"src").rglob('*.java'))+list((root/component/"src").rglob('*.yml'))+[root/component/"pom.xml"]
    with zipfile.ZipFile(args.output/"measured-source.zip",'x',compression=zipfile.ZIP_DEFLATED) as archive:
        for path in source_files:
            archive.write(path,str(path.relative_to(root)))
    cases,input_id=CASES,"six-development-probes-repeated"
    if args.input:
        if args.input.stat().st_size>2_000_000:
            parser.error("bounded development input required")
        source=json.loads(args.input.read_text(encoding="utf-8"))
        if source.get("population")!="development" or not source.get("review_reference"):
            parser.error("explicit reviewed development population required; final evaluation is not supported by this diagnostic")
        cases,input_id=source["cases"],source["id"]
        if not cases or len(cases)*args.repeats>1000:
            parser.error("1..1000 submitted development requests required")
        from adaptive_waf.contracts import AttackClass
        for case in cases.values():
            AttackClass(case["expected_attack"])
    wire_cases = {name: {**case, **({"query": quote(case["query"], safe="=&%")} if "query" in case else {})} for name,case in cases.items()}
    jobs = list(wire_cases.items()) * args.repeats
    random.Random(args.seed).shuffle(jobs)
    from adaptive_waf.runtime.artifacts import load_adaptive_pipeline
    from adaptive_waf.runtime.guarded import GuardedPipeline
    from adaptive_waf.runtime.strategies import RoutedPipeline
    from adaptive_waf.contracts import HttpRequestRecord
    from adaptive_waf.service.app import create_app, load_service_config
    from dataclasses import replace
    from adaptive_waf.service.escalation import DisabledEscalationWorker
    import uvicorn
    import psutil
    import torch
    if args.torch_threads is not None:torch.set_num_threads(args.torch_threads)
    import sklearn
    provenance.update(torch=torch.__version__,cuda=torch.version.cuda,sklearn=sklearn.__version__,
                      cuda_device=torch.cuda.get_device_name() if torch.cuda.is_available() else None)

    baseline = load_adaptive_pipeline(strategy="fixed")
    baseline.warm_deep_model()
    selected = [baseline]
    class Selector:
        @property
        def model_versions(self):
            return selected[0].model_versions
        def detect(self, *values):
            return selected[0].detect(*values)
    application = create_app(config=replace(load_service_config(),http_workers=args.http_workers),pipeline_loader=Selector, escalation_worker=DisabledEscalationWorker())
    server = uvicorn.Server(uvicorn.Config(application, access_log=False, log_level="error"))
    with ExitStack() as cleanup, socket.socket() as listener:
        cleanup.callback(baseline.close)
        listener.bind(("127.0.0.1", 0))
        detection = f"http://127.0.0.1:{listener.getsockname()[1]}"
        thread = Thread(target=lambda: server.run(sockets=[listener]), daemon=True)
        thread.start()
        def stop_api():
            server.should_exit = True
            thread.join(timeout=5)
        cleanup.callback(stop_api)
        wait_http(detection + "/ready")
        token = secrets.token_urlsafe(32)
        environment = {"WAF_INTERNAL_TOKEN": token, "REDIS_HOST": "127.0.0.1", "REDIS_PORT": os.environ["WAF_TEST_REDIS_PORT"],
                       "RABBITMQ_HOST": "127.0.0.1", "RABBITMQ_PORT": os.environ["WAF_TEST_RABBIT_PORT"],
                       "WAF_POSTGRES_URL": f"jdbc:postgresql://127.0.0.1:{os.environ['WAF_TEST_POSTGRES_PORT']}/waf_fixture",
                       "WAF_POSTGRES_USER": "waf_fixture", "WAF_POSTGRES_PASSWORD": "local-fixture-only",
                       "WAF_ADMIN_USERNAME": "fixture-admin", "WAF_ADMIN_INITIAL_PASSWORD": "local-fixture-only"}
        control, control_process = java_service(root, "security-control-service", environment, args.output, cleanup)
        control_request(control, "/v1/control/policy", {"blockRiskThreshold": .81, "rateLimitShortWindow": 1000000})
        backend, backend_process = java_service(root, "demo-backend", environment, args.output, cleanup)
        environment.update(CONTROL_SERVICE_URL=control, DETECTION_SERVICE_URL=detection, DEMO_BACKEND_URL=backend,
                           BEHAVIOUR_TEMPORARY_BLOCK_THRESHOLD="1000000", LOAD_MODE_ELEVATED_REQUESTS="1000000",
                           LOAD_MODE_DEGRADED_REQUESTS="2000000", LOAD_MODE_EMERGENCY_REQUESTS="3000000")
        gateway, gateway_process = java_service(root, "gateway-service", environment, args.output, cleanup)
        process_group = [psutil.Process(os.getpid()), psutil.Process(gateway_process.pid), psutil.Process(backend_process.pid), psutil.Process(control_process.pid)]
        experiments = []
        modes = [("direct_inference", "direct", baseline), ("detection_api", "api", baseline),
                 ("fixed_gateway", "gateway", baseline), ("guarded_gateway", "gateway", GuardedPipeline(baseline)),
                 ("rules_only_gateway", "gateway", RoutedPipeline(baseline, "rules_only")),
                 ("both_gateway", "gateway", RoutedPipeline(baseline, "both")), ("direct_backend", "backend", baseline)]
        for strategy in filter(None,args.additional_strategies.split(',')):
            if strategy == "deep_only_control":
                from adaptive_waf.runtime.research_baselines import DeepOnlyControl
                modes.insert(-1,("deep_only_control_gateway","gateway",DeepOnlyControl(baseline)))
                continue
            if strategy not in {"single_fast","always_deep","confidence","cost_threshold","calibrated_fusion"}:
                raise ValueError("Unsupported additional static strategy")
            modes.insert(-1,(strategy+"_gateway","gateway",RoutedPipeline(baseline,strategy)))
        if args.only_modes:
            requested=set(args.only_modes.split(','))
            if not requested.issubset({name for name,_,_ in modes}):
                raise ValueError("unknown experiment mode")
            modes=[mode for mode in modes if mode[0] in requested]
        for name, boundary, pipeline in modes:
            selected[0] = pipeline
            for workers in concurrency if boundary != "direct" else [1]:
                print("Running", name, "concurrency", workers, flush=True)
                before_cpu = sum(sum(process.cpu_times()[:2]) for process in process_group)
                gpu_samples = GpuSamples()
                cleanup.callback(gpu_samples.__exit__)
                gpu_samples.__enter__()
                started = time.perf_counter()
                if boundary == "direct":
                    rows = []
                    for case_id, payload in jobs:
                        request = HttpRequestRecord(payload.get("method","GET"), payload["path"], payload.get("query", ""),
                            headers=payload.get("headers",{}),cookies=payload.get("cookies", {}),body=payload.get("body",""))
                        before = time.perf_counter()
                        result = pipeline.detect(request)
                        rows.append({"case_id": case_id, "request_id": str(request.request_id), "expected": LABELS.get(case_id,payload.get("expected_attack")),
                                     "predicted_attack": str(result.predicted_attack), "completed": True, "http_status": 0, "action": "UNKNOWN",
                                     "inspection_status": "FULLY_INSPECTED", "round_trip_ms": (time.perf_counter()-before)*1000})
                else:
                    target = detection if boundary == "api" else gateway if boundary == "gateway" else backend
                    with ThreadPoolExecutor(max_workers=workers) as pool:
                        rows = list(pool.map(lambda job: invoke(boundary, target, job), jobs))
                duration = time.perf_counter() - started
                gpu_samples.__exit__()
                cpu_seconds = sum(sum(process.cpu_times()[:2]) for process in process_group) - before_cpu
                if boundary == "gateway":
                    required = {row["request_id"] for row in rows}
                    events, deadline = {}, time.monotonic() + 8
                    while time.monotonic() < deadline:
                        for event in control_request(control, "/v1/security/events?limit=500")["events"]:
                            if event.get("requestId") in required:
                                events[event["requestId"]] = event
                        if required.issubset(events):
                            break
                        time.sleep(.1)
                    for row in rows:
                        if row["request_id"] in events:
                            event = events[row["request_id"]]
                            row.update(predicted_attack=event.get("predictedAttack"), action=event.get("action"),
                                       inspection_status=event.get("inspectionStatus"), inference_ms=event.get("detectionLatencyMs"))
                            details = json.loads(event.get("detailsJson") or "{}")
                            decision = details.get("detection") or {}
                            row.update(routing_path=decision.get("routing_path"), decision=decision.get("decision"),
                                       model_versions=decision.get("model_versions"), stages_ms=decision.get("latency_by_stage_ms"))
                metrics = summarize(rows, duration)
                metrics.update(cpu_core_seconds=cpu_seconds, cpu_equivalent_percent=100*cpu_seconds/duration,
                               process_group_rss_bytes=sum(process.memory_info().rss for process in process_group),
                               gpu_process_allocated_bytes=torch.cuda.memory_allocated() if torch.cuda.is_available() else 0,
                               gpu_process_peak_allocated_bytes=torch.cuda.max_memory_allocated() if torch.cuda.is_available() else 0)
                metrics["gpu_device_samples"] = gpu_samples.samples
                metrics["deep_batch_cumulative_snapshot"] = baseline.batch_statistics()
                metrics["cpu_ms_per_submitted_request"] = cpu_seconds*1000/len(rows)
                if boundary == "direct":
                    metrics["completed_pipeline_calls"] = metrics.pop("completed_http_responses")
                experiments.append({"mode": name, "concurrency": workers, "metrics": metrics, "records": rows})
        report = {"created_at": datetime.now(timezone.utc).isoformat(), "input_id": input_id, "seed": args.seed,
                  "input_sha256": hashlib.sha256(json.dumps(wire_cases,sort_keys=True).encode()).hexdigest(), "transport_encoding_shared_across_modes":True,
                  "provenance":provenance, "model_versions":baseline.model_versions, "experiments": experiments,
                  "limitations": ["Prepared development probes only; no generalization or final-test claim.",
                    "Repeated inputs are not independent samples; no security confidence interval inferred.",
                    "Fixed and guarded strategies differ in available mandatory rules; this is not isolated routing novelty evidence.",
                    "Resource CPU/RSS covers client, detection and three Java processes; GPU metrics are allocator observations, not GPU utilization.",
                    "nvidia-smi samples cover the entire device; power, memory and utilization can include unrelated workloads. RSS is end-of-trial, not peak.",
                    "No CRS-only, fitted-conformal or trained-bandit results exist in this report."]}
        (args.output / "metrics.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps([{k: value for k,value in experiment.items() if k != "records"} for experiment in experiments], indent=2))


if __name__ == "__main__":
    main()
