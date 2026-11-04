"""Bounded local CRS-only enforcement diagnostic, using the same development wire inputs."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import random
import subprocess
from time import perf_counter
from urllib.parse import quote
from scripts.evaluate_phase10 import CASES
from scripts.research_probe import invoke,local_url,summarize


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url",required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    base=local_url(args.url)
    if args.output.exists():
        parser.error("new output directory required")
    args.output.mkdir(parents=True)
    wire={name:{**case,**({"query":quote(case["query"],safe="=&%")} if "query" in case else {})} for name,case in CASES.items()}
    jobs=list(wire.items())*2
    random.Random(641).shuffle(jobs)
    experiments=[]
    for workers in (1,4):
        started=perf_counter()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            rows=list(pool.map(lambda job:invoke("backend",base,job),jobs))
        duration=perf_counter()-started
        for row in rows:
            row["action"]="BLOCK" if row["http_status"]==403 else "ALLOW" if row["http_status"]==200 else "UNKNOWN"
            row["inspection_status"]="RULES_ONLY" if row["http_status"] in (200,403) else "DETECTION_UNAVAILABLE"
        metrics=summarize(rows,duration)
        metrics["per_attack_enforcement_containment"]={label:sum(r["action"]=="BLOCK" for r in rows if r["expected"]==label)/sum(r["expected"]==label for r in rows)
            for label in sorted({r["expected"] for r in rows}-{"BENIGN"})}
        experiments.append({"mode":"crs_only_gateway","concurrency":workers,"metrics":metrics,"records":rows})
    root=Path(__file__).resolve().parents[1]
    command=["docker","compose","-p","adaptive-waf-crs-research","-f",str(root/"research/compose.crs.yml")]
    version=subprocess.check_output(command+["exec","-T","crs","head","-n","2","/opt/owasp-crs/rules/REQUEST-901-INITIALIZATION.conf"],text=True)
    resolved=subprocess.check_output(command+["config"],text=True)
    report={"input_sha256":hashlib.sha256(json.dumps(wire,sort_keys=True).encode()).hexdigest(),"seed":641,
        "crs_version_source":version,"configuration":resolved,"experiments":experiments,
        "limitations":["Six development probes repeated twice; no held-out generalization or security interval.",
            "Reports CRS enforcement interventions against a controlled backend that returns 200 for all probes; per-class ML classification remains unavailable.",
            "Containerized CRS/backend timing boundary differs from host-JVM gateway comparison. Not an isolated performance ablation.",
            "No GPU computation, dollars, or full-system CPU cost is inferred from this trial."]}
    (args.output/"metrics.json").write_text(json.dumps(report,indent=2,allow_nan=False))
    print(json.dumps([{k:v for k,v in row.items() if k!="records"} for row in experiments],indent=2))


if __name__=="__main__":
    main()
