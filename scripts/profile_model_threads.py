"""Compare estimator thread budgets on identical warmed development inputs; no model is retrained."""
import argparse
import json
from pathlib import Path
from time import perf_counter
import numpy as np
from adaptive_waf.runtime.artifacts import load_adaptive_pipeline
from adaptive_waf.runtime.optimization import configure_inference_threads
from adaptive_waf.contracts import HttpRequestRecord
from scripts.evaluate_phase10 import CASES
from scripts.research_probe import percentile


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        parser.error("new output path required")
    pipeline=load_adaptive_pipeline(strategy="fixed")
    pipeline.warm_deep_model()
    requests=[(name,HttpRequestRecord("GET",case["path"],case.get("query",""),cookies=case.get("cookies",{}))) for name,case in CASES.items()]
    records=[]
    for threads in (None,1,2):
        if threads:
            for model in (pipeline._triage_model,pipeline._router_model,*pipeline._expert_models.values()):
                configure_inference_threads(model,threads)
        for repeat in range(3):
            for case_id,request in requests:
                started=perf_counter()
                result=pipeline.detect(request)
                records.append({"threads":threads,"repeat":repeat,"case_id":case_id,"predicted_attack":str(result.predicted_attack),
                                "risk":result.overall_risk,"elapsed_ms":(perf_counter()-started)*1000,
                                "stages_ms":result.latency_by_stage_ms})
    reference=[row for row in records if row["threads"] is None]
    identical=True
    for threads in (1,2):
        current=[row for row in records if row["threads"]==threads]
        identical &= all(a["predicted_attack"]==b["predicted_attack"] and np.isclose(a["risk"],b["risk"],atol=1e-10) for a,b in zip(reference,current,strict=True))
    report={"scope":"warmed single-client development diagnostic; no final-set or generalization claim",
            "predictions_and_risk_equivalent":bool(identical),"records":records,
            "summary":[{"threads":threads,"p50_ms":percentile([row["elapsed_ms"] for row in records if row["threads"]==threads],.5),
                        "p95_ms":percentile([row["elapsed_ms"] for row in records if row["threads"]==threads],.95)} for threads in (None,1,2)]}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report["summary"],indent=2))
    if not identical:
        raise SystemExit("prediction-equivalence check failed")


if __name__=="__main__":
    main()
