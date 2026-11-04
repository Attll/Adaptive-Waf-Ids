"""Derive classification/coverage summaries from immutable measured request records."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
from scripts.research_probe import summarize


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists():
        parser.error("new output required; measured files are not overwritten")
    report=json.loads(args.input.read_text(encoding="utf-8"))
    derived=[]
    for run in report["experiments"]:
        metrics=summarize(run["records"],run["metrics"]["elapsed_seconds"])
        if run["mode"]=="direct_inference":
            metrics["completed_pipeline_calls"]=metrics.pop("completed_http_responses")
        counts=Counter(stage for row in run["records"] for stage in (row.get("stages_ms") or {}))
        derived.append({"mode":run["mode"],"concurrency":run["concurrency"],"metrics":metrics,"journal_stage_invocations":dict(counts)})
    value={"source":str(args.input),"source_sha256":hashlib.sha256(args.input.read_bytes()).hexdigest(),"experiments":derived,
        "scope":"Recomputed solely from measured records and original elapsed time; no new experiment or inferred missing outcomes"}
    with args.output.open("x",encoding="utf-8") as target:
        json.dump(value,target,indent=2,allow_nan=False)


if __name__=="__main__":
    main()
