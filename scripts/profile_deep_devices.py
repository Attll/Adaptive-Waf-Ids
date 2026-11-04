"""Bounded read-only CPU/CUDA inference comparison using existing artifacts and development probes."""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import platform
from time import perf_counter
import tomllib

from scripts.evaluate_phase10 import CASES
from scripts.research_probe import LABELS, percentile
from adaptive_waf.contracts import HttpRequestRecord
from adaptive_waf.runtime.artifacts import DistilBertPredictor


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--repeats",type=int,default=3)
    args=parser.parse_args()
    if args.output.exists() or not 1<=args.repeats<=5:
        parser.error("new output file and 1..5 repeats required")
    import torch
    torch.set_num_threads(1)
    root=Path(__file__).resolve().parents[1]
    deep=tomllib.loads((root/"configs/models/deep_deployment.toml").read_text(encoding="utf-8"))
    calibration=tomllib.loads((root/"configs/models/calibration_deployment.toml").read_text(encoding="utf-8"))["deep"]
    records=[]
    for device in (["cpu","cuda"] if torch.cuda.is_available() else ["cpu"]):
        predictor=DistilBertPredictor(root/deep["artifact"],root/calibration["artifact"],device)
        predictor.warm()
        predictor(HttpRequestRecord("GET","/warmup"))
        if device=="cuda":
            torch.cuda.synchronize()
            torch.cuda.reset_peak_memory_stats()
        for repeat in range(args.repeats):
            for case_id,case in CASES.items():
                request=HttpRequestRecord("GET",case["path"],case.get("query",""),cookies=case.get("cookies",{}))
                before=perf_counter()
                scores=predictor(request)
                if device=="cuda":
                    torch.cuda.synchronize()
                elapsed=(perf_counter()-before)*1000
                records.append({"device":device,"repeat":repeat,"case_id":case_id,"expected":LABELS[case_id],
                    "predicted":str(max(scores,key=scores.get)),"scores":{str(k):v for k,v in scores.items()},"elapsed_ms":elapsed,
                    "cuda_peak_allocated_bytes":torch.cuda.max_memory_allocated() if device=="cuda" else None})
        del predictor
        if device=="cuda":
            torch.cuda.empty_cache()
    summary=[{"device":device,"calls":len(rows),"p50_ms":percentile([r["elapsed_ms"] for r in rows],.5),
        "p95_ms":percentile([r["elapsed_ms"] for r in rows],.95),
        "exact_matches":sum(r["expected"]==r["predicted"] for r in rows)}
        for device in sorted({r["device"] for r in records}) if (rows:=[r for r in records if r["device"]==device])]
    report={"scope":"Existing deep model only; warmed tokenization + inference + device transfer + probabilities. Six repeated development inputs, not a new accuracy evaluation.",
        "torch":torch.__version__,"python":platform.python_version(),"cpu_threads":1,"model_run_id":deep["run_id"],
        "cuda_device":torch.cuda.get_device_name() if torch.cuda.is_available() else None,"records":records,"summary":summary}
    if len(summary)==2:
        report["max_probability_delta_cpu_cuda"]=max(abs(a["scores"][k]-b["scores"][k]) for a,b in zip(records[:len(records)//2],records[len(records)//2:],strict=True) for k in a["scores"])
        report["cpu_cuda_predictions_equal"]=all(a["predicted"]==b["predicted"] for a,b in zip(records[:len(records)//2],records[len(records)//2:],strict=True))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open("x",encoding="utf-8") as destination:
        json.dump(report,destination,indent=2,allow_nan=False)
    print(json.dumps(summary,indent=2))


if __name__=="__main__":
    main()
