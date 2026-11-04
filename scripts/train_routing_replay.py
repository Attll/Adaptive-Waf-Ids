"""Train a bounded shadow policy from verified measured route matrices; never execute final-test inputs."""
import argparse
import hashlib
import json
from pathlib import Path
from adaptive_waf.runtime.routing import LinUCB
from adaptive_waf.runtime.replay import replay,validate_population


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--development",type=Path,required=True)
    parser.add_argument("--evaluation",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--model-versions",type=Path,required=True)
    parser.add_argument("--unconstrained",action="store_true")
    args=parser.parse_args()
    if args.output.exists() or any(path.stat().st_size>20_000_000 for path in (args.development,args.evaluation)):
        parser.error("new output directory and bounded replay inputs required")
    development=[json.loads(line) for line in args.development.read_text(encoding="utf-8").splitlines() if line.strip()]
    evaluation=[json.loads(line) for line in args.evaluation.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not development or not evaluation:
        parser.error("nonempty separated replay populations required")
    validate_population(development,"development")
    validate_population(evaluation,"evaluation",{r["request_id"] for r in development},{r["group_id"] for r in development})
    policy=LinUCB(seed=641)
    learning=replay(development,policy,learn=True,constrained=not args.unconstrained)
    observations=replay(evaluation,policy,constrained=not args.unconstrained)
    args.output.mkdir(parents=True)
    (args.output/"policy.json").write_text(json.dumps({"model_versions":json.loads(args.model_versions.read_text(encoding="utf-8")),"policy":policy.state()},indent=2,allow_nan=False))
    (args.output/"replay.json").write_text(json.dumps({"seed":641,"shadow_only":True,"constrained":not args.unconstrained,
        "input_sha256":{str(path):hashlib.sha256(path.read_bytes()).hexdigest() for path in (args.development,args.evaluation)},
        "learning":learning,"evaluation":observations,"limitations":"Measured full-information replay; no IPS/DR or live security guarantee"},indent=2,allow_nan=False))


if __name__=="__main__":
    main()
