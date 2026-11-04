"""Prepare conformal/profile artifacts from explicitly reviewed, separated inputs. No inference or training."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
from adaptive_waf.contracts import HttpRequestRecord
from adaptive_waf.runtime.profiles import EndpointProfiles
from adaptive_waf.runtime.uncertainty import SplitConformal


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kind",choices=("conformal","profiles"),required=True)
    parser.add_argument("--input",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists() or args.input.stat().st_size>20_000_000:
        parser.error("new output file and bounded input required")
    value=json.loads(args.input.read_text(encoding="utf-8"))
    if not value.get("review_reference"):
        parser.error("reviewed provenance required")
    records=value["records"]
    if not records or any(row.get("label_source")!="VERIFIED" for row in records):
        parser.error("verified labels required; model predictions are not labels")
    if args.kind=="profiles":
        if value["population"]!="development" or any(row["label"]!="BENIGN" for row in records):
            parser.error("profile fitting requires reviewed benign development observations")
        profile=EndpointProfiles(value["version"])
        for row in records:
            profile.observe(HttpRequestRecord(**row["request"]),row["request_id"],"VERIFIED_BENIGN")
        profile.save(args.output,value["review_reference"])
    else:
        if value["population"]!="calibration":
            parser.error("dedicated calibration population required")
        # Explicit population manifests are mandatory, including empty sets when appropriate.
        forbidden=set(value["training_ids"])|set(value["evaluation_ids"])
        forbidden_groups=set(value["training_groups"])|set(value["evaluation_groups"])
        if any(not row.get("group_id") or row["group_id"] in forbidden_groups for row in records):
            parser.error("calibration application/template/session group overlaps or is missing")
        artifact=SplitConformal.fit([row["probabilities"] for row in records],[row["label"] for row in records],
            value["classes"],[row["request_id"] for row in records],value["model_version"],alpha=value.get("alpha",.1),
            class_sensitive=value.get("class_sensitive",True),forbidden_ids=forbidden)
        with args.output.open("x") as destination:
            json.dump(asdict(artifact),destination,indent=2,allow_nan=False)


if __name__=="__main__":
    main()
