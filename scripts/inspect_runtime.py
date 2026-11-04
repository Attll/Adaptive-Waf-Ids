"""Read-only hardware/library inventory with an optional tiny CUDA execution check."""
import argparse
from datetime import datetime, timezone
import importlib.metadata
import json
from pathlib import Path
import platform
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cuda-smoke", action="store_true")
    args = parser.parse_args()
    packages = {}
    for name in ("numpy", "scikit-learn", "fastapi", "torch", "transformers", "pika", "psycopg", "xgboost", "lightgbm"):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = None
    report = {"created_at": datetime.now(timezone.utc).isoformat(), "python": sys.version,
              "platform": platform.platform(), "packages": packages}
    try:
        report["nvidia_smi"] = subprocess.check_output(["nvidia-smi", "--query-gpu=name,driver_version,memory.total", "--format=csv,noheader"],
                                                     text=True, timeout=10).strip()
    except (OSError, subprocess.SubprocessError):
        report["nvidia_smi"] = None
    if packages["torch"]:
        import torch
        report.update(cuda_runtime=torch.version.cuda, cuda_available=torch.cuda.is_available(),
                      compiled_architectures=torch.cuda.get_arch_list())
        if torch.cuda.is_available():
            report.update(device=torch.cuda.get_device_name(0), capability=torch.cuda.get_device_capability(0))
            if args.cuda_smoke:
                try:
                    torch.ones(1, device="cuda").sum().item()
                    report["cuda_smoke"] = "passed"
                except RuntimeError as error:
                    report["cuda_smoke"] = type(error).__name__
    if args.output.exists():
        parser.error("output exists; select a new inventory path")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
