from __future__ import annotations
import argparse
import os
import tomllib
import uvicorn
from adaptive_waf.adaptation.service import AdaptationSettings, create_app

def main() -> None:
    parser = argparse.ArgumentParser(description="Run the controlled training/adaptation lifecycle service.")
    parser.add_argument("--config", default="configs/adaptation_service.toml")
    parser.add_argument("--port", type=int, default=8084)
    args = parser.parse_args()
    with open(args.config, "rb") as handle: settings = AdaptationSettings(**tomllib.load(handle))
    settings.control_service_url = os.getenv("CONTROL_SERVICE_URL", settings.control_service_url)
    uvicorn.run(create_app(settings), host="127.0.0.1", port=args.port)
if __name__ == "__main__": main()
