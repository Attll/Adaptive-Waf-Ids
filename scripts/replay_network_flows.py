from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.request import Request, urlopen


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay prepared CICIDS JSONL flows through the live network sensor.")
    parser.add_argument("path", type=Path, help="Prepared CICIDS JSONL split")
    parser.add_argument("--sensor-url", default="http://127.0.0.1:8083")
    parser.add_argument("--source-ip", default="203.0.113.10", help="Development correlation source for records without IP metadata")
    parser.add_argument("--destination-ip", default="198.51.100.20")
    parser.add_argument("--limit", type=int, default=10)
    arguments = parser.parse_args()
    processed = 0
    with arguments.path.open(encoding="utf-8") as handle:
        for line in handle:
            if processed >= arguments.limit:
                break
            record = json.loads(line)
            request = Request(
                arguments.sensor_url.rstrip("/") + "/v1/flows",
                data=json.dumps({"source_ip": arguments.source_ip, "destination_ip": arguments.destination_ip, "features": record["features"]}).encode(),
                headers={"Content-Type": "application/json"}, method="POST",
            )
            with urlopen(request, timeout=5) as response:
                result = json.loads(response.read())
            processed += 1
            context = result["network_context"]
            print(f"flow {processed}: class={context['network_class']}; risk={context['network_risk']:.6f}; source={context['source_ip']}")
    print(f"Replay completed: {processed} flows")


if __name__ == "__main__":
    main()
