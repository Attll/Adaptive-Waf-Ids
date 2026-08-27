from __future__ import annotations

import argparse
import os
from pathlib import Path

import uvicorn

from adaptive_waf.network_sensor.service import SensorSettings, create_app, load_sensor_settings


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the asynchronous Adaptive WAF network sensor.")
    parser.add_argument("--config", type=Path, default=Path("configs/network_sensor.toml"))
    parser.add_argument("--host", default=os.getenv("NETWORK_SENSOR_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("NETWORK_SENSOR_PORT", "8083")))
    arguments = parser.parse_args()
    settings = load_sensor_settings(arguments.config)
    settings.redis_host = os.getenv("REDIS_HOST", settings.redis_host)
    settings.redis_port = int(os.getenv("REDIS_PORT", str(settings.redis_port)))
    uvicorn.run(create_app(settings), host=arguments.host, port=arguments.port)


if __name__ == "__main__":
    main()
