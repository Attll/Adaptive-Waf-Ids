from __future__ import annotations

import argparse
import json
import time
from urllib.request import Request, urlopen

from adaptive_waf.network_sensor.flows import FlowAccumulator, PacketObservation


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture TCP/UDP traffic on Linux and submit compatible flow features to the network sensor.")
    parser.add_argument("--interface", required=True, help="Network interface, for example eth0")
    parser.add_argument("--sensor-url", default="http://127.0.0.1:8083")
    parser.add_argument("--duration", type=float, default=0.0, help="Seconds to capture; 0 means until interrupted")
    arguments = parser.parse_args()
    try:
        from scapy.all import IP, TCP, UDP, sniff
    except ImportError as error:
        raise SystemExit("Live capture requires the optional sensor dependency: pip install -e '.[sensor]'") from error

    flows: dict[tuple[tuple[str, int], tuple[str, int], int], FlowAccumulator] = {}

    def observe(packet) -> None:
        if IP not in packet or (TCP not in packet and UDP not in packet):
            return
        transport = packet[TCP] if TCP in packet else packet[UDP]
        protocol = 6 if TCP in packet else 17
        observation = PacketObservation(
            source_ip=packet[IP].src, destination_ip=packet[IP].dst,
            source_port=int(transport.sport), destination_port=int(transport.dport), protocol=protocol,
            timestamp=float(packet.time), length=len(packet),
            flags=frozenset(str(packet[TCP].flags)) if TCP in packet else frozenset(),
            tcp_window=int(packet[TCP].window) if TCP in packet else 0,
        )
        endpoints = tuple(sorted(((observation.source_ip, observation.source_port), (observation.destination_ip, observation.destination_port))))
        key = (endpoints[0], endpoints[1], protocol)
        flow = flows.get(key)
        if flow is None:
            flows[key] = FlowAccumulator.from_packet(observation)
        else:
            flow.add(observation)

    try:
        sniff(iface=arguments.interface, prn=observe, store=False, timeout=arguments.duration or None)
    except KeyboardInterrupt:
        pass
    for flow in flows.values():
        payload = {"source_ip": flow.source_ip, "destination_ip": flow.destination_ip, "features": flow.features()}
        request = Request(arguments.sensor_url.rstrip("/") + "/v1/flows", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
        with urlopen(request, timeout=5) as response:
            evidence = json.loads(response.read())["network_context"]
        print(f"source={evidence['source_ip']} class={evidence['network_class']} risk={evidence['network_risk']:.6f}")
    print(f"Captured and submitted {len(flows)} flows")


if __name__ == "__main__":
    main()
