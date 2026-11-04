from __future__ import annotations

import argparse
import json
import time
from urllib.request import Request, urlopen

from adaptive_waf.network_sensor.flows import FlowAccumulator, PacketObservation
from adaptive_waf.network_sensor.pcap import observe_packet
from adaptive_waf.network_sensor.table import FlowTable
from collections import deque


def main() -> None:
    parser = argparse.ArgumentParser(description="Capture TCP/UDP traffic on Linux and submit compatible flow features to the network sensor.")
    parser.add_argument("--interface", required=True, help="Network interface, for example eth0")
    parser.add_argument("--sensor-url", default="http://127.0.0.1:8083")
    parser.add_argument("--duration", type=float, default=0.0, help="Seconds to capture; 0 means until interrupted")
    parser.add_argument("--max-flows", type=int, default=256)
    parser.add_argument("--max-packets-per-flow", type=int, default=256)
    parser.add_argument("--emit-interval", type=float, default=1.0)
    parser.add_argument("--feature-contract",choices=['frame-population-v1','payload-sample-v2'],default='frame-population-v1',
                        help='v2 corrects payload length/sample std; neither is certified CICFlowMeter parity')
    arguments = parser.parse_args()
    try:
        from scapy.all import IP, IPv6, TCP, UDP, sniff
    except ImportError as error:
        raise SystemExit("Live capture requires the optional sensor dependency: pip install -e '.[sensor]'") from error

    flows = FlowTable(arguments.max_flows, arguments.max_packets_per_flow,feature_contract=arguments.feature_contract)
    pending = deque(maxlen=256)
    dropped = 0
    submitted = 0
    failed = 0
    rejected_packets = 0
    if arguments.emit_interval <= 0 or arguments.duration < 0:
        parser.error("emit interval must be positive and duration nonnegative")

    def enqueue(emissions):
        nonlocal dropped
        for emission in emissions:
            if len(pending) == pending.maxlen:
                dropped += 1
            pending.append(emission)

    def emit():
        nonlocal submitted, failed
        while pending:
            emission = pending.popleft()
            flow = emission.flow
            payload = {"source_ip": flow.source_ip, "destination_ip": flow.destination_ip, "features": flow.features(),
                       "observation_scope": "PACKET_WINDOW" if emission.partial else "CLOSED_FLOW",
                       "feature_contract":flow.feature_contract}
            request = Request(arguments.sensor_url.rstrip("/") + "/v1/flows", data=json.dumps(payload).encode(),
                              headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urlopen(request, timeout=2) as response:
                    response.read()
                submitted += 1
            except OSError:
                failed += 1

    def observe(packet) -> None:
        nonlocal rejected_packets
        if (IP not in packet and IPv6 not in packet) or (TCP not in packet and UDP not in packet):
            return
        if arguments.feature_contract == 'frame-population-v1':
            network = packet[IP] if IP in packet else packet[IPv6]
            transport = packet[TCP] if TCP in packet else packet[UDP]
            observation = PacketObservation(network.src,network.dst,int(transport.sport),int(transport.dport),
                6 if TCP in packet else 17,float(packet.time),len(packet),
                frozenset(str(transport.flags)) if TCP in packet else frozenset(),int(transport.window) if TCP in packet else 0)
        else:
            try:
                observation = observe_packet(packet)
            except ValueError:
                rejected_packets += 1
                return
        enqueue(flows.add(observation))

    try:
        deadline = time.monotonic() + arguments.duration if arguments.duration else float("inf")
        while time.monotonic() < deadline:
            sniff(iface=arguments.interface, prn=observe, store=False, timeout=min(arguments.emit_interval, deadline-time.monotonic()))
            enqueue(flows.poll(time.time()))
            emit()
    except KeyboardInterrupt:
        pass
    enqueue(flows.poll(time.time(), final=True))
    emit()
    print(f"Submitted {submitted} bounded flow windows; delivery_failed={failed}; buffer_overflow={dropped}; rejected_packets={rejected_packets}; contract={arguments.feature_contract}. Packet-window features require separate validation.")


if __name__ == "__main__":
    main()
