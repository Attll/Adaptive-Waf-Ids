"""Bounded packet windows. Emitted windows are not asserted equivalent to full CICFlowMeter flows."""
from collections import OrderedDict
from dataclasses import dataclass
from adaptive_waf.network_sensor.flows import FlowAccumulator, FEATURE_CONTRACTS


@dataclass(frozen=True)
class FlowEmission:
    flow: FlowAccumulator
    reason: str
    partial: bool


class FlowTable:
    def __init__(self, max_flows=256, max_packets=256, idle_seconds=10, max_age_seconds=60, feature_contract='frame-population-v1'):
        if min(max_flows, max_packets, idle_seconds, max_age_seconds) <= 0:
            raise ValueError("flow bounds must be positive")
        self.max_flows, self.max_packets = max_flows, max_packets
        self.idle, self.age = idle_seconds, max_age_seconds
        self.flows = OrderedDict()
        if feature_contract not in FEATURE_CONTRACTS:
            raise ValueError('unsupported flow feature contract')
        self.feature_contract = feature_contract

    def add(self, packet):
        ends = sorted(((packet.source_ip, packet.source_port), (packet.destination_ip, packet.destination_port)))
        key = (*ends, packet.protocol)
        emissions = self.poll(packet.timestamp)
        if key not in self.flows:
            if len(self.flows) >= self.max_flows:
                _, (flow, _, _, _) = self.flows.popitem(last=False)
                emissions.append(FlowEmission(flow, "CAPACITY", True))
            self.flows[key] = (FlowAccumulator.from_packet(packet,self.feature_contract), packet.timestamp, packet.timestamp, 1)
        else:
            flow, start, last, count = self.flows[key]
            flow.add(packet)
            self.flows[key] = (flow, start, max(last, packet.timestamp), count + 1)
            self.flows.move_to_end(key)
        flow, _, _, count = self.flows[key]
        if count >= self.max_packets or packet.flags.intersection({"F", "R"}):
            self.flows.pop(key)
            complete = bool(packet.flags.intersection({"F", "R"}))
            emissions.append(FlowEmission(flow, "CLOSED" if complete else "PACKET_LIMIT", not complete))
        return emissions

    def poll(self, now, final=False):
        emissions = []
        for key, (flow, start, last, _) in list(self.flows.items()):
            if final or now - last >= self.idle or now - start >= self.age:
                self.flows.pop(key)
                reason = "CAPTURE_END" if final else "IDLE" if now - last >= self.idle else "AGE_LIMIT"
                emissions.append(FlowEmission(flow, reason, True))
        return emissions

    @property
    def retained_packets(self):
        return sum(row[3] for row in self.flows.values())
