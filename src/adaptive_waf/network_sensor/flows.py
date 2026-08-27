from __future__ import annotations

from dataclasses import dataclass, field
import math
from statistics import fmean, pstdev


@dataclass(frozen=True, slots=True)
class PacketObservation:
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: int
    timestamp: float
    length: int
    flags: frozenset[str] = frozenset()
    tcp_window: int = 0


@dataclass(slots=True)
class FlowAccumulator:
    """Builds only the CICIDS fields reproducible from packet/flow observations."""

    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: int
    _forward: list[PacketObservation] = field(default_factory=list)
    _backward: list[PacketObservation] = field(default_factory=list)

    @classmethod
    def from_packet(cls, packet: PacketObservation) -> "FlowAccumulator":
        flow = cls(packet.source_ip, packet.destination_ip, packet.source_port, packet.destination_port, packet.protocol)
        flow.add(packet)
        return flow

    def accepts(self, packet: PacketObservation) -> bool:
        return packet.protocol == self.protocol and ((packet.source_ip, packet.destination_ip, packet.source_port, packet.destination_port) == (self.source_ip, self.destination_ip, self.source_port, self.destination_port) or (packet.source_ip, packet.destination_ip, packet.source_port, packet.destination_port) == (self.destination_ip, self.source_ip, self.destination_port, self.source_port))

    def add(self, packet: PacketObservation) -> None:
        if not self.accepts(packet):
            raise ValueError("packet does not belong to this flow")
        (self._forward if packet.source_ip == self.source_ip and packet.source_port == self.source_port else self._backward).append(packet)

    def features(self) -> dict[str, float]:
        packets = sorted([*self._forward, *self._backward], key=lambda packet: packet.timestamp)
        if not packets:
            raise ValueError("flow has no packets")
        duration_seconds = max(0.000001, packets[-1].timestamp - packets[0].timestamp)
        duration_microseconds = duration_seconds * 1_000_000
        forward_lengths = [packet.length for packet in self._forward]
        backward_lengths = [packet.length for packet in self._backward]
        all_lengths = [packet.length for packet in packets]
        iats = [later.timestamp - earlier.timestamp for earlier, later in zip(packets, packets[1:])]
        active, idle = self._activity_periods(packets)
        flags = {flag: sum(flag in packet.flags for packet in packets) for flag in ("S", "R", "P", "A")}
        return {
            "Dst Port": float(self.destination_port), "Protocol": float(self.protocol), "Flow Duration": duration_microseconds,
            "Tot Fwd Pkts": float(len(forward_lengths)), "Tot Bwd Pkts": float(len(backward_lengths)),
            "TotLen Fwd Pkts": float(sum(forward_lengths)), "TotLen Bwd Pkts": float(sum(backward_lengths)),
            "Fwd Pkt Len Max": self._max(forward_lengths), "Fwd Pkt Len Mean": self._mean(forward_lengths), "Fwd Pkt Len Std": self._std(forward_lengths),
            "Bwd Pkt Len Max": self._max(backward_lengths), "Bwd Pkt Len Mean": self._mean(backward_lengths), "Bwd Pkt Len Std": self._std(backward_lengths),
            "Flow Byts/s": float(sum(all_lengths)) / duration_seconds, "Flow Pkts/s": float(len(packets)) / duration_seconds,
            "Flow IAT Mean": self._mean(iats) * 1_000_000, "Flow IAT Std": self._std(iats) * 1_000_000, "Flow IAT Max": self._max(iats) * 1_000_000, "Flow IAT Min": self._min(iats) * 1_000_000,
            "SYN Flag Cnt": float(flags["S"]), "RST Flag Cnt": float(flags["R"]), "PSH Flag Cnt": float(flags["P"]), "ACK Flag Cnt": float(flags["A"]),
            "Pkt Len Min": self._min(all_lengths), "Pkt Len Max": self._max(all_lengths), "Pkt Len Mean": self._mean(all_lengths), "Pkt Len Std": self._std(all_lengths),
            "Down/Up Ratio": float(len(backward_lengths)) / max(1, len(forward_lengths)), "Init Fwd Win Byts": float(self._forward[0].tcp_window if self._forward else 0), "Init Bwd Win Byts": float(self._backward[0].tcp_window if self._backward else 0),
            "Active Mean": self._mean(active) * 1_000_000, "Active Std": self._std(active) * 1_000_000, "Active Max": self._max(active) * 1_000_000, "Active Min": self._min(active) * 1_000_000,
            "Idle Mean": self._mean(idle) * 1_000_000, "Idle Std": self._std(idle) * 1_000_000, "Idle Max": self._max(idle) * 1_000_000, "Idle Min": self._min(idle) * 1_000_000,
        }

    @staticmethod
    def _activity_periods(packets: list[PacketObservation]) -> tuple[list[float], list[float]]:
        active_start = packets[0].timestamp
        previous = packets[0].timestamp
        active: list[float] = []
        idle: list[float] = []
        for packet in packets[1:]:
            gap = packet.timestamp - previous
            if gap > 1.0:
                active.append(max(0.0, previous - active_start))
                idle.append(gap)
                active_start = packet.timestamp
            previous = packet.timestamp
        active.append(max(0.0, previous - active_start))
        return active, idle

    @staticmethod
    def _mean(values: list[float | int]) -> float: return float(fmean(values)) if values else 0.0
    @staticmethod
    def _std(values: list[float | int]) -> float: return float(pstdev(values)) if len(values) > 1 else 0.0
    @staticmethod
    def _min(values: list[float | int]) -> float: return float(min(values)) if values else 0.0
    @staticmethod
    def _max(values: list[float | int]) -> float: return float(max(values)) if values else 0.0
