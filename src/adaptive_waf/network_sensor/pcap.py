"""Scapy transport observation shared by capture and offline reference comparisons."""
from adaptive_waf.network_sensor.flows import PacketObservation


def observe_packet(packet):
    from scapy.all import IP, IPv6, IPv6ExtHdrFragment, TCP, UDP
    if (IP not in packet and IPv6 not in packet) or (TCP not in packet and UDP not in packet):
        return None
    network = packet[IP] if IP in packet else packet[IPv6]
    transport = packet[TCP] if TCP in packet else packet[UDP]
    if IP in packet and (int(network.frag) or int(network.flags) & 1) or IPv6ExtHdrFragment in packet:
        raise ValueError('fragmented packet needs reassembly; flow payload measurement unavailable')
    captured = len(bytes(transport))
    if IP in packet:
        declared = int(network.len or len(bytes(network))) - int(network.ihl or 5)*4
    else:
        declared = int(network.plen if network.plen is not None else len(bytes(network.payload))) - (len(bytes(network.payload))-captured)
    header = int(transport.dataofs or 5)*4 if TCP in packet else 8
    if UDP in packet:
        declared = min(declared,int(transport.len or declared))
    if declared < header or declared > captured:
        raise ValueError('truncated/invalid transport packet; flow payload measurement unavailable')
    return PacketObservation(str(network.src),str(network.dst),int(transport.sport),int(transport.dport),
            6 if TCP in packet else 17,float(packet.time),len(bytes(packet)),
            frozenset(str(transport.flags)) if TCP in packet else frozenset(),int(transport.window) if TCP in packet else 0,
            payload_length=declared-header)
