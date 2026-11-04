import unittest
from adaptive_waf.network_sensor.table import FlowTable
from adaptive_waf.network_sensor.flows import PacketObservation


def packet(port=1, timestamp=0, flags=frozenset()):
    return PacketObservation("192.0.2.1", "192.0.2.2", port, 80, 6, timestamp, 60, flags)


class FlowTableTests(unittest.TestCase):
    def test_packet_and_flow_capacity_are_bounded(self):
        table = FlowTable(max_flows=2, max_packets=3)
        self.assertFalse(table.add(packet()))
        table.add(packet(timestamp=.1))
        emitted = table.add(packet(timestamp=.2))
        self.assertEqual(emitted[0].reason, "PACKET_LIMIT")
        self.assertEqual(emitted[0].flow.features()["Tot Fwd Pkts"], 3)
        for port in range(10):
            table.add(packet(port, 1))
        self.assertLessEqual(len(table.flows), 2)
        self.assertLessEqual(table.retained_packets, 6)

    def test_idle_close_and_periodic_expiry(self):
        table = FlowTable(idle_seconds=2)
        table.add(packet())
        self.assertEqual(table.poll(3)[0].reason, "IDLE")
        self.assertFalse(table.flows)
        self.assertFalse(table.add(packet(timestamp=4)))
        self.assertFalse(table.add(packet(timestamp=4.1, flags=frozenset({"F"})))[0].partial)
