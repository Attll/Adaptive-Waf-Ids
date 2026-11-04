import json
import math
from pathlib import Path
import tempfile
import unittest
import importlib.util

from adaptive_waf.network_sensor.flows import FlowAccumulator, PacketObservation
from adaptive_waf.network_sensor.pcap import observe_packet
from adaptive_waf.training.candidate_data import sha256
from scripts.compare_network_features import compare


class NetworkFeatureContractTests(unittest.TestCase):
    def test_versioned_payload_and_sample_std_preserve_legacy_values(self):
        packets = [PacketObservation('192.0.2.1','192.0.2.2',1234,80,6,1,60,payload_length=0),
                   PacketObservation('192.0.2.1','192.0.2.2',1234,80,6,1.5,64,payload_length=4)]
        legacy = FlowAccumulator.from_packet(packets[0])
        candidate = FlowAccumulator.from_packet(packets[0],'payload-sample-v2')
        legacy.add(packets[1]);candidate.add(packets[1])
        self.assertEqual(legacy.features()['TotLen Fwd Pkts'],124)
        self.assertEqual(legacy.features()['Fwd Pkt Len Std'],2)
        self.assertEqual(candidate.features()['TotLen Fwd Pkts'],4)
        self.assertAlmostEqual(candidate.features()['Fwd Pkt Len Std'],math.sqrt(8))
        with self.assertRaisesRegex(ValueError,'measured'):
            FlowAccumulator.from_packet(PacketObservation('192.0.2.1','192.0.2.2',1,2,6,1,60),'payload-sample-v2')

    @unittest.skipUnless(importlib.util.find_spec('scapy'),'optional sensor dependency required')
    def test_real_pcap_roundtrip_compares_to_hand_calculated_38_features(self):
        from scapy.all import Ether,IP,TCP,Raw,PcapReader,wrpcap
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packets = [Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src='192.0.2.1',dst='192.0.2.2')/TCP(sport=1234,dport=80,flags='S',window=100),
                       Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src='192.0.2.1',dst='192.0.2.2')/TCP(sport=1234,dport=80,flags='PA',window=200)/Raw(b'abcd')]
            packets[0].time,packets[1].time = 1,1.5
            wrpcap(str(root/'controlled.pcap'),packets)
            features = {'Dst Port':80.,'Protocol':6.,'Flow Duration':500000.,'Tot Fwd Pkts':2.,'Tot Bwd Pkts':0.,
                'TotLen Fwd Pkts':4.,'TotLen Bwd Pkts':0.,'Fwd Pkt Len Max':4.,'Fwd Pkt Len Mean':2.,'Fwd Pkt Len Std':math.sqrt(8),
                'Bwd Pkt Len Max':0.,'Bwd Pkt Len Mean':0.,'Bwd Pkt Len Std':0.,'Flow Byts/s':8.,'Flow Pkts/s':4.,
                'Flow IAT Mean':500000.,'Flow IAT Std':0.,'Flow IAT Max':500000.,'Flow IAT Min':500000.,
                'SYN Flag Cnt':1.,'RST Flag Cnt':0.,'PSH Flag Cnt':1.,'ACK Flag Cnt':1.,
                'Pkt Len Min':0.,'Pkt Len Max':4.,'Pkt Len Mean':2.,'Pkt Len Std':math.sqrt(8),'Down/Up Ratio':0.,
                'Init Fwd Win Byts':100.,'Init Bwd Win Byts':0.,'Active Mean':500000.,'Active Std':0.,'Active Max':500000.,'Active Min':500000.,
                'Idle Mean':0.,'Idle Std':0.,'Idle Max':0.,'Idle Min':0.}
            reference = {'pcap_sha256':sha256(root/'controlled.pcap'),'reference_kind':'CONTROLLED_ARITHMETIC',
                         'reference_provenance':'Two packets, times 1/1.5s, transport payloads 0/4 bytes; independent arithmetic in regression fixture, not native CICFlowMeter output.',
                         'flows':[{'key':['192.0.2.1','192.0.2.2',1234,80,6],'window':0,'features':features}]}
            (root/'reference.json').write_text(json.dumps(reference))
            self.assertTrue(compare(root/'controlled.pcap',root/'reference.json')['all_features_match'])
            self.assertFalse(compare(root/'controlled.pcap',root/'reference.json','frame-population-v1')['all_features_match'])
            with PcapReader(str(root/'controlled.pcap')) as reader:
                observations = [observe_packet(packet) for packet in reader]
            self.assertEqual([value.payload_length for value in observations],[0,4])
            with (root/'controlled.pcap').open('ab') as output:output.write(b'changed')
            with self.assertRaisesRegex(ValueError,'hash'):compare(root/'controlled.pcap',root/'reference.json')

    @unittest.skipUnless(importlib.util.find_spec('scapy'),'optional sensor dependency required')
    def test_ipv6_udp_padding_and_truncation_have_explicit_bounds(self):
        from scapy.all import Ether,IP,IPv6,TCP,UDP,Raw,Padding
        packet = Ether(bytes(Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IPv6(src='2001:db8::1',dst='2001:db8::2')/UDP(sport=2,dport=3)/Raw(b'xyz')))
        self.assertEqual(observe_packet(packet).payload_length,3)
        padded = Ether(bytes(Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP()/UDP()/Raw(b'abc'))+b'\x00'*20)
        self.assertEqual(observe_packet(padded).payload_length,3)
        truncated = Ether(bytes(Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP()/TCP()/Raw(b'abc'))[:-1])
        with self.assertRaisesRegex(ValueError,'truncated'):observe_packet(truncated)
        with self.assertRaisesRegex(ValueError,'fragmented'):observe_packet(IP(flags='MF')/TCP())
