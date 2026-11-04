"""Compare versioned extraction against an independently generated, PCAP-pinned feature reference.

This tool does not manufacture a CICFlowMeter reference. Matching a controlled
arithmetic fixture is useful regression evidence but not CICIDS feature parity.
"""
import argparse
from collections import defaultdict
import json
import math
from pathlib import Path

from adaptive_waf.network_sensor.pcap import observe_packet
from adaptive_waf.network_sensor.table import FlowTable
from adaptive_waf.training.candidate_data import sha256


def extract(pcap, contract, bounds):
    from scapy.all import PcapReader
    table = FlowTable(feature_contract=contract,**bounds)
    emissions, count, last = [], 0, 0
    with PcapReader(str(pcap)) as packets:
        for packet in packets:
            count += 1
            if count > 10000:
                raise ValueError('comparison limited to 10,000 packets')
            observation = observe_packet(packet)
            if observation is None:continue
            last = max(last,observation.timestamp)
            emissions.extend(table.add(observation))
    emissions.extend(table.poll(last,final=True))
    windows, rows = defaultdict(int), []
    for emission in emissions:
        flow = emission.flow
        key = (flow.source_ip,flow.destination_ip,flow.source_port,flow.destination_port,flow.protocol)
        ordinal = windows[key]
        windows[key] += 1
        rows.append({'key':list(key),'window':ordinal,'reason':emission.reason,'partial':emission.partial,'features':flow.features()})
    return rows,count


def compare(pcap, reference_path, contract='payload-sample-v2', atol=1e-6, rtol=1e-6):
    if Path(pcap).stat().st_size > 64*1024**2 or Path(reference_path).stat().st_size > 10*1024**2:
        raise ValueError('reference comparison file capacity exceeded')
    reference = json.loads(Path(reference_path).read_text(encoding='utf-8'))
    if sha256(pcap) != reference['pcap_sha256']:
        raise ValueError('reference PCAP hash mismatch')
    if reference['reference_kind'] not in {'CONTROLLED_ARITHMETIC','CICFLOWMETER_REFERENCE'}:
        raise ValueError('unknown reference provenance')
    if not reference.get('reference_provenance'):
        raise ValueError('independent reference provenance required')
    if not 0 <= atol <= .01 or not 0 <= rtol <= .01:
        raise ValueError('comparison tolerance exceeds bounds')
    rows,packets = extract(pcap,contract,reference.get('window_bounds',{}))
    actual = {(tuple(row['key']),row['window']):row for row in rows}
    expected = {(tuple(row['key']),row['window']):row for row in reference['flows']}
    if len(expected) != len(reference['flows']):
        raise ValueError('duplicate reference flow/window')
    differences = []
    for key in sorted(set(actual)|set(expected)):
        if key not in actual or key not in expected:
            differences.append({'flow':key,'reason':'missing extracted or reference window'})
            continue
        a,e = actual[key]['features'],expected[key]['features']
        for feature in sorted(set(a)|set(e)):
            if feature not in a or feature not in e or not math.isfinite(e[feature]) or not math.isclose(a[feature],e[feature],abs_tol=atol,rel_tol=rtol):
                differences.append({'flow':key,'feature':feature,'actual':a.get(feature),'expected':e.get(feature)})
    return {'pcap_sha256':sha256(pcap),'reference_sha256':sha256(reference_path),'feature_contract':contract,
            'reference_kind':reference['reference_kind'],'reference_provenance':reference['reference_provenance'],
            'packets':packets,'flows':len(rows),'all_features_match':not differences,'differences':differences,
            'atol':atol,'rtol':rtol,'extracted':rows,
            'acceptance_scope':'controlled fixture only; application/dataset/native parser equivalence requires a matching pinned reference campaign'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap',type=Path,required=True)
    parser.add_argument('--reference',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--contract',choices=['frame-population-v1','payload-sample-v2'],default='payload-sample-v2')
    args = parser.parse_args()
    if args.output.exists():parser.error('new result path required')
    result = compare(args.pcap,args.reference,args.contract)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x',encoding='utf-8') as output:json.dump(result,output,indent=2,allow_nan=False)
    print(json.dumps({'all_features_match':result['all_features_match'],'differences':len(result['differences']),'reference_kind':result['reference_kind']}))
    if not result['all_features_match']:raise SystemExit(1)


if __name__ == '__main__':main()
