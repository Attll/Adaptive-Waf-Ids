"""Freeze a small group-disjoint new-candidate protocol from existing train/validation only."""
import argparse
from collections import Counter,defaultdict
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sqlite3
from adaptive_waf.features.inspection import VERSION,inspection_group
from adaptive_waf.training.http_data import _read_jsonl,_request_from_record


def allocate_groups(groups,seed=20261028):
    result={}
    for label,identifiers in groups.items():
        if len(set(identifiers))!=len(identifiers) or set(result).intersection(identifiers):
            raise ValueError('duplicate or cross-label groups')
        identifiers=sorted(identifiers,key=lambda key:hashlib.sha256(f'{seed}:{key}'.encode()).digest())
        if len(identifiers)<3: raise ValueError(f'{label} needs at least three distinct groups')
        tune=max(1,int(len(identifiers)*.15));evaluation=max(1,int(len(identifiers)*.15))
        train=len(identifiers)-tune-evaluation
        result.update({key:(label,'train' if index<train else 'tune' if index<train+tune else 'evaluation') for index,key in enumerate(identifiers)})
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset',type=Path,default=Path('datasets/processed/atrdf/atrdf-dataset3-dataset4-v1'))
    parser.add_argument('--audit',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--seed',type=int,default=20261028)
    args=parser.parse_args()
    if args.output.exists():parser.error('new output directory required')
    audit=json.loads((args.audit/'audit.json').read_text(encoding='utf-8'))
    if hashlib.sha256(Path('src/adaptive_waf/features/inspection.py').read_bytes()).hexdigest()!=audit['representation_source_sha256']:
        parser.error('representation changed since audit; create a new audited protocol')
    # Audit provenance must match before any selection is written.
    for split in ('train','validation'):
        with (args.dataset/(split+'.jsonl')).open('rb') as source:
            if hashlib.file_digest(source,'sha256').hexdigest()!=audit['sources_sha256'][split]:
                parser.error('source changed since quality audit')
    db=sqlite3.connect(f'file:{(args.audit/"groups.sqlite").as_posix()}?mode=ro',uri=True)
    groups=defaultdict(list)
    for key,label in db.execute('select group_id,min(label) from observations group by group_id having count(distinct label)=1'):
        groups[label].append(key)
    db.close()
    assignments=allocate_groups(groups,args.seed)
    caps={'train':1000,'tune':200,'evaluation':200}
    selected={};counts=defaultdict(Counter)
    for key,(label,role) in sorted(assignments.items(),key=lambda row:hashlib.sha256(f'{args.seed}:{row[0]}'.encode()).digest()):
        if counts[role][label]<caps[role]:
            selected[key]=(label,role);counts[role][label]+=1
    args.output.mkdir(parents=True)
    streams={role:(args.output/(role+'.jsonl')).open('x',encoding='utf-8') for role in caps}
    seen=set()
    try:
        for split in ('train','validation'):
            for row in _read_jsonl(args.dataset/(split+'.jsonl')):
                key=inspection_group(_request_from_record(row['request']))
                if key in seen or key not in selected:continue
                label,role=selected[key]
                if row['label']!=label:raise ValueError('group label changed')
                seen.add(key)
                value={'request':row['request'],'label':label,'group_id':key,'request_id':hashlib.sha256((VERSION+':'+key).encode()).hexdigest(),
                    'population':role,'label_source':'DATASET_ANNOTATION','source':row['source']}
                streams[role].write(json.dumps(value,ensure_ascii=False)+'\n')
    finally:
        for stream in streams.values():stream.close()
    if len(seen)!=len(selected):raise ValueError('audit/source grouping mismatch')
    hashes={}
    for role in caps:
        with (args.output/(role+'.jsonl')).open('rb') as source:hashes[role]=hashlib.file_digest(source,'sha256').hexdigest()
    manifest={'created_at':datetime.now(timezone.utc).isoformat(),'seed':args.seed,'representation':VERSION,'counts':counts,'sha256':hashes,
        'source_sha256':audit['sources_sha256'],'group_ids':{role:sorted(key for key,(_,r) in selected.items() if r==role) for role in caps},
        'representation_source_sha256':audit['representation_source_sha256'],
        'one_representative_per_group':True,'legacy_test_opened':False,'evaluation_access':'No evaluation predictions before all configurations are frozen and training is approved',
        'limitations':['Prospective holdout only for newly initialized candidates; legacy models have seen the source training population.',
            'Dataset annotation is not an independent operator verification or proof of successful exploitation.',
            'XSS/RCE/cookie template counts are too small for separate six-class calibration, policy training and final populations.',
            'No claim of application-separated or real-world generalization.']}
    (args.output/'manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    print(json.dumps({'counts':counts,'sha256':hashes},indent=2))


if __name__=='__main__':main()
