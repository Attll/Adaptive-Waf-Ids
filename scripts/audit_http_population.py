"""Stream train/validation provenance and candidate-view leakage; never opens the legacy test split."""
import argparse
from collections import Counter,defaultdict
import hashlib
import json
from pathlib import Path
import sqlite3
from adaptive_waf.features.inspection import VERSION,inspection_group,inspection_text
from adaptive_waf.training.http_data import _read_jsonl,_request_from_record


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset',type=Path,default=Path('datasets/processed/atrdf/atrdf-dataset3-dataset4-v1'))
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if args.output.exists(): parser.error('new output directory required')
    args.output.mkdir(parents=True)
    database=sqlite3.connect(args.output/'groups.sqlite')
    database.executescript('create table observations(split text, group_id text, label text); create index group_index on observations(group_id);')
    counts,headers,clipping=defaultdict(Counter),defaultdict(Counter),defaultdict(Counter)
    source_hashes={}
    for split in ('train','validation'):
        path=args.dataset/(split+'.jsonl')
        with path.open('rb') as stream: source_hashes[split]=hashlib.file_digest(stream,'sha256').hexdigest()
        batch=[]
        for index,row in enumerate(_read_jsonl(path),1):
            request=_request_from_record(row['request'])
            group=inspection_group(request)
            counts[split][row['label']]+=1
            headers[row['label']].update(name.lower() for name in request.headers)
            clipping[row['label']].update(inspection_text(request,512).truncated_fields)
            batch.append((split,group,row['label']))
            if len(batch)>=2000:
                database.executemany('insert into observations values(?,?,?)',batch)
                database.commit();batch=[]
            if index%50000==0: print(split,index,flush=True)
        database.executemany('insert into observations values(?,?,?)',batch);database.commit()
    conflicts=database.execute('select count(*) from (select group_id from observations group by group_id having count(distinct label)>1)').fetchone()[0]
    overlap=database.execute('select count(*) from (select group_id from observations group by group_id having count(distinct split)>1)').fetchone()[0]
    groups={label:n for label,n in database.execute('select label,count(distinct group_id) from observations group by label')}
    result={'representation':VERSION,'sources_sha256':source_hashes,'counts':counts,'groups_per_label':groups,
        'representation_source_sha256':hashlib.sha256(Path('src/adaptive_waf/features/inspection.py').read_bytes()).hexdigest(),
        'conflicting_label_groups':conflicts,'train_validation_overlapping_candidate_groups':overlap,
        'headers_per_label':headers,'field_truncations_at_512_character_budget':clipping,'legacy_test_opened':False,
        'scope':'Dataset quality audit of previously used train/validation, not independent final evaluation. No request content exported.'}
    (args.output/'audit.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    database.close()
    print(json.dumps({key:result[key] for key in ('groups_per_label','conflicting_label_groups','train_validation_overlapping_candidate_groups')},indent=2))


if __name__=='__main__':main()
