"""Create a curated Docker model context, verifying the preserved baseline manifest."""
import json
from pathlib import Path
import shutil
from adaptive_waf.training.candidate_data import sha256

def main():
    manifest=json.loads(Path('research/results/artifact_manifest.json').read_text(encoding='utf-8'))
    root=Path('release-build')
    original=list(manifest['artifacts'])
    for row in manifest['artifacts']:
        source=Path(row['path'].replace('\\','/'))
        if sha256(source)!=row['sha256']:raise ValueError(f'baseline artifact changed: {source}')
        target=root/source
        target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(source,target)
    known={row['path'].replace('\\','/') for row in manifest['artifacts']}
    # Model Lab serves only already-trained candidates from the selected runs.
    for row in original:
        source=Path(row['path'].replace('\\','/'))
        if source.name=='model.joblib' and source.parent.name in {'random_forest','extra_trees','logistic_regression'}:
            for algorithm in ('random_forest','extra_trees','logistic_regression'):
                extra=source.parent.parent/algorithm/'model.joblib';key=extra.as_posix()
                if extra.is_file() and key not in known:
                    target=root/extra;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(extra,target)
                    manifest['artifacts'].append({'path':key,'bytes':extra.stat().st_size,'sha256':sha256(extra)});known.add(key)
    # Retain selected-run catalog metadata without copying alternative model binaries.
    for row in original:
        source=Path(row['path'].replace('\\','/'))
        for parent in source.parents:
            if parent==Path('artifacts/training'):break
            for name in ('config.json','metrics.json','feature_manifest.json'):
                extra=parent/name;key=extra.as_posix()
                if extra.is_file() and key not in known:
                    target=root/extra;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(extra,target)
                    manifest['artifacts'].append({'path':key,'bytes':extra.stat().st_size,'sha256':sha256(extra)})
                    known.add(key)
    (root/'model-manifest.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
    (root/'sensor-model-manifest.json').write_text(json.dumps({'artifacts':[row for row in manifest['artifacts'] if '/network/' in row['path'].replace('\\','/')]}),encoding='utf-8')
    print(f"Verified {len(original)} baseline artifacts; staged {len(manifest['artifacts'])} files including catalog metadata")

if __name__=='__main__':main()
