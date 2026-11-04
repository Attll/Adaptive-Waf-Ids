"""Fail clearly before serving when a curated release artifact is absent or changed."""
import hashlib
import json
import os
from pathlib import Path
import sys

manifest=Path('/app/model-manifest.json')
if manifest.exists():
    for row in json.loads(manifest.read_text())['artifacts']:
        path=Path('/app')/row['path'].replace('\\','/')
        with path.open('rb') as source:
            digest=hashlib.file_digest(source,'sha256').hexdigest()
        if digest!=row['sha256']:raise RuntimeError(f'model integrity failed: {path}')
os.execvp(sys.argv[1],sys.argv[1:])
