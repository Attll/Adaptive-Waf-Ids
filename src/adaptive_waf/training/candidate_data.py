"""Frozen prospective populations and field-budgeted candidate inputs."""
from collections import Counter
import hashlib
import json
from pathlib import Path

from adaptive_waf.contracts import HttpRequestRecord
from adaptive_waf.features.classical import ClassicalFeatureExtractor
from adaptive_waf.features.inspection import VERSION, components, inspection_group, inspection_text, _decode
from adaptive_waf.training.http_data import _read_jsonl, _request_from_record

TOKEN_VERSION = 'field-token-budget-v1'
WEIGHTS = {'METHOD': 1, 'PATH': 4, 'QUERY': 9, 'COOKIES': 7, 'BODY': 9, 'CONTENT_TYPE': 2}


def sha256(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def protocol_manifest(directory):
    manifest = json.loads((Path(directory) / 'manifest.json').read_text(encoding='utf-8'))
    if manifest['representation'] != VERSION:
        raise ValueError('unsupported input representation')
    import adaptive_waf.features.inspection as representation
    if sha256(representation.__file__) != manifest['representation_source_sha256']:
        raise ValueError('representation changed after population freeze')
    groups = manifest['group_ids']
    seen = set()
    for role in ('train', 'tune', 'evaluation'):
        current = groups[role]
        if len(current) != len(set(current)) or seen.intersection(current):
            raise ValueError('population group overlap')
        seen.update(current)
    return manifest


def load_role(directory, role):
    if role not in {'train', 'tune', 'evaluation'}:
        raise ValueError('unknown population role')
    manifest = protocol_manifest(directory)
    path = Path(directory) / (role + '.jsonl')
    if sha256(path) != manifest['sha256'][role]:
        raise ValueError('population content hash mismatch')
    requests, labels, identifiers = [], [], []
    for row in _read_jsonl(path):
        request = _request_from_record(row['request'])
        if row['population'] != role or inspection_group(request) != row['group_id']:
            raise ValueError('population provenance mismatch')
        requests.append(request)
        labels.append(row['label'])
        identifiers.append(row['group_id'])
    if sorted(identifiers) != manifest['group_ids'][role] or dict(Counter(labels)) != manifest['counts'][role]:
        raise ValueError('population membership/count mismatch')
    return requests, labels, manifest, identifiers


def lexical_inputs(requests):
    return [inspection_text(request, 2048).text for request in requests]


def structural_inputs(requests):
    # Remove exactly the same transport metadata in fitting and serving.
    extractor = ClassicalFeatureExtractor()
    values = []
    for request in requests:
        content_type = components(request)['CONTENT_TYPE']
        clean = HttpRequestRecord(request.method, request.path, request.query,
                                  {'content-type': content_type} if content_type else {}, request.cookies, request.body)
        values.append(extractor.extract(clean).values)
    return values


def field_tokens(request, encode, max_length, *, cls_id, sep_id, pad_id):
    """Independent head/tail token quotas prevent long fields starving later ones.

    Operate on components, never parse marker text that an attacker can inject.
    Raw and once-decoded alternatives share each field's quota.
    """
    if not 64 <= max_length <= 4096:
        raise ValueError('token budget must be 64..4096')
    fields = components(request)
    result = [cls_id]
    available = max_length - 1 - len(fields)
    total = sum(WEIGHTS.values())
    for name, value in fields.items():
        if name in {'PATH', 'QUERY', 'COOKIES'}:
            decoded = _decode(value, name)
            if decoded != value:
                value += '\n' + decoded
        # Bound tokenizer work as well as the resulting tensor.
        if len(value) > 16384:
            value = value[:8192] + value[-8192:]
        ids = encode('[' + name + ']\n' + value)
        quota = available * WEIGHTS[name] // total
        if len(ids) > quota:
            head = quota // 2
            ids = ids[:head] + ids[-(quota-head):]
        result.extend(ids)
        result.append(sep_id)
    return result + [pad_id] * (max_length-len(result))


def byte_tokens(request, max_length=1024):
    return field_tokens(request, lambda value: [b+3 for b in value.encode('utf-8')], max_length,
                        cls_id=1, sep_id=2, pad_id=0)
