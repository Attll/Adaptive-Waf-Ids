"""Versioned learned-model input, shared by candidate training and serving. No attack rules."""
from dataclasses import dataclass
import json
import unicodedata
from urllib.parse import unquote,unquote_plus
from adaptive_waf.contracts import HttpRequestRecord
from adaptive_waf.data.preparation import near_duplicate_group_key

VERSION = "http-inspection-text-v2"


def _text(value):
    return unicodedata.normalize("NFKC", str(value)).replace('\r\n','\n')


def _decode(value,field):
    # Decode once to match URL query interpretation, retaining raw text independently for inference.
    return (unquote_plus if field=="QUERY" else unquote)(_text(value))


def components(request):
    content_type=next((str(v).split(';',1)[0].strip().lower() for k,v in request.headers.items() if k.lower()=="content-type"),"")
    return {"METHOD":_text(request.method).upper(),"PATH":_text(request.path),"QUERY":_text(request.query),
        "COOKIES":json.dumps(dict(sorted(request.cookies.items())),ensure_ascii=False,separators=(',',':')),
        "BODY":_text(request.body),"CONTENT_TYPE":content_type}


def inspection_group(request):
    fields=components(request)
    # Transport variants belong to one group; source filenames, labels and transport metadata never enter it.
    for name in ("PATH","QUERY","COOKIES"):
        fields[name]=_decode(fields[name],name)
    return near_duplicate_group_key(json.dumps(fields,sort_keys=True,ensure_ascii=False))


def _window(value,limit):
    if len(value)<=limit: return value
    return value[:limit//2]+value[-(limit-limit//2):] if limit else ""


@dataclass(frozen=True)
class InspectionText:
    text: str
    truncated_fields: tuple[str,...]
    version: str = VERSION


def inspection_text(request:HttpRequestRecord,max_chars=2048):
    if max_chars<256 or max_chars>32768:
        raise ValueError("candidate text budget must be 256..32768 characters")
    fields=components(request)
    names=tuple(fields)
    overhead=sum(len(name)+3 for name in names)+len(names)-1
    available=max_chars-overhead
    weights={"METHOD":1,"PATH":4,"QUERY":9,"COOKIES":7,"BODY":9,"CONTENT_TYPE":2}
    total=sum(weights.values())
    parts,truncated=[],[]
    for name,value in fields.items():
        if name in {"PATH","QUERY","COOKIES"}:
            decoded=_decode(value,name)
            if decoded!=value: value=value+"\n"+decoded
        budget=available*weights[name]//total
        if len(value)>budget: truncated.append(name)
        parts.append(f"[{name}]\n"+_window(value,budget))
    return InspectionText('\n'.join(parts),tuple(truncated))
