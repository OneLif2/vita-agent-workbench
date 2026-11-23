"""Compare *device-reported* local wall clock times. No sockets or content access.

'MATCH' means time candidate, never the identity, fault type or cause of a crash.
We don't convert to the 5090's timezone or trust epoch-like digits in filenames.
"""
from datetime import datetime
import re

_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\Z")

def _stamp(value):
    if not isinstance(value,str) or not _STAMP.fullmatch(value):
        raise ValueError("expected local device time YYYY-MM-DDTHH:MM:SS without timezone")
    try:
        return datetime.strptime(value,"%Y-%m-%dT%H:%M:%S")
    except ValueError as exc:
        raise ValueError("invalid calendar date or time") from exc

def validate_window(since, until):
    if since is None and until is None:
        return None
    if since is None or until is None:
        raise ValueError("--since and --until must be supplied together")
    a,b=_stamp(since),_stamp(until)
    if a>b:raise ValueError("--since must not be later than --until")
    return a,b

def classify(rows, matched, truncated, since, until):
    window=validate_window(since,until)
    if window is None:raise ValueError("a time window is required")
    if type(matched) is not int or not isinstance(rows,list) or len(rows)>32 or matched<len(rows):
        raise ValueError("invalid index counts")
    if type(truncated) not in (bool,int) or truncated not in (0,1) or bool(truncated)!=(matched>len(rows)):
        raise ValueError("inconsistent truncation metadata")
    a,b=window;hits=[];unknown=0
    for item in rows:
        t=item["modified"]
        if t is None or t=="unknown":unknown+=1
        elif a<=_stamp(t)<=b:hits.append(item["name"])
    coverage='complete' if not unknown and not truncated else 'incomplete'
    return dict(status='MATCH' if hits else ('NO_MATCH' if coverage=='complete' else 'INCONCLUSIVE'),
                candidates=hits,coverage=coverage,unknown_time_count=unknown,
                from_local=since,to_local=until)
