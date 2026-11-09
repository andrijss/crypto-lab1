"""Thread-safe, short-lived progress snapshots. No keys or file contents."""
import re
import threading
import time

_records = {}
_lock = threading.Lock()
_STAGES = {
    'uploading': (0, 10),
    'preparing': (10, 20),
    'encrypting': (20, 95),
    'decrypting': (20, 95),
    'verifying': (95, 97),
    'finalizing': (97, 99),
    'completed': (100, 100),
}


def _expire():
    cutoff = time.monotonic() - 3600
    for ident in list(_records):
        if _records[ident]['updated'] < cutoff:
            del _records[ident]


def start(ident):
    if not isinstance(ident, str) or not re.fullmatch(r'[0-9a-f]{32}', ident):
        raise ValueError('Invalid progress ID')
    with _lock:
        _expire()
        if ident in _records:
            raise ValueError('Progress ID is already in use')
        _records[ident] = dict(stage='uploading', value=0, updated=time.monotonic())


def update(ident, stage, completed=0, total=1):
    with _lock:
        record = _records.get(ident)
        if record is None:
            return
        if stage != 'failed':
            lower, upper = _STAGES[stage]
            fraction = min(1, max(0, completed / total)) if total else 1
            record['value'] = max(record['value'], round(lower + (upper - lower) * fraction))
        record['stage'] = stage
        record['updated'] = time.monotonic()


def snapshot(ident):
    with _lock:
        _expire()
        record = _records.get(ident)
        return {k: record[k] for k in ('stage', 'value')} if record else None
