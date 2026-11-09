import base64
import uuid
from unittest.mock import patch

import pytest

from backend import progress
from backend.crypto import generate
from backend.files import transform
from backend.server import Handler, jobs
from test_api import call


def get_progress(ident):
    handler = Handler.__new__(Handler)
    handler.path = '/api/progress/' + ident
    handler.send = lambda status, payload: setattr(handler, 'result', (status, payload))
    handler.do_GET()
    return handler.result


def test_live_progress_and_completion():
    ident = uuid.uuid4().hex
    key = base64.b64encode(generate('DES')).decode()
    observed = []

    def operation(source, target, key, **options):
        # The input is available before the crypto operation starts.
        assert source.read_bytes() == b'input'
        observed.append(get_progress(ident)[1]['value'])
        options['progress']('encrypting', 5, 10)
        observed.append(get_progress(ident)[1]['value'])
        options['progress']('verifying', 0, 1)
        observed.append(get_progress(ident)[1]['value'])
        target.write_bytes(b'ciphertext')
        return {}

    with patch('backend.server.transform', side_effect=operation):
        status, result = call('/api/transform', b'input', {'key': key, 'progress_id': ident})
    assert status == 200
    assert 0 < observed[0] < observed[1] < observed[2] < 100
    assert get_progress(ident) == (200, {'stage': 'completed', 'value': 100})
    jobs.pop(result['id'])[0].unlink()


def test_failed_operation_does_not_report_completion():
    ident = uuid.uuid4().hex
    status, _ = call('/api/transform', b'input', {'key': base64.b64encode(b'bad').decode(), 'progress_id': ident})
    assert status == 400
    status, result = get_progress(ident)
    assert status == 200
    assert result['stage'] == 'failed'
    assert result['value'] < 100


def test_progress_ids_and_missing_status():
    assert get_progress(uuid.uuid4().hex)[0] == 404
    for ident in ('', '../file', 1, 'x' * 32):
        with pytest.raises(ValueError):
            progress.start(ident)
    ident = uuid.uuid4().hex
    progress.start(ident)
    with pytest.raises(ValueError):
        progress.start(ident)


@pytest.mark.parametrize('length', [0, 1, 128])
def test_stream_reports_processed_bytes_for_both_directions(tmp_path, length):
    source, encrypted, restored = (tmp_path / name for name in ('input', 'encrypted', 'restored'))
    source.write_bytes(bytes(length))
    key = generate('DES')
    for decrypt in (False, True):
        events = []
        transform(encrypted if decrypt else source, restored if decrypt else encrypted,
                  key, decrypt=decrypt, buffer=32,
                  progress=lambda *event: events.append(event))
        phase = 'decrypting' if decrypt else 'encrypting'
        processed = [(done, total) for stage, done, total in events if stage == phase]
        total = (length // 8 + 1) * 8 if decrypt else length
        assert processed[0] == (0, total)
        assert processed[-1] == (total, total)
        assert events[-1][0] == 'verifying'
    assert restored.read_bytes() == source.read_bytes()


def test_progress_header_with_real_crypto():
    ident = uuid.uuid4().hex
    key = base64.b64encode(generate('DES')).decode()
    status, result = call('/api/transform', b'progress header input',
                          {'key': key}, headers={'X-Progress-ID': ident})
    assert status == 200
    assert get_progress(ident) == (200, {'stage': 'completed', 'value': 100})
    encrypted = jobs.pop(result['id'])[0]
    try:
        decrypt_id = uuid.uuid4().hex
        status, restored = call('/api/transform', encrypted.read_bytes(),
                                {'key': key, 'decrypt': True},
                                headers={'X-Progress-ID': decrypt_id})
        assert status == 200
        assert get_progress(decrypt_id)[1]['value'] == 100
        output = jobs.pop(restored['id'])[0]
        assert output.read_bytes() == b'progress header input'
        output.unlink()
    finally:
        encrypted.unlink()
