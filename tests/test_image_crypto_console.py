"""Tests for the console application in image_crypto (independent of other apps)."""

import io
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from Crypto.Cipher import DES
from PIL import Image

from image_crypto import core
from image_crypto.cli import main


ROOT = Path(__file__).resolve().parents[1]
OPTIONS = [
    (algorithm, mode, padding)
    for algorithm, modes in core.AVAILABLE_MODES.items()
    for mode in modes
    for padding in (("pkcs7", "iso7816", "x923") if mode in core.BLOCK_MODES else ("none",))
]


def prepare(tmp_path, data=b"example image bytes", algorithm="DES", bits=None):
    source, encrypted, restored, key = (tmp_path / name for name in ("image.png", "image.enc", "restored.png", "key.bin"))
    source.write_bytes(data)
    core.save_key(core.generate_key(algorithm, bits), algorithm, key)
    return source, encrypted, restored, key


@pytest.mark.parametrize("algorithm,mode,padding", OPTIONS)
@pytest.mark.parametrize("size", [0, 1, 7, 8, 15, 16, 17, 1023, 1024, 1025, 4109])
def test_all_modes_padding_and_boundaries(tmp_path, algorithm, mode, padding, size):
    data = (bytes(range(256)) * (size // 256 + 1))[:size]
    source, encrypted, restored, key = prepare(tmp_path, data, algorithm)
    info = core.encrypt_file(source, encrypted, key, algorithm=algorithm, mode=mode, padding=padding, chunk_size=1024)
    assert info.original_size == size
    assert encrypted.stat().st_size == core.HEADER.size + info.ciphertext_size + 64 + info.tag_size
    assert core.decrypt_file(encrypted, restored, key, original=source, chunk_size=16) == info
    assert restored.read_bytes() == data
    assert core.verify_files(source, restored)


@pytest.mark.parametrize("image_format", ["PNG", "JPEG", "BMP", "TIFF", "GIF", "WEBP", "ICO", "PPM"])
def test_real_image_formats(tmp_path, image_format):
    buffer = io.BytesIO()
    Image.new("RGB", (32, 24), (13, 180, 217)).save(buffer, format=image_format)
    source, encrypted, restored, key = prepare(tmp_path, buffer.getvalue())
    core.encrypt_file(source, encrypted, key)
    core.decrypt_file(encrypted, restored, key, original=source)
    assert restored.read_bytes() == source.read_bytes()
    with Image.open(restored) as decoded:
        decoded.load()
        assert decoded.format == image_format


@pytest.mark.parametrize("algorithm", ["DES"])
def test_generated_keys_and_binary_io(tmp_path, algorithm):
    keys = [core.generate_key(algorithm) for _ in range(32)]
    assert len(set(keys)) == len(keys)
    if algorithm == "DES":
        assert all(byte.bit_count() % 2 for key in keys for byte in key)
        assert not set(keys) & core.WEAK_DES_KEYS
    path = tmp_path / "key.bin"
    core.save_key(keys[0], algorithm, path)
    assert path.read_bytes() == keys[0]
    assert core.load_key(path, algorithm) == keys[0]
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600
    with pytest.raises(core.CryptoError):
        core.save_key(keys[1], algorithm, path)
    assert path.read_bytes() == keys[0]


@pytest.mark.parametrize("algorithm,bits", [("DES", 56), ("DES", 128), ("RSA", 256)])
def test_invalid_key_generation(algorithm, bits):
    with pytest.raises(core.CryptoError):
        core.generate_key(algorithm, bits)


@pytest.mark.parametrize("algorithm,mode,padding", [
    ("DES", "CBC", "none"), ("DES", "BAD", "none"), ("DES", "CFB", "pkcs7"),
    ("DES", "EAX", "zeros"), ("RSA", "CBC", "pkcs7"), ("DES", "BAD", "none"),
])
def test_invalid_options(tmp_path, algorithm, mode, padding):
    source, encrypted, _, key = prepare(tmp_path)
    with pytest.raises(core.CryptoError):
        core.encrypt_file(source, encrypted, key, algorithm=algorithm, mode=mode, padding=padding)
    assert not encrypted.exists()


@pytest.mark.parametrize("size", [0, 1, 15, 17, -16, 16 * 1024 * 1024 + 16, "1024", 16.0])
def test_invalid_buffer_sizes(size):
    with pytest.raises(core.CryptoError):
        core.validate_chunk_size(size)


def test_invalid_and_weak_key_files(tmp_path):
    path = tmp_path / "key.bin"
    for key in (b"", b"short", b"a" * 33, b"a" * (1024 * 1024)):
        path.write_bytes(key)
        with pytest.raises(core.CryptoError):
            core.load_key(path, "DES")
    for key in core.WEAK_DES_KEYS:
        for variant in (key, bytes(byte ^ 1 for byte in key)):
            path.write_bytes(variant)
            with pytest.raises(core.CryptoError, match="Weak"):
                core.load_key(path, "DES")


@pytest.mark.parametrize("algorithm,mode,padding", OPTIONS)
def test_wrong_key_never_publishes_plaintext(tmp_path, algorithm, mode, padding):
    source, encrypted, restored, key = prepare(tmp_path, b"data" * 1000, algorithm)
    core.encrypt_file(source, encrypted, key, algorithm=algorithm, mode=mode, padding=padding)
    key.write_bytes(core.generate_key(algorithm))
    restored.write_bytes(b"keep existing output")
    with pytest.raises(core.CryptoError, match="Integrity"):
        core.decrypt_file(encrypted, restored, key, force=True)
    assert restored.read_bytes() == b"keep existing output"
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("part", ["header", "iv", "ciphertext", "checksum", "tag", "mac", "truncate", "append"])
def test_tampering(tmp_path, part):
    source, encrypted, restored, key = prepare(tmp_path, b"data" * 1000)
    info = core.encrypt_file(source, encrypted, key)
    content = bytearray(encrypted.read_bytes())
    offsets = {
        "header": 8, "iv": core.HEADER.size - 16, "ciphertext": core.HEADER.size + 5,
        "checksum": core.HEADER.size + info.ciphertext_size,
        "tag": core.HEADER.size + info.ciphertext_size + 32, "mac": len(content) - 1,
    }
    if part == "truncate":
        content = content[:-1]
    elif part == "append":
        content += b"junk"
    else:
        content[offsets[part]] ^= 1
    encrypted.write_bytes(content)
    with pytest.raises(core.CryptoError):
        core.decrypt_file(encrypted, restored, key)
    assert not restored.exists()
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("field,value", [(0, b"BADMAGIC"), (1, 99), (2, 99), (3, 99), (4, 17), (5, 17), (6, 99), (7, 2**64 - 1), (8, b"X" * 16)])
def test_malformed_headers(tmp_path, field, value):
    source, encrypted, restored, key = prepare(tmp_path)
    core.encrypt_file(source, encrypted, key)
    content = encrypted.read_bytes()
    fields = list(core.HEADER.unpack(content[:core.HEADER.size]))
    fields[field] = value
    encrypted.write_bytes(core.HEADER.pack(*fields) + content[core.HEADER.size:])
    with pytest.raises(core.CryptoError):
        core.decrypt_file(encrypted, restored, key)
    assert not restored.exists()


def test_wrong_original_preserves_output(tmp_path):
    source, encrypted, restored, key = prepare(tmp_path)
    core.encrypt_file(source, encrypted, key)
    source.write_bytes(b"different original")
    restored.write_bytes(b"keep me")
    with pytest.raises(core.CryptoError, match="original"):
        core.decrypt_file(encrypted, restored, key, original=source, force=True)
    assert restored.read_bytes() == b"keep me"


def test_paths_and_overwrite(tmp_path):
    source, encrypted, restored, key = prepare(tmp_path)
    for output in (source, key):
        with pytest.raises(core.CryptoError, match="differ"):
            core.encrypt_file(source, output, key, force=True)
    alias = tmp_path / "hardlink"
    os.link(source, alias)
    with pytest.raises(core.CryptoError, match="differ"):
        core.encrypt_file(source, alias, key, force=True)
    link = tmp_path / "symlink"
    link.symlink_to(restored)
    with pytest.raises(core.CryptoError, match="symbolic link"):
        core.encrypt_file(source, link, key, force=True)
    for bad in (tmp_path, tmp_path / "missing" / "out.enc"):
        with pytest.raises(core.CryptoError):
            core.encrypt_file(source, bad, key, force=True)
    core.encrypt_file(source, encrypted, key)
    before = encrypted.read_bytes()
    with pytest.raises(core.CryptoError, match="already exists"):
        core.encrypt_file(source, encrypted, key)
    assert encrypted.read_bytes() == before
    core.encrypt_file(source, encrypted, key, force=True)
    assert encrypted.read_bytes() != before
    core.decrypt_file(encrypted, restored, key)
    assert core.verify_files(source, restored)


def test_random_iv(tmp_path):
    source, encrypted, _, key = prepare(tmp_path)
    first = core.encrypt_file(source, encrypted, key)
    second = core.encrypt_file(source, encrypted, key, force=True)
    assert first.iv != second.iv


def test_atomic_cleanup(tmp_path):
    source, encrypted, _, key = prepare(tmp_path, b"x" * 4096)
    encrypted.write_bytes(b"preserved")
    with patch.object(core, "_read_exact", side_effect=OSError("disk read failed")):
        with pytest.raises(OSError):
            core.encrypt_file(source, encrypted, key, force=True)
    assert encrypted.read_bytes() == b"preserved"
    assert not list(tmp_path.glob(".*.tmp"))


def test_atomic_creation_race(tmp_path):
    output = tmp_path / "out"
    with pytest.raises(FileExistsError):
        with core.atomic_output(output) as stream:
            stream.write(b"new")
            output.write_bytes(b"concurrent writer")
    assert output.read_bytes() == b"concurrent writer"
    assert not list(tmp_path.glob(".*.tmp"))


@pytest.mark.parametrize("algorithm,module,key_hex,plain_hex,cipher_hex", [
    ("DES", DES, "133457799BBCDFF1", "0123456789ABCDEF", "85E813540F0AB405"),
])
def test_known_vectors(tmp_path, algorithm, module, key_hex, plain_hex, cipher_hex):
    source, encrypted, _, key = prepare(tmp_path, bytes.fromhex(plain_hex), algorithm)
    key.write_bytes(bytes.fromhex(key_hex))
    core.encrypt_file(source, encrypted, key, algorithm=algorithm, mode="ECB")
    assert encrypted.read_bytes()[core.HEADER.size:core.HEADER.size + module.block_size] == bytes.fromhex(cipher_hex)


def test_bounded_reads(tmp_path):
    source, encrypted, restored, key = prepare(tmp_path, os.urandom(2 * core.CHUNK_SIZE + 17))
    real_open, requested = Path.open, []

    class BoundedReader:
        def __init__(self, stream):
            self.stream = stream

        def read(self, size=-1):
            assert 0 <= size <= core.CHUNK_SIZE
            requested.append(size)
            return self.stream.read(size)

        def __getattr__(self, name):
            return getattr(self.stream, name)

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *args):
            return self.stream.__exit__(*args)

    def bounded_open(path, mode="r", *args, **kwargs):
        stream = real_open(path, mode, *args, **kwargs)
        return BoundedReader(stream) if mode == "rb" else stream

    with patch.object(Path, "open", bounded_open):
        core.encrypt_file(source, encrypted, key)
        core.decrypt_file(encrypted, restored, key, original=source)
        assert core.verify_files(source, restored)
    assert max(requested) == core.CHUNK_SIZE


def test_cli_workflow(tmp_path, capsys):
    source, encrypted, restored, key = prepare(tmp_path)
    key.unlink()
    assert main(["keygen", "-o", str(key)]) == 0
    assert main(["encrypt", "-i", str(source), "-o", str(encrypted), "-k", str(key)]) == 0
    assert main(["decrypt", "-i", str(encrypted), "-o", str(restored), "-k", str(key), "--original", str(source)]) == 0
    assert main(["verify", "--original", str(source), "--restored", str(restored)]) == 0
    output = capsys.readouterr()
    assert "Execution time:" in output.out
    assert "Peak process memory" in output.out
    assert "files match" in output.out
    assert not output.err
    restored.write_bytes(b"wrong data")
    assert main(["verify", "--original", str(source), "--restored", str(restored)]) == 1
    assert "differ" in capsys.readouterr().err


@pytest.mark.parametrize("args", [
    ["keygen", "--bits", "56", "-o", "key.bin"],
    ["encrypt", "-i", "missing.png", "-o", "out.enc", "-k", "missing.key"],
])
def test_cli_runtime_errors(args, capsys):
    assert main(args) == 1
    output = capsys.readouterr()
    assert "Error:" in output.err
    assert "Traceback" not in output.err


@pytest.mark.parametrize("args", [
    ["keygen", "--algorithm", "RSA", "-o", "key.bin"], ["decrypt"],
    ["verify", "--original", "a", "--restored", "b", "--chunk-size", "0"],
    ["verify", "--original", "a", "--restored", "b", "--chunk-size", "NaN"],
])
def test_cli_argument_errors(args, capsys):
    with pytest.raises(SystemExit) as error:
        main(args)
    assert error.value.code == 2
    assert "Argument error:" in capsys.readouterr().err


def test_module_entrypoint():
    result = subprocess.run([sys.executable, "-m", "image_crypto", "--help"], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0
    assert "keygen" in result.stdout
