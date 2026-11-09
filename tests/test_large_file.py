"""Run explicitly: python -m pytest -m large -s tests/test_large_file.py."""

import hashlib
import re
import struct
import subprocess
import sys
from pathlib import Path

import pytest
from PIL import Image

from image_crypto.core import file_digest, generate_key, save_key


ROOT = Path(__file__).resolve().parents[1]


def write_large_bmp(path):
    """Create a valid 108 MiB BMP with only one row in memory."""
    width, height = 8192, 4608
    row = bytes(range(256)) * (width * 3 // 256)
    pixel_size = len(row) * height
    header = struct.pack("<2sIHHI", b"BM", 54 + pixel_size, 0, 0, 54)
    header += struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, pixel_size, 2835, 2835, 0, 0)
    digest = hashlib.sha256(header)
    with path.open("wb") as output:
        output.write(header)
        for _ in range(height):
            output.write(row)
            digest.update(row)
    return 54 + pixel_size, digest.digest()


@pytest.mark.large
@pytest.mark.parametrize("algorithm,mode", [("DES", "CBC"), ("DES", "CTR")])
def test_image_over_100_mib_has_bounded_process_memory(tmp_path, algorithm, mode):
    source, encrypted, restored, key = (tmp_path / name for name in ("large.bmp", "large.enc", "restored.bmp", "key.bin"))
    original = write_large_bmp(source)
    assert source.stat().st_size > 100 * 1024 * 1024
    with Image.open(source) as image:
        assert image.format == "BMP"
        assert image.size == (8192, 4608)
    save_key(generate_key(algorithm), algorithm, key)
    commands = [
        ["encrypt", "-i", str(source), "-o", str(encrypted), "-k", str(key), "--algorithm", algorithm, "--mode", mode],
        ["decrypt", "-i", str(encrypted), "-o", str(restored), "-k", str(key), "--original", str(source)],
    ]
    for command in commands:
        result = subprocess.run([sys.executable, "main.py", *command], cwd=ROOT, capture_output=True, text=True, timeout=120)
        print(f"\n{algorithm}-{mode} {command[0]}:\n{result.stdout}")
        assert result.returncode == 0, result.stderr
        match = re.search(r"\(RSS\): ([\d.]+) MiB", result.stdout)
        assert match, result.stdout
        # A separate process prevents pytest/Pillow allocations from polluting the peak.
        assert float(match.group(1)) < 96
    assert file_digest(restored) == original
    with Image.open(restored) as image:
        assert image.format == "BMP"
        assert image.size == (8192, 4608)
