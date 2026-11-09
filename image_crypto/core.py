"""Bounded-memory encryption with an authenticated, versioned file container.

Layout: fixed header | ciphertext | SHA-256(plaintext) | AEAD tag | HMAC.
All fields except the final HMAC are authenticated by HMAC-SHA256. Native
EAX authentication also binds the header. Outputs are published atomically
only after successful processing, authentication and plaintext verification.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import struct
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Iterator

from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad


CHUNK_SIZE = 1024 * 1024
MAX_CHUNK_SIZE = 16 * 1024 * 1024
MAGIC = b"IMGCIPH1"
HEADER = struct.Struct("!8s6BQ16s")
DIGEST_SIZE = 32
ALGORITHMS = {"DES": 1}
MODES = {"ECB": 1, "CBC": 2, "CFB": 3, "OFB": 4, "CTR": 5, "EAX": 6}
PADDINGS = {"none": 0, "pkcs7": 1, "iso7816": 2, "x923": 3}
AVAILABLE_MODES = {
    "DES": ("ECB", "CBC", "CFB", "OFB", "CTR", "EAX"),
}
BLOCK_MODES = {"ECB", "CBC"}
AEAD_MODES = {"EAX"}
# Canonical odd-parity representations of the 4 weak and 12 semi-weak DES keys.
WEAK_DES_KEYS = {
    bytes.fromhex(value)
    for value in (
        "0101010101010101", "FEFEFEFEFEFEFEFE", "E0E0E0E0F1F1F1F1",
        "1F1F1F1F0E0E0E0E", "01FE01FE01FE01FE", "FE01FE01FE01FE01",
        "1FE01FE00EF10EF1", "E01FE01FF10EF10E", "01E001E001F101F1",
        "E001E001F101F101", "1FFE1FFE0EFE0EFE", "FE1FFE1FFE0EFE0E",
        "011F011F010E010E", "1F011F010E010E01", "E0FEE0FEF1FEF1FE",
        "FEE0FEE0FEF1FEF1",
    )
}


class CryptoError(ValueError):
    """An input, container or authentication error suitable for CLI display."""


@dataclass(frozen=True)
class FileInfo:
    algorithm: str
    mode: str
    padding: str
    key_size: int
    original_size: int
    iv: bytes
    tag_size: int

    @property
    def block_size(self) -> int:
        return 8

    @property
    def ciphertext_size(self) -> int:
        if self.mode in BLOCK_MODES:
            return (self.original_size // self.block_size + 1) * self.block_size
        return self.original_size

    def pack(self) -> bytes:
        return HEADER.pack(
            MAGIC, ALGORITHMS[self.algorithm], MODES[self.mode], PADDINGS[self.padding],
            self.key_size, len(self.iv), self.tag_size, self.original_size,
            self.iv.ljust(16, b"\0"),
        )


def validate_chunk_size(chunk_size: int) -> None:
    if type(chunk_size) is not int or not 16 <= chunk_size <= MAX_CHUNK_SIZE or chunk_size % 16:
        raise CryptoError("Buffer size must be a multiple of 16 bytes, between 16 bytes and 16 MiB.")


def validate_options(algorithm: str, mode: str, padding: str) -> None:
    if algorithm not in ALGORITHMS:
        raise CryptoError("Algorithm must be DES.")
    if mode not in AVAILABLE_MODES[algorithm]:
        raise CryptoError(f"Mode {mode} is unavailable for {algorithm}.")
    if padding not in PADDINGS:
        raise CryptoError("Padding must be pkcs7, iso7816, x923 or none.")
    if mode in BLOCK_MODES and padding == "none":
        raise CryptoError(f"Mode {mode} requires padding: pkcs7, iso7816 or x923.")
    if mode not in BLOCK_MODES and padding != "none":
        raise CryptoError(f"Mode {mode} does not require padding. Choose none.")


def _odd_parity(key: bytes) -> bytes:
    return bytes((byte & 0xFE) | (1 ^ ((byte & 0xFE).bit_count() & 1)) for byte in key)


def validate_key(key: bytes, algorithm: str) -> None:
    if algorithm not in ALGORITHMS:
        raise CryptoError("Algorithm must be DES.")
    lengths = (8,)
    if len(key) not in lengths:
        sizes = "8 bytes"
        raise CryptoError(f"Invalid {algorithm} key length: expected {sizes}, got {len(key)}.")
    if algorithm == "DES" and _odd_parity(key) in WEAK_DES_KEYS:
        raise CryptoError("Weak or semi-weak DES key. Generate another key.")


def generate_key(algorithm: str, bits: int | None = None) -> bytes:
    if algorithm not in ALGORITHMS:
        raise CryptoError("Algorithm must be DES.")
    bits = 64 if bits is None else bits
    if type(bits) is not int or bits != 64:
        raise CryptoError("DES requires 64 bits (56 key bits and 8 parity bits).")
    while True:
        key = secrets.token_bytes(bits // 8)
        key = _odd_parity(key)
        if key not in WEAK_DES_KEYS:
            return key


def _regular_file(path: Path) -> None:
    if not path.is_file():
        raise CryptoError(f"File not found or not a regular file: {path}")


def _same_path(first: Path, second: Path) -> bool:
    return first.resolve() == second.resolve() or (
        first.exists() and second.exists() and os.path.samefile(first, second)
    )


def validate_output(output: Path, protected: tuple[Path, ...], force: bool) -> None:
    for path in protected:
        if _same_path(output, path):
            raise CryptoError("Output must differ from the input, key and verification original.")
    if output.is_symlink():
        raise CryptoError("Output path must not be a symbolic link.")
    if not output.parent.is_dir():
        raise CryptoError(f"Output directory does not exist: {output.parent}")
    if output.exists():
        if not output.is_file():
            raise CryptoError(f"Output path is not a regular file: {output}")
        if not force:
            raise CryptoError(f"File already exists: {output}. Use --force to overwrite.")


@contextmanager
def atomic_output(output: Path, force: bool = False) -> Iterator[BinaryIO]:
    """Keep existing output intact on error; create new output without clobbering."""
    fd, name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=output.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "wb") as stream:
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
        if output.is_symlink():
            raise CryptoError("Output path must not be a symbolic link.")
        if force:
            os.replace(temporary, output)
        else:
            # link() atomically fails if a destination appeared during processing.
            os.link(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def save_key(key: bytes, algorithm: str, output: str | Path, *, force: bool = False) -> None:
    validate_key(key, algorithm)
    output = Path(output)
    validate_output(output, (), force)
    with atomic_output(output, force) as stream:
        stream.write(key)


def load_key(path: str | Path, algorithm: str) -> bytes:
    path = Path(path)
    _regular_file(path)
    with path.open("rb") as stream:
        key = stream.read(33)  # A mistakenly selected large file cannot fill memory.
    validate_key(key, algorithm)
    return key


def _iv_size(algorithm: str, mode: str) -> int:
    block_size = 8
    if mode == "ECB":
        return 0
    if mode == "CTR":
        return block_size // 2
    if mode == "EAX":
        return 16
    return block_size


def _validate_counter_size(info: FileInfo) -> None:
    if info.mode == "CTR":
        limit = (1 << (8 * (info.block_size - len(info.iv)))) * info.block_size
        if info.original_size > limit:
            raise CryptoError(f"File is too large for the {info.algorithm}-CTR counter (limit: {limit} bytes).")


def _new_cipher(info: FileInfo, key: bytes):
    module = DES
    mode = getattr(module, f"MODE_{info.mode}")
    if info.mode == "ECB":
        return module.new(key, mode)
    if info.mode == "CTR":
        return module.new(key, mode, nonce=info.iv, initial_value=0)
    if info.mode in AEAD_MODES:
        return module.new(key, mode, nonce=info.iv, mac_len=info.tag_size)
    if info.mode == "CFB":
        return module.new(key, mode, iv=info.iv, segment_size=info.block_size * 8)
    return module.new(key, mode, iv=info.iv)


def _new_mac(key: bytes):
    # Domain-separated authentication key: never use encryption key directly as MAC key.
    mac_key = hmac.digest(key, b"image-crypto/v1/HMAC-SHA256", "sha256")
    return hmac.new(mac_key, digestmod="sha256")


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise CryptoError("Encrypted file is truncated or corrupted.")
    return data


def read_header(stream: BinaryIO) -> tuple[FileInfo, bytes]:
    raw = _read_exact(stream, HEADER.size)
    magic, alg, mode, padding, key_size, iv_size, tag_size, size, iv = HEADER.unpack(raw)
    if magic != MAGIC:
        raise CryptoError("Not an Image Crypto file, or its version is unsupported.")
    try:
        info = FileInfo(
            next(name for name, value in ALGORITHMS.items() if value == alg),
            next(name for name, value in MODES.items() if value == mode),
            next(name for name, value in PADDINGS.items() if value == padding),
            key_size, size, iv[:iv_size], tag_size,
        )
    except StopIteration as error:
        raise CryptoError("Header contains an unknown algorithm, mode or padding.") from error
    validate_options(info.algorithm, info.mode, info.padding)
    expected_tag_size = info.block_size if info.mode in AEAD_MODES else 0
    if (
        key_size != 8
        or iv_size != _iv_size(info.algorithm, info.mode)
        or any(iv[iv_size:])
        or tag_size != expected_tag_size
    ):
        raise CryptoError("Invalid key, IV/nonce or tag parameters in the header.")
    _validate_counter_size(info)
    return info, raw


def encrypt_file(
    source: str | Path, output: str | Path, key_file: str | Path, *,
    algorithm: str = "DES", mode: str | None = None, padding: str | None = None,
    chunk_size: int = CHUNK_SIZE, force: bool = False,
) -> FileInfo:
    mode = "CBC" if mode is None else mode
    padding = ("pkcs7" if mode in BLOCK_MODES else "none") if padding is None else padding
    validate_options(algorithm, mode, padding)
    validate_chunk_size(chunk_size)
    source, output, key_file = Path(source), Path(output), Path(key_file)
    _regular_file(source)
    validate_output(output, (source, key_file), force)
    key = load_key(key_file, algorithm)
    with source.open("rb") as incoming:
        original_stat = os.fstat(incoming.fileno())
        info = FileInfo(
            algorithm, mode, padding, len(key), original_stat.st_size,
            secrets.token_bytes(_iv_size(algorithm, mode)),
            8 if mode in AEAD_MODES else 0,
        )
        _validate_counter_size(info)
        cipher, mac, digest = _new_cipher(info, key), _new_mac(key), hashlib.sha256()
        header = info.pack()
        mac.update(header)
        if mode in AEAD_MODES:
            cipher.update(header)
        with atomic_output(output, force) as outgoing:
            outgoing.write(header)
            remaining = info.original_size
            while remaining:
                data = _read_exact(incoming, min(chunk_size, remaining))
                remaining -= len(data)
                digest.update(data)
                if mode in BLOCK_MODES and remaining == 0:
                    data = pad(data, info.block_size, style=padding)
                encrypted = cipher.encrypt(data)
                mac.update(encrypted)
                outgoing.write(encrypted)
            if not info.original_size and mode in BLOCK_MODES:
                encrypted = cipher.encrypt(pad(b"", info.block_size, style=padding))
                mac.update(encrypted)
                outgoing.write(encrypted)
            current_stat = os.fstat(incoming.fileno())
            if incoming.read(1) or (
                current_stat.st_size, current_stat.st_mtime_ns, current_stat.st_ctime_ns
            ) != (original_stat.st_size, original_stat.st_mtime_ns, original_stat.st_ctime_ns):
                raise CryptoError("Input file changed during encryption. Try again.")
            checksum = digest.digest()
            tag = cipher.digest() if mode in AEAD_MODES else b""
            mac.update(checksum + tag)
            outgoing.write(checksum + tag + mac.digest())
    return info


def file_digest(path: str | Path, chunk_size: int = CHUNK_SIZE) -> tuple[int, bytes]:
    validate_chunk_size(chunk_size)
    path = Path(path)
    _regular_file(path)
    digest, total = hashlib.sha256(), 0
    with path.open("rb") as incoming:
        while data := incoming.read(chunk_size):
            digest.update(data)
            total += len(data)
    return total, digest.digest()


def verify_files(original: str | Path, restored: str | Path, *, chunk_size: int = CHUNK_SIZE) -> bool:
    # Both length and cryptographic hash must agree, independent of file extension.
    return file_digest(original, chunk_size) == file_digest(restored, chunk_size)


def decrypt_file(
    source: str | Path, output: str | Path, key_file: str | Path, *,
    original: str | Path | None = None, chunk_size: int = CHUNK_SIZE, force: bool = False,
) -> FileInfo:
    validate_chunk_size(chunk_size)
    source, output, key_file = Path(source), Path(output), Path(key_file)
    _regular_file(source)
    protected = (source, key_file)
    if original is not None:
        original = Path(original)
        _regular_file(original)
        protected += (original,)
    validate_output(output, protected, force)
    with source.open("rb") as incoming:
        info, header = read_header(incoming)
        expected_size = HEADER.size + info.ciphertext_size + DIGEST_SIZE * 2 + info.tag_size
        if os.fstat(incoming.fileno()).st_size != expected_size:
            raise CryptoError("Encrypted file size does not match its header: file is truncated or corrupted.")
        key = load_key(key_file, info.algorithm)
        if len(key) != info.key_size:
            raise CryptoError(f"The file header requires a {info.key_size}-byte key.")
        cipher, mac, digest = _new_cipher(info, key), _new_mac(key), hashlib.sha256()
        mac.update(header)
        if info.mode in AEAD_MODES:
            cipher.update(header)
        with atomic_output(output, force) as outgoing:
            remaining, written, final_block = info.ciphertext_size, 0, b""
            while remaining:
                encrypted = _read_exact(incoming, min(chunk_size, remaining))
                remaining -= len(encrypted)
                mac.update(encrypted)
                data = cipher.decrypt(encrypted)
                if info.mode in BLOCK_MODES and remaining == 0:
                    data, final_block = data[:-info.block_size], data[-info.block_size:]
                digest.update(data)
                written += len(data)
                outgoing.write(data)
            checksum = _read_exact(incoming, DIGEST_SIZE)
            tag = _read_exact(incoming, info.tag_size)
            stored_mac = _read_exact(incoming, DIGEST_SIZE)
            mac.update(checksum + tag)
            if incoming.read(1) or not hmac.compare_digest(mac.digest(), stored_mac):
                raise CryptoError("Integrity check failed: incorrect key or corrupted file.")
            if info.mode in AEAD_MODES:
                try:
                    cipher.verify(tag)
                except ValueError as error:
                    raise CryptoError("Authentication tag verification failed.") from error
            if info.mode in BLOCK_MODES:
                try:
                    data = unpad(final_block, info.block_size, style=info.padding)
                except ValueError as error:
                    raise CryptoError("Invalid padding in the encrypted file.") from error
                digest.update(data)
                written += len(data)
                outgoing.write(data)
            if written != info.original_size or not hmac.compare_digest(digest.digest(), checksum):
                raise CryptoError("Decrypted file SHA-256 or length does not match the original.")
            if original is not None and (written, digest.digest()) != file_digest(original, chunk_size):
                raise CryptoError("Decrypted image does not match the specified original.")
    return info
