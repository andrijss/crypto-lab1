"""English command-line interface and process-level performance metrics."""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Sequence

from .core import (
    ALGORITHMS, MODES, PADDINGS, CryptoError,
    decrypt_file, encrypt_file, generate_key, save_key, verify_files,
)


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"Argument error: {message}\n")


def peak_memory_bytes() -> int:
    """OS high-water mark for RSS of this process, including Python/libraries."""
    if sys.platform == "win32":
        import psutil

        return psutil.Process().memory_info().peak_wset
    import resource

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def _chunk_kib(value: str) -> int:
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("buffer size must be an integer in KiB") from error
    if not 1 <= number <= 16384:
        raise argparse.ArgumentTypeError("buffer size must be between 1 and 16384 KiB")
    return number * 1024


def build_parser() -> Parser:
    parser = Parser(
        description="Encrypt and decrypt images with DES without loading the entire file into memory.",
        epilog="Example: python main.py encrypt -i photo.png -o photo.enc -k des.key --algorithm DES --mode CBC",
    )
    commands = parser.add_subparsers(dest="command", title="Commands")
    keygen = commands.add_parser("keygen", help="Generate and save a binary key")
    keygen.add_argument("--algorithm", type=str.upper, choices=ALGORITHMS, default="DES", help="Algorithm (default: DES)")
    keygen.add_argument("--bits", type=int, help="DES: 64 bits including parity")
    keygen.add_argument("-o", "--output", required=True, help="Binary key output file")
    keygen.add_argument("--force", action="store_true", help="Allow overwriting an existing file")

    encrypt = commands.add_parser("encrypt", help="Encrypt an image file")
    decrypt = commands.add_parser("decrypt", help="Decrypt a file and verify its integrity")
    for command in (encrypt, decrypt):
        command.add_argument("-i", "--input", required=True, help="Input file")
        command.add_argument("-o", "--output", required=True, help="Output file")
        command.add_argument("-k", "--key", required=True, help="Binary key file")
        command.add_argument("--chunk-size", type=_chunk_kib, default=1024 * 1024, metavar="KiB", help="Buffer: 1–16384 KiB (default: 1024)")
        command.add_argument("--force", action="store_true", help="Allow overwriting the output file")
    encrypt.add_argument("--algorithm", type=str.upper, choices=ALGORITHMS, default="DES", help="Algorithm (default: DES)")
    encrypt.add_argument("--mode", type=str.upper, choices=MODES, help="DES: ECB/CBC/CFB/OFB/CTR/EAX. Default: CBC")
    encrypt.add_argument("--padding", type=str.lower, choices=PADDINGS, help="ECB/CBC: pkcs7 (default), iso7816 or x923; other modes: none")
    decrypt.add_argument("--original", help="Also compare SHA-256 with the original image")

    verify = commands.add_parser("verify", help="Compare the size and SHA-256 of the original and restored files")
    verify.add_argument("--original", required=True, help="Original image")
    verify.add_argument("--restored", required=True, help="Decrypted image")
    verify.add_argument("--chunk-size", type=_chunk_kib, default=1024 * 1024, metavar="KiB", help="Buffer: 1–16384 KiB (default: 1024)")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    started = time.perf_counter()
    try:
        if args.command == "keygen":
            key = generate_key(args.algorithm, args.bits)
            save_key(key, args.algorithm, args.output, force=args.force)
            print(f"Key {args.algorithm} ({len(key) * 8} bits) saved in binary format: {args.output}")
        elif args.command == "encrypt":
            info = encrypt_file(
                args.input, args.output, args.key, algorithm=args.algorithm,
                mode=args.mode, padding=args.padding, chunk_size=args.chunk_size, force=args.force,
            )
            print(f"Encrypted: {args.output}")
            print(f"Algorithm: {info.algorithm}; mode: {info.mode}; padding: {info.padding}; original bytes: {info.original_size}")
        elif args.command == "decrypt":
            info = decrypt_file(
                args.input, args.output, args.key, original=args.original,
                chunk_size=args.chunk_size, force=args.force,
            )
            print(f"Decrypted: {args.output} ({info.algorithm}-{info.mode})")
            print("Integrity and SHA-256 verification passed.")
            if args.original:
                print("Original comparison: files match.")
        elif args.command == "verify":
            if not verify_files(args.original, args.restored, chunk_size=args.chunk_size):
                raise CryptoError("Files differ: size or SHA-256 does not match.")
            print("Verification passed: file sizes and SHA-256 hashes match.")
        return 0
    except (CryptoError, OSError, ValueError, OverflowError) as error:
        if isinstance(error, PermissionError):
            message = f"Permission denied: {error.filename or error}"
        elif isinstance(error, FileNotFoundError):
            message = f"File or directory not found: {error.filename or error}"
        elif isinstance(error, FileExistsError):
            message = "Output file already exists. Use --force to overwrite."
        else:
            message = str(error)
        print(f"Error: {message}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Operation interrupted by the user.", file=sys.stderr)
        return 130
    finally:
        print(f"Execution time: {time.perf_counter() - started:.6f} s")
        print(f"Peak process memory (RSS): {peak_memory_bytes() / (1024 * 1024):.2f} MiB")
