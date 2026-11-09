# Crypto Lab 1 — DES

Local image encryption lab with a React + Vite interface, standard shadcn/ui components, a white Neutral theme and locally bundled Inter.

## Run

Python 3.10+ and Node.js 20.19+ are required.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m backend.server
```

In another terminal:

```sh
cd frontend
npm ci
npm run dev
```

Open http://127.0.0.1:5173. The API binds to 127.0.0.1:8000. Restart the Python process after backend changes.

Select a file, generate or load a binary DES key, choose ECB or CBC and a padding scheme, then encrypt or decrypt. Save the key separately; encrypted containers never contain it. Generated keys contain 8 bytes with odd parity, giving 56 effective key bits.

The Attachment picker supports image thumbnails, file metadata, replacement and removal. Progress reflects uploaded and processed bytes within weighted stages, and reaches 100% only after successful completion. File selection and settings are disabled during processing.

## Implementation

- `backend/des.py`: custom DES permutations, expansion, S-boxes, Feistel function and key schedule.
- `backend/des_tables.json` and `backend/tables.py`: external tables, validated at import.
- `backend/crypto.py`: DES key validation/generation, cached round keys, ECB/CBC and padding. PyCryptodome is a reference implementation available to tests and benchmarks. The UI always uses the custom implementation.
- `backend/files.py`: streaming file processing, bounded process-pool batches for ECB and CBC decryption, checksum verification and atomic output.
- `backend/images.py`: RGB pixel demonstrations using PNG plus a ZIP sidecar package.
- `backend/server.py`: local HTTP API, streamed uploads, opaque result IDs and one-hour result expiry.
- `backend/progress.py`: thread-safe, expiring progress snapshots. The client sends `X-Progress-ID` and polls `/api/progress/{id}`.
- `frontend/src/components/ui`: official shadcn/ui components; shared MIT utilities and license are in `frontend/src/lib`.
- `backend/benchmark.py`: repeated measurements in fresh processes.
- `image_crypto`: an independent console implementation with a separate authenticated container format. See `CONSOLE_README.md`.

## Files and padding

File mode restores the original bytes, including image metadata. The versioned container contains `CLAB`, version byte 1, a 4-byte big-endian JSON length, JSON metadata and ciphertext. Metadata includes algorithm, mode, padding, IV, original length, extension and plaintext SHA-256. The key is stored separately.

CBC generates a fresh random 8-byte IV per encryption. PKCS#7, PKCS#5 and ANSI X9.23 are supported. X9.23 fills padding bytes with zeros. A complete padding block is added when the input is empty or block-aligned.

Decryption stages data in a temporary file and commits it only after padding, length and checksum checks succeed. Errors remove staged files and preserve an existing destination. SHA-256 detects accidental corruption and incorrect keys; it does not authenticate the web container against an active attacker. DES and ECB are educational and must not be used to secure real data.

Pixel mode produces `pixels.zip` containing `encrypted.png`, `pixels.enc` and `image.json`. The PNG keeps the original dimensions. Loading that ZIP for decryption restores decoded RGB pixels as PNG. Use file mode for byte-exact image recovery. Pixel decoding is limited to 25 million pixels; file mode processes uploads up to 10 GiB without loading the whole file into RAM.

Python does not guarantee secure erasure of immutable key buffers.

## Verification and measurements

```sh
.venv/bin/python -m pytest tests -q
.venv/bin/python -m pytest -m large tests/test_large_file.py -q
npm run build --prefix frontend

# Three formats, three sizes, both implementations, five repeats.
.venv/bin/python -m backend.benchmark
```

Benchmarks record median/min/max total and crypto time, remaining overhead, throughput, parent-process peak RSS, buffer size, worker count and environment metadata. Remaining time includes I/O, hashing and preparation. Worker IPC is included in parallel crypto wall time. Peak RSS excludes child processes. Each measurement runs in a fresh process.

Saved DES comparison measurements are in `benchmark-results/comparison/`. They use small files and cannot establish large-file scaling. The full default measurement matrix has not been executed. Streaming integration tests include files larger than 100 MiB. See `REPORT.md`.
