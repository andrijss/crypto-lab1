# DES console application

The independent console application streams arbitrary files and restores image bytes without decoding. Its authenticated `IMGCIPH1` format differs from the web application's `CLAB` format.

```sh
python main.py keygen --algorithm DES -o des.key
python main.py encrypt -i photo.png -o photo.enc -k des.key --mode CBC
python main.py decrypt -i photo.enc -o restored.png -k des.key --original photo.png
python main.py verify --original photo.png --restored restored.png
```

DES keys contain 8 raw bytes, including parity. The generator rejects weak and semi-weak keys. Supported modes: ECB, CBC, CFB64, OFB, CTR and EAX. ECB/CBC support `pkcs7`, `iso7816` and zero-filled `x923`; other modes use `none`. The default is CBC with PKCS#7.

All console containers include a domain-separated HMAC-SHA256 over header, ciphertext, plaintext checksum and optional EAX tag. Authentication, padding, length and checksum checks finish before an atomic output commit. Existing outputs require `--force`. Paths are checked to avoid overwriting the input or key. On POSIX, new key and output files use private permissions.

`--chunk-size` selects a 1–16384 KiB buffer; default 1024 KiB. Each command prints elapsed time and peak process RSS. DES-CTR has a 32 GiB input limit. The library implementation is for educational comparison; DES is unsuitable for real-world protection.

```sh
python -m image_crypto --help
python main.py encrypt --help
```
