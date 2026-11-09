from . import tables as constants

def permute(block: int, table: list[int], input_size: int) -> int:
    result = 0

    for position in table:
        bit = (block >> (input_size - position)) & 1
        result = (result << 1) | bit

    return result


def rotate_left(value: int, shifts: int, size: int) -> int:
    mask = (1 << size) - 1

    return ((value << shifts) | (value >> (size - shifts))) & mask


def generate_round_keys(key: bytes) -> list[int]:
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes")

    key_int = int.from_bytes(key, "big")

    permuted_key = permute(key_int, constants.PC1, 64)

    C = permuted_key >> 28
    D = permuted_key & 0x0FFFFFFF

    round_keys = []

    for shift in constants.SHIFTS:
        C = rotate_left(C, shift, 28)
        D = rotate_left(D, shift, 28)

        combined = (C << 28) | D

        round_key = permute(combined, constants.PC2, 56)

        round_keys.append(round_key)

    return round_keys


def feistel(right: int, round_key: int) -> int:
    expanded = permute(right, constants.E, 32)

    mixed = expanded ^ round_key

    substituted = 0

    for i in range(8):
        chunk = (mixed >> (42 - 6 * i)) & 0x3F

        row = ((chunk & 0x20) >> 4) | (chunk & 1)

        col = (chunk >> 1) & 0x0F

        value = constants.S_BOXES[i][row][col]

        substituted = (substituted << 4) | value

    return permute(substituted, constants.P, 32)


def encrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != 8 or len(key) != 8:
        raise ValueError("Block and key must be 8 bytes long")

    block_int = int.from_bytes(block, "big")

    permuted = permute(block_int, constants.IP, 64)

    L = permuted >> 32
    R = permuted & 0xFFFFFFFF

    round_keys = generate_round_keys(key)

    for round_key in round_keys:
        L, R = R, L ^ feistel(R, round_key)

    combined = (R << 32) | L

    ciphertext_int = permute(combined, constants.IP_INV, 64)

    return ciphertext_int.to_bytes(8, "big")


def decrypt_block(block: bytes, key: bytes) -> bytes:
    if len(block) != 8 or len(key) != 8:
        raise ValueError("Block and key must be 8 bytes long")

    block_int = int.from_bytes(block, "big")

    permuted = permute(block_int, constants.IP, 64)

    L = permuted >> 32
    R = permuted & 0xFFFFFFFF

    round_keys = generate_round_keys(key)

    for round_key in reversed(round_keys):
        L, R = R, L ^ feistel(R, round_key)

    combined = (R << 32) | L

    plaintext_int = permute(combined, constants.IP_INV, 64)

    return plaintext_int.to_bytes(8, "big")



def encrypt(plaintext: bytes, key: bytes) -> bytes:
    padding_size = 8 - (len(plaintext) % 8)
    padded_plaintext = plaintext + bytes([padding_size]) * padding_size

    ciphertext = bytearray()
    for offset in range(0, len(padded_plaintext), 8):
        ciphertext.extend(encrypt_block(padded_plaintext[offset:offset + 8], key))

    return bytes(ciphertext)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if not ciphertext or len(ciphertext) % 8 != 0:
        raise ValueError("Ciphertext must contain a non-empty number of 8-byte blocks")

    plaintext = bytearray()
    for offset in range(0, len(ciphertext), 8):
        plaintext.extend(decrypt_block(ciphertext[offset:offset + 8], key))

    padding_size = plaintext[-1]
    if not 1 <= padding_size <= 8 or plaintext[-padding_size:] != bytes([padding_size]) * padding_size:
        raise ValueError("Invalid PKCS#7 padding")

    return bytes(plaintext[:-padding_size])
