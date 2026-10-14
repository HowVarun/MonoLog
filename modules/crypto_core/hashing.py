import hashlib, hmac


def hash_key(public_key: bytes) -> bytes:
    return hashlib.sha3_256(public_key).digest()

def hash_verify(public_key: bytes, expected_hash: bytes) -> bool:
    return hmac.compare_digest(hash_key(public_key), expected_hash)

def hash_convert_str(hash: bytes) -> str:
    return hash.hex()

def hash_convert_bytes(hash: str) -> bytes:
    return bytes.fromhex(hash.strip())