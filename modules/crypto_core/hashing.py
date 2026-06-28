import hashlib


def hash_key(public_key: bytes) -> str:
    return hashlib.sha3_256(public_key).hexdigest().encode("utf-8")

def hash_verify(public_key: bytes, hash : bytes) -> bool:
    if hash_key(public_key) == hash:
        return True
    else:
        return False