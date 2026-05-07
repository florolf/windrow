import hashlib
from pathlib import Path

def sha256_file(path: Path) -> bytes:
    h = hashlib.sha256()

    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)

    return h.digest()


def sha256(data: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(data)
    return h.digest()
