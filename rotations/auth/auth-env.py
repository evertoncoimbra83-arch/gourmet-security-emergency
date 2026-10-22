"""Local server-side Auth env operations. Never emits a secret value."""
import hashlib
import os
import re
import secrets
import stat
import sys
import tempfile
from pathlib import Path

KEYS = {"SESSION_SECRET", "JWT_SECRET", "NEXTAUTH_SECRET"}


def key_lines(raw: bytes, key: str):
    pattern = re.compile(rb"^\s*(?:export\s+)?" + key.encode() + rb"\s*=")
    return [i for i, line in enumerate(raw.splitlines(keepends=True)) if pattern.match(line)]


def require_single(path: Path, key: str):
    raw = path.read_bytes()
    if len(key_lines(raw, key)) != 1:
        raise ValueError("target key must occur exactly once")
    return raw


def update(path: Path, key: str):
    raw = require_single(path, key)
    original_mode = stat.S_IMODE(path.stat().st_mode)
    lines = raw.splitlines(keepends=True)
    index = key_lines(raw, key)[0]
    line = lines[index]
    ending = b"\r\n" if line.endswith(b"\r\n") else (b"\n" if line.endswith(b"\n") else b"")
    prefix = line.split(b"=", 1)[0] + b"="
    new_secret = secrets.token_urlsafe(48)
    new_hash = hashlib.sha256(new_secret.encode()).hexdigest()
    lines[index] = prefix + new_secret.encode() + ending
    new_raw = b"".join(lines)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp_auth_env_")
    try:
        os.chmod(tmp, original_mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(new_raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        if hasattr(os, "O_DIRECTORY"):
            dir_fd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print(new_hash)


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in {"check", "update"} or sys.argv[3] not in KEYS:
        return 1
    path = Path(sys.argv[2])
    try:
        if sys.argv[1] == "check":
            require_single(path, sys.argv[3])
        else:
            update(path, sys.argv[3])
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
