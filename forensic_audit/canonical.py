from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding used for hashes and receipt MACs."""
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def object_hash(obj: Any) -> str:
    return sha256_hex(canonical_bytes(obj))


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json_atomic(path: Path, obj: Any) -> None:
    """Durable-ish atomic JSON publish on native Windows.

    The temporary file is fsynced before replacement.  Windows cannot fsync a
    directory handle portably from the standard library; ``os.replace`` is
    atomic on NTFS and reopening the path is the commit-point test used here.
    """
    import os

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    data = (json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def iter_jsonl_objects(path: Path):
    """Yield ``(line_number, raw_line_without_newline, object_or_None, error)``."""
    if not path.exists():
        return
    with open(path, "rb") as f:
        for lineno, raw_with_lf in enumerate(f, 1):
            raw = raw_with_lf[:-1] if raw_with_lf.endswith(b"\n") else raw_with_lf
            if raw.endswith(b"\r"):
                raw = raw[:-1]
            try:
                obj = json.loads(raw.decode("utf-8"))
                error = None
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                obj = None
                error = str(exc)
            yield lineno, raw, obj, error


def prefix_sha256(path: Path, end_offset: int | None = None) -> str:
    h = hashlib.sha256()
    remaining = end_offset
    with open(path, "rb") as f:
        while True:
            size = 1024 * 1024 if remaining is None else min(1024 * 1024, remaining)
            chunk = f.read(size)
            if not chunk:
                break
            h.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
                if remaining <= 0:
                    break
    return h.hexdigest()
