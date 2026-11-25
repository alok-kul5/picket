"""Download the public datasets in datasets/manifest.yml and normalise them.

Raw downloads go to .cache/raw/, normalised events to .cache/events/<id>.jsonl.gz.
Archives are read in memory; nothing inside them is extracted to disk or run.
"""
from __future__ import annotations

import gzip
import json
import sys
import tarfile
import urllib.parse
import urllib.request
import zipfile
import zlib
from pathlib import Path
from typing import Iterator

import yaml

from . import normalize

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / ".cache"
RAW = CACHE / "raw"
EVENTS = CACHE / "events"
NUL = bytes(1)
NEWLINE = bytes([10])


def manifest() -> dict:
    return yaml.safe_load((ROOT / "datasets" / "manifest.yml").read_text(encoding="utf-8"))


def _download(url: str, dest: Path) -> Path:
    if dest.exists() and dest.stat().st_size > 0:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "picket-replay/1.0"})
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(req, timeout=300) as r, open(tmp, "wb") as fh:
        while chunk := r.read(1 << 20):
            fh.write(chunk)
    tmp.replace(dest)
    return dest


def _tar_members(path: Path) -> Iterator[tuple[str, bytes]]:
    with tarfile.open(path, "r:gz") as t:
        for m in t:
            if not m.isfile():
                continue
            base = m.name.rsplit("/", 1)[-1].lower()
            # baselines ship every channel; keep the ones our rules read
            if base.endswith(".evtx") and not any(k in base for k in ("security", "sysmon", "system")):
                continue
            fh = t.extractfile(m)
            if fh:
                yield m.name, fh.read()


def _salvage_tar(path: Path) -> Iterator[tuple[str, bytes]]:
    """A few upstream archives are truncated: keep every complete line of the first member."""
    data = zlib.decompressobj(31).decompress(path.read_bytes())
    member = data[:100].split(NUL, 1)[0].decode()
    body = data[512:]
    yield member, body[: body.rfind(NEWLINE) + 1]


def _members(path: Path) -> Iterator[tuple[str, bytes]]:
    name = path.name.lower()
    if name.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if not info.is_dir():
                    yield info.filename, z.read(info)
    elif name.endswith((".tar.gz", ".tgz")):
        try:
            yield from list(_tar_members(path))
        except (EOFError, tarfile.ReadError, zlib.error):
            yield from _salvage_tar(path)
    else:
        yield path.name, path.read_bytes()


def build(ds: dict, sources: dict, force: bool = False) -> Path:
    out = EVENTS / f"{ds['id']}.jsonl.gz"
    if out.exists() and not force:
        return out
    src = sources[ds["source"]]
    if src.get("local"):
        raw = ROOT / "fixtures" / ds["path"]
    else:
        url = src["base"] + urllib.parse.quote(ds["path"])
        raw = _download(url, RAW / ds["id"] / ds["path"].rsplit("/", 1)[-1])
    EVENTS.mkdir(parents=True, exist_ok=True)
    n = 0
    tmp = out.with_suffix(".part")
    with gzip.open(tmp, "wt", encoding="utf-8") as fh:
        for name, data in _members(raw):
            for e in normalize.by_name(name, data):
                e["_dataset"] = ds["id"]
                fh.write(json.dumps(e, default=str) + "\n")
                n += 1
    tmp.replace(out)
    print(f"  {ds['id']:<32} {n:>9,} events")
    return out


def main(argv: list[str] | None = None) -> int:
    argv = argv or []
    m = manifest()
    only = {a for a in argv if not a.startswith("-")}
    for ds in m["datasets"]:
        if only and ds["id"] not in only:
            continue
        if "--attack-only" in argv and ds["kind"] == "benign":
            continue
        try:
            build(ds, m["sources"], force="--force" in argv)
        except OSError as exc:  # e.g. a local antivirus quarantined an archive
            print(f"  {ds['id']:<32} skipped: {exc.__class__.__name__}: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
