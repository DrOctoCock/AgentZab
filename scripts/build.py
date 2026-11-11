#!/usr/bin/env python3
"""Build a deterministic release ZIP without local keys, CA files or state."""
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def build(destination):
    version = (ROOT / "VERSION").read_text().strip()
    name = f"agentzab-linux-mtls-{version}"
    files = [ROOT / p for p in ("VERSION", "README.md", "00-START-HIER.md", "install.sh", ".gitignore")]
    for directory in ("agentzab", "config", "docs", "scripts", "tests", "common"):
        files += [p for p in (ROOT / directory).rglob("*")
                  if p.is_file() and "__pycache__" not in p.parts
                  and (directory != "common" or p.name == "README.md")
                  and p.suffix not in {".pyc", ".pem", ".key", ".cer", ".crt", ".der", ".pfx", ".p12", ".csr", ".srl"}]
    files = sorted(set(files))
    for file in files:
        if file.is_symlink():
            raise ValueError(f"Refusing symlink in release: {file}")
    content = {file.relative_to(ROOT).as_posix(): file.read_bytes() for file in files}
    manifest = {path: hashlib.sha256(data).hexdigest() for path, data in content.items()}
    content["MANIFEST.json"] = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / f"{name}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as out:
        for path, data in sorted(content.items()):
            info = zipfile.ZipInfo(f"{name}/{path}", date_time=(2026, 1, 1, 0, 0, 0))
            info.create_system = 3
            mode = 0o755 if path.endswith(".sh") else 0o644
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            out.writestr(info, data, compresslevel=9)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(".zip.sha256").write_text(f"{digest}  {archive.name}\n")
    print(f"{archive}\nSHA256 {digest}")
    return archive


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else ROOT / "dist")
