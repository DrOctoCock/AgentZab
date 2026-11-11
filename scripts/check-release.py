#!/usr/bin/env python3
"""Independently rebuild, extract, check manifest, permissions and tamper rejection."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("builder", ROOT / "scripts/build.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
archive = ROOT / "dist" / f"agentzab-linux-mtls-{(ROOT / 'VERSION').read_text().strip()}.zip"
with tempfile.TemporaryDirectory(prefix="agentzab-release-") as temp:
    temp = Path(temp)
    rebuilt = builder.build(temp / "rebuilt")
    assert archive.read_bytes() == rebuilt.read_bytes(), "Release not byte-reproducible"
    with zipfile.ZipFile(archive) as package:
        assert not any(p.endswith((".key", ".pem", ".cer", ".crt")) or "/.runtime/" in p for p in package.namelist())
        package.extractall(temp / "unpacked")
        for member in package.infolist():
            path = temp / "unpacked" / member.filename
            path.chmod((member.external_attr >> 16) & 0o777)
    release = next((temp / "unpacked").iterdir())
    subprocess.run([str(release / "install.sh"), "verify-package"], check=True)
    manifest = json.loads((release / "MANIFEST.json").read_text())
    assert all(hashlib.sha256((release / p).read_bytes()).hexdigest() == d for p, d in manifest.items())
    assert (release / "install.sh").stat().st_mode & 0o111
    (release / "config/site.json").write_text("{}")
    result = subprocess.run([str(release / "install.sh"), "verify-package"], capture_output=True)
    assert result.returncode != 0, "Tampering not detected"
print("PASS: two byte-identical builds; extracted manifest; executable modes; no certificates/keys; tamper rejected")
