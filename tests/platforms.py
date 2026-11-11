#!/usr/bin/env python3
"""Opt-in native APT/systemd smoke inside a disposable local privileged container.

Privileged is needed ONLY for a nested test systemd, never on target agent hosts.
No host mounts except the read-only PUBLIC cloud CA; no Docker socket mount.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parent.parent
DOCKER = ["docker", "--host=unix:///var/run/docker.sock"]


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def test_platform(pki=None, network=None, metrics=None):
    tag = "agentzab-platform-test:" + secrets.token_hex(4)
    name = "agentzab-platform-" + secrets.token_hex(4)
    ca_path = os.environ.get("CODEX_PROXY_CERT", "/etc/ssl/certs/ca-certificates.crt")
    with tempfile.TemporaryDirectory(prefix="agentzab-platform-", dir=ROOT / ".runtime") as directory:
        directory = Path(directory)
        release = directory / "release"
        release.mkdir()
        archive = ROOT / "dist" / f"agentzab-linux-mtls-{(ROOT / 'VERSION').read_text().strip()}.zip"
        with zipfile.ZipFile(archive) as package:
            for member in package.infolist():
                relative = Path(*Path(member.filename).parts[1:])
                path = release / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(package.read(member))
                path.chmod((member.external_attr >> 16) & 0o777)
        if pki:
            profile = json.loads((release / "config/site.json").read_text())
            profile.update(server="zabbix.lab.test", server_certificate_name="zabbix.lab.test")
            (release / "config/site.json").write_text(json.dumps(profile, indent=2))
            manifest = json.loads((release / "MANIFEST.json").read_text())
            manifest["config/site.json"] = hashlib.sha256((release / "config/site.json").read_bytes()).hexdigest()
            (release / "MANIFEST.json").write_text(json.dumps(manifest, sort_keys=True, indent=2))
        shutil.copy(ROOT / "tests/Dockerfile.platform", directory / "Dockerfile")
        build_environment = os.environ.copy()
        # Keep Docker registry/proxy configuration; only relocate buildx state.
        build_environment["BUILDX_CONFIG"] = str(ROOT / ".runtime/buildx")
        run(DOCKER + ["build", "--secret", f"id=proxy_ca,src={ca_path}", "-t", tag, str(directory)],
            env=build_environment)
        try:
            run(DOCKER + ["run", "-d", "--name", name, "--privileged", "--cgroupns=private",
                          "--tmpfs", "/run", "--tmpfs", "/run/lock", "--hostname", "canary.example.test",
                          "--mount", f"type=bind,src={ca_path},dst=/run/cloud-ca.pem,readonly",
                          "-e", "CURL_CA_BUNDLE=/run/cloud-ca.pem", tag])
            deadline = time.monotonic() + 45
            while True:
                state = subprocess.run(DOCKER + ["exec", name, "test", "-d", "/run/systemd/system"])
                if state.returncode == 0:
                    break
                inspect = run(DOCKER + ["inspect", "-f", "{{.State.Running}}", name], capture_output=True, text=True).stdout.strip()
                if inspect != "true" or time.monotonic() > deadline:
                    run(DOCKER + ["logs", name])
                    raise RuntimeError("Nested systemd unavailable; native platform test not passed")
                time.sleep(2)
            # All changes are inside this disposable container.
            run(DOCKER + ["exec", name, "/opt/agentzab/install.sh", "preflight"])
            run(DOCKER + ["exec", name, "/opt/agentzab/install.sh", "prepare-csr"])
            before = run(DOCKER + ["exec", name, "sha256sum", "/etc/zabbix/certs/zabbix-agent2.key"],
                         capture_output=True, text=True).stdout
            run(DOCKER + ["exec", name, "/opt/agentzab/install.sh", "prepare-csr"])
            after = run(DOCKER + ["exec", name, "sha256sum", "/etc/zabbix/certs/zabbix-agent2.key"],
                        capture_output=True, text=True).stdout
            assert before == after
            # Verify official signing key bootstrap and actual authenticated APT install.
            code = ("import sys;sys.path.insert(0,'/opt/agentzab/agentzab');"
                    "import rollout;rollout.setup_repository('ubuntu','24.04');"
                    "app=rollout.Rollout();print('APT_VERSION='+app.apt_install())")
            # The mounted CA is public trust material for the session proxy only.
            run(DOCKER + ["exec", name, "sh", "-c",
                         "printf '%s\\n' 'Acquire::https::CaInfo \"/run/cloud-ca.pem\";' > /etc/apt/apt.conf.d/99-test-cloud-ca"])
            if pki:
                run(DOCKER + ["network", "connect", network, name])
                csr = directory / "canary.csr"
                certificate = directory / "agent.cer"
                extensions = directory / "agent.ext"
                extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                                      "extendedKeyUsage=clientAuth,serverAuth\n")
                run(DOCKER + ["cp", f"{name}:/var/lib/zabbix-agent2-rollout/outbox/canary.example.test.csr", str(csr)])
                pki.cmd("x509", "-req", "-in", csr, "-CA", pki.root, "-CAkey", pki.rootkey,
                        "-CAcreateserial", "-days", "90", "-sha256", "-extfile", extensions, "-out", certificate)
                run(DOCKER + ["cp", str(pki.root), f"{name}:/opt/agentzab/common/zabbix_ca.pem"])
                run(DOCKER + ["cp", str(certificate), f"{name}:/var/lib/zabbix-agent2-rollout/inbox/agent.cer"])
                # Match the documented root-owned install(1) handover. Docker
                # cp can preserve the external caller's UID in this daemon.
                run(DOCKER + ["exec", name, "chown", "root:root",
                              "/opt/agentzab/common/zabbix_ca.pem",
                              "/var/lib/zabbix-agent2-rollout/inbox/agent.cer"])
                run(DOCKER + ["exec", name, "/opt/agentzab/install.sh", "check-certs"])
                since = int(time.time())
                run(DOCKER + ["exec", name, "/opt/agentzab/install.sh", "auto", "--confirm-host", "canary.example.test"])
                native_metrics = metrics(since)
                digest_before = run(DOCKER + ["exec", name, "sha256sum", "/var/lib/zabbix-agent2-rollout/managed.json"], capture_output=True).stdout
                run(DOCKER + ["exec", name, "/opt/agentzab/install.sh", "auto"])
                digest_after = run(DOCKER + ["exec", name, "sha256sum", "/var/lib/zabbix-agent2-rollout/managed.json"], capture_output=True).stdout
                assert digest_before == digest_after, "Repeated auto changed managed installation"
                since = int(time.time()) + 1
                run(DOCKER + ["exec", name, "systemctl", "restart", "zabbix-agent2"])
                metrics(since)
                run(DOCKER + ["exec", name, "/opt/agentzab/install.sh", "validate"])
            else:
                run(DOCKER + ["exec", name, "python3", "-c", code])
            run(DOCKER + ["exec", name, "zabbix_agent2", "--version"])
            inactive = subprocess.run(DOCKER + ["exec", name, "systemctl", "is-active", "--quiet", "zabbix-agent2"])
            assert (inactive.returncode == 0) == bool(pki), "Unexpected agent service state"
            assert run(DOCKER + ["exec", name, "test", "!", "-e", "/usr/sbin/policy-rc.d"]).returncode == 0
            result = {"result": "PASS", "platform": "Ubuntu 24.04 amd64, nested systemd",
                      "checks": ["release preflight", "CSR/key idempotence", "pinned official signing key",
                                 "real signed 7.0.x APT install", "premature start prevented", "temporary guard removed"],
                      "limit": "Production Windows PKI and target host still require a real Canary"}
            if pki:
                result["checks"] += ["public CSR signed outside target; private key never copied", "full native auto/install/validate",
                                     "real mTLS metrics", "auto idempotence", "systemd restart and new metrics"]
                result["metrics"] = native_metrics
            (ROOT / ".runtime/platform-result.json").write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps(result, indent=2))
        except Exception:
            subprocess.run(DOCKER + ["exec", name, "systemctl", "status", "zabbix-agent2", "--no-pager"])
            subprocess.run(DOCKER + ["exec", name, "journalctl", "-u", "zabbix-agent2", "--no-pager", "-n", "80"])
            subprocess.run(DOCKER + ["exec", name, "systemctl", "cat", "zabbix-agent2"])
            raise
        finally:
            subprocess.run(DOCKER + ["rm", "-f", name])
            subprocess.run(DOCKER + ["image", "rm", tag], stdout=subprocess.DEVNULL)


if __name__ == "__main__":
    (ROOT / ".runtime").mkdir(exist_ok=True, mode=0o700)
    test_platform()
