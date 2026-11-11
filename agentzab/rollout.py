#!/usr/bin/env python3
"""Local active-only Zabbix Agent 2 rollout; no API or autoregistration."""
import argparse
import contextlib
import datetime as dt
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import time

PACKAGE = Path(__file__).resolve().parent.parent
STATE = Path("/var/lib/zabbix-agent2-rollout")
ETC = Path("/etc/zabbix")
SUPPORTED = {("ubuntu", "22.04"), ("ubuntu", "24.04"), ("debian", "12")}
REPO_FINGERPRINT = "4C3D6F2CC75F5146754FC374D913219AB5333005"
PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----\s+.*?-----END CERTIFICATE-----", re.S)


class RolloutError(Exception):
    pass


def command(args, *, data=None, okay=(0,)):
    result = subprocess.run([str(x) for x in args], input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=300)
    if result.returncode not in okay:
        # Only public OpenSSL diagnostics are returned. Never echo input/key material.
        detail = result.stderr.decode(errors="replace")[-1600:]
        raise RolloutError(f"{Path(str(args[0])).name} failed ({result.returncode}): {detail}")
    return result.stdout


def atomic(path, content, mode=0o600, gid=None):
    path = Path(path)
    reject_symlinks(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".rollout-")
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(content.encode() if isinstance(content, str) else content)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(tmp, mode)
        if gid is not None:
            os.chown(tmp, 0, gid)
        os.replace(tmp, path)
    finally:
        Path(tmp).unlink(missing_ok=True)


def reject_symlinks(path):
    path = Path(os.path.abspath(path))
    for part in [*reversed(path.parents), path]:
        if part.is_symlink():
            raise RolloutError(f"Symlink forbidden for managed path: {part}")


def secure(path, *, directory=False, root=True):
    reject_symlinks(path)
    info = Path(path).stat()
    if directory and not stat.S_ISDIR(info.st_mode):
        raise RolloutError(f"Not a directory: {path}")
    if not directory and not stat.S_ISREG(info.st_mode):
        raise RolloutError(f"Not a regular file: {path}")
    if root and info.st_uid != 0:
        raise RolloutError(f"Must be owned by root: {path}")
    if info.st_mode & 0o022:
        raise RolloutError(f"Group/world-writable path refused: {path}")


def verify_package(package=PACKAGE):
    manifest = package / "MANIFEST.json"
    if not manifest.is_file():
        raise RolloutError("Release manifest missing. Build locally: ./scripts/local-ci.sh")
    entries = json.loads(manifest.read_text())
    if not entries or not isinstance(entries, dict):
        raise RolloutError("Invalid release manifest")
    for name, expected in entries.items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise RolloutError("Unsafe manifest path")
        path = package / relative
        reject_symlinks(path)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise RolloutError(f"Package checksum mismatch: {name}")
    # Prevent extra importable code being introduced beside verified modules.
    for path in (package / "agentzab").rglob("*.py"):
        if path.relative_to(package).as_posix() not in entries:
            raise RolloutError("Unmanifested executable module")
    print(f"PASS: {len(entries)} package files match manifest (not an authenticity signature).")


def fqdn(value):
    value = value.rstrip(".")
    if len(value) > 253 or "." not in value or not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", p) for p in value.split(".")):
        raise RolloutError("A valid FQDN is required; fix hostname/DNS before generating a CSR")
    # Preserve case: the Zabbix technical hostname is case sensitive.
    return value


def stable_version(versions):
    candidates = []
    for raw in versions:
        version = raw.strip()
        match = re.fullmatch(r"(?:\d+:)?7\.0\.(\d+)(?:[-+~].*)?", version)
        if match and not re.search(r"alpha|beta|rc|pre|snapshot|dev|nightly|git|trunk|~", version, re.I):
            candidates.append(version)
    if not candidates:
        raise RolloutError("No stable signed Zabbix Agent 2 7.0.x package found in APT sources")
    best = candidates[0]
    for version in candidates[1:]:
        result = subprocess.run(["dpkg", "--compare-versions", version, "gt", best])
        if result.returncode == 0:
            best = version
        elif result.returncode != 1:
            raise RolloutError("dpkg version comparison failed")
    return best


def setup_repository(distribution, version):
    """Bootstrap only the pinned official 2024 signing key, over verified TLS."""
    codename = {("ubuntu", "22.04"): "jammy", ("ubuntu", "24.04"): "noble",
                ("debian", "12"): "bookworm"}.get((distribution, version))
    if not codename:
        raise RolloutError("Unsupported repository target")
    target = Path("/etc/apt/sources.list.d/agentzab.sources")
    keyring = Path("/usr/share/keyrings/agentzab-zabbix.gpg")
    source = (f"Types: deb\nURIs: https://repo.zabbix.com/zabbix/7.0/{distribution}\n"
              f"Suites: {codename}\nComponents: main\nArchitectures: amd64\nSigned-By: {keyring}\n")
    for path in (target, keyring):
        reject_symlinks(path)
        if path.exists():
            secure(path)
    if target.exists() and target.read_text() != source:
        raise RolloutError("Existing agentzab.sources differs; refusing overwrite")
    with tempfile.TemporaryDirectory(prefix="agentzab-repokey-") as tmp:
        tmp = Path(tmp)
        command(["curl", "--fail", "--silent", "--show-error", "--proto", "=https", "--tlsv1.2",
                 "--max-time", "60", "https://repo.zabbix.com/zabbix-official-repo.key", "-o", tmp / "key.asc"])
        command(["gpg", "--batch", "--homedir", tmp, "--import", tmp / "key.asc"])
        exported = command(["gpg", "--batch", "--homedir", tmp, "--export", REPO_FINGERPRINT])
        if not exported:
            raise RolloutError("Official repository key fingerprint changed; review, do not bypass")
        atomic(tmp / "key.gpg", exported)
        details = command(["gpg", "--batch", "--homedir", tmp, "--show-keys", "--with-colons", tmp / "key.gpg"]).decode()
        if f"fpr:::::::::{REPO_FINGERPRINT}:" not in details:
            raise RolloutError("Repository key fingerprint mismatch")
        if keyring.exists() and keyring.read_bytes() != exported:
            raise RolloutError("Existing repository key differs; explicit key lifecycle review required")
        atomic(keyring, exported, 0o644)
    atomic(target, source, 0o644)
    print(f"Configured official signed Zabbix 7.0 repository for {distribution} {codename}.")


class Certificates:
    def __init__(self, minimum_days):
        self.minimum_days = minimum_days

    def public_pem(self, path, single=False):
        data = Path(path).read_bytes()
        if b"PRIVATE KEY" in data:
            raise RolloutError("Private key found in public certificate input")
        blocks = PEM_RE.findall(data)
        if blocks:
            if PEM_RE.sub(b"", data).strip():
                raise RolloutError("Unexpected data outside certificate PEM blocks")
        else:
            blocks = [command(["openssl", "x509", "-inform", "DER", "-in", path, "-outform", "PEM"])]
            if command(["openssl", "x509", "-outform", "DER"], data=blocks[0]) != data:
                raise RolloutError("DER input must contain exactly one canonical X.509 certificate")
        if single and len(blocks) != 1:
            raise RolloutError("Exactly one leaf certificate is required")
        return b"".join(b.rstrip() + b"\n" for b in blocks)

    def info(self, cert):
        def x(*args):
            return command(["openssl", "x509", "-in", cert, "-noout", *args]).decode().strip()
        issuer = x("-issuer", "-nameopt", "RFC2253").split("=", 1)[1].strip()
        subject = x("-subject", "-nameopt", "RFC2253").split("=", 1)[1].strip()
        return {"issuer": issuer, "subject": subject,
                "fingerprint_sha256": x("-fingerprint", "-sha256").split("=", 1)[1]}

    def validate(self, leaf, key, ca, intermediates, hostname, output_dir):
        output_dir.mkdir(parents=True, exist_ok=True)
        leaf_pem = self.public_pem(leaf, single=True)
        ca_pem = self.public_pem(ca)
        inter_pem = self.public_pem(intermediates) if intermediates and Path(intermediates).exists() else b""
        normalized = output_dir / "leaf.pem"
        atomic(normalized, leaf_pem)
        trust = output_dir / "ca.pem"
        atomic(trust, ca_pem)
        untrusted = output_dir / "intermediates.pem"
        atomic(untrusted, inter_pem)
        for block in PEM_RE.findall(ca_pem + inter_pem):
            cert = output_dir / "candidate.pem"
            atomic(cert, block + b"\n")
            text = command(["openssl", "x509", "-in", cert, "-noout", "-text"]).decode()
            if "CA:TRUE" not in text:
                raise RolloutError("CA/intermediate input contains a non-CA certificate")
        text = command(["openssl", "x509", "-in", normalized, "-noout", "-text"]).decode()
        if "CA:FALSE" not in text or "Digital Signature" not in text:
            raise RolloutError("Leaf requires CA:FALSE and Digital Signature key usage")
        if "TLS Web Client Authentication" not in text or "TLS Web Server Authentication" not in text:
            raise RolloutError("Site policy requires both clientAuth and serverAuth EKUs")
        if "Subject Alternative Name" in text:
            raise RolloutError("Site policy forbids SAN on the agent certificate; see PKI handover")
        algorithms = re.findall(r"Signature Algorithm:\s*(\S+)", text)
        if not algorithms or any(re.search(r"md[245]|sha1", a, re.I) for a in algorithms):
            raise RolloutError("Weak certificate signature algorithm")
        subject = command(["openssl", "x509", "-in", normalized, "-noout", "-subject",
                           "-nameopt", "sep_multiline,sname,utf8"]).decode()
        common_names = re.findall(r"^\s*CN\s*=\s*(.*?)\s*$", subject, re.M)
        if common_names != [hostname]:
            raise RolloutError("Agent certificate CN must exactly match the saved Zabbix hostname")
        command(["openssl", "x509", "-in", normalized, "-noout", "-checkend",
                 str(self.minimum_days * 86400)])
        cert_pub = command(["openssl", "x509", "-in", normalized, "-noout", "-pubkey"])
        cert_der = command(["openssl", "pkey", "-pubin", "-outform", "DER"], data=cert_pub)
        key_der = command(["openssl", "pkey", "-in", key, "-pubout", "-outform", "DER"])
        if cert_der != key_der:
            raise RolloutError("Certificate does not match the existing local private key")
        for purpose in ("sslclient", "sslserver"):
            args = ["openssl", "verify", "-CAfile", trust, "-purpose", purpose]
            if inter_pem:
                args += ["-untrusted", untrusted]
            command(args + [normalized])
        # Build leaf-first chain; only available CA certs may be appended.
        pool = []
        fingerprints = set()
        for i, block in enumerate(PEM_RE.findall(inter_pem + ca_pem)):
            cert = output_dir / f"ca-{i}.pem"
            atomic(cert, block + b"\n")
            info = self.info(cert)
            if info["fingerprint_sha256"] not in fingerprints:
                pool.append((cert, info))
                fingerprints.add(info["fingerprint_sha256"])
        chain = leaf_pem
        current = self.info(normalized)
        seen = {current["fingerprint_sha256"]}
        while current["issuer"] != current["subject"]:
            matches = [(p, info) for p, info in pool if info["subject"] == current["issuer"]]
            if len(matches) != 1:
                raise RolloutError("Incomplete or ambiguous CA chain; provide unique issuing certificates")
            path, current = matches[0]
            if current["fingerprint_sha256"] in seen:
                raise RolloutError("Certificate chain loop")
            seen.add(current["fingerprint_sha256"])
            if current["issuer"] != current["subject"]:
                chain += path.read_bytes()
        info = self.info(normalized)
        info.update({"hostname": hostname, "checked_at": dt.datetime.now(dt.timezone.utc).isoformat()})
        return chain, ca_pem, info


def render(hostname, site, cert_dir, server_info):
    # Values have been validated before interpolation. No Include directives:
    # unmanaged snippets must not accidentally re-enable passive checks.
    return ("# Managed by AgentZab; change site profile and rerun install, not this file.\n"
            f"Hostname={hostname}\nServerActive={site['server']}:{site['port']}\n"
            "LogType=system\nTimeout=10\nRefreshActiveChecks=60\nForceActiveChecksOnStart=1\n"
            "TLSConnect=cert\nTLSAccept=cert\n"
            f"TLSCAFile={cert_dir}/zabbix-server-trust-ca.pem\n"
            f"TLSCertFile={cert_dir}/zabbix-agent2-chain.pem\n"
            f"TLSKeyFile={cert_dir}/zabbix-agent2.key\n"
            f"TLSServerCertIssuer={server_info['issuer']}\n"
            f"TLSServerCertSubject={server_info['subject']}\n"
            "DenyKey=system.run[*]\n")


class Rollout:
    def __init__(self, package=PACKAGE, state=STATE, etc=ETC):
        self.package, self.state, self.etc = Path(package), Path(state), Path(etc)
        self.cert_dir = self.etc / "certs"
        self.key = self.cert_dir / "zabbix-agent2.key"
        self.config = self.etc / "zabbix_agent2.conf"
        self.identity = self.state / "identity.json"
        self.marker = self.state / "managed.json"
        self.site = json.loads((self.package / "config/site.json").read_text())
        fqdn(self.site["server"])
        fqdn(self.site["server_certificate_name"])
        if not isinstance(self.site["port"], int) or not 1 <= self.site["port"] <= 65535:
            raise RolloutError("Invalid server port")
        if not isinstance(self.site["minimum_valid_days"], int) or not 1 <= self.site["minimum_valid_days"] <= 365:
            raise RolloutError("minimum_valid_days must be 1..365")
        for key in ("ca_file", "intermediate_file"):
            p = Path(self.site[key])
            if p.is_absolute() or ".." in p.parts:
                raise RolloutError("Site certificate sources must stay inside the package")
        self.certs = Certificates(self.site["minimum_valid_days"])

    def path_setup(self):
        for path in (self.etc, self.cert_dir, self.state):
            reject_symlinks(path)
            path.mkdir(parents=True, exist_ok=True, mode=0o700 if path != self.etc else 0o755)
            secure(path, directory=True)
        for name in ("inbox", "outbox", "reports", "backups"):
            path = self.state / name
            reject_symlinks(path)
            path.mkdir(mode=0o700, exist_ok=True)
            secure(path, directory=True)

    def foreign_guard(self):
        installed = subprocess.run(["dpkg-query", "-W", "-f=${Status}", "zabbix-agent2"],
                                   capture_output=True, text=True)
        present = installed.returncode == 0 and installed.stdout == "install ok installed"
        if not self.marker.exists() and (present or self.config.exists()):
            raise RolloutError("Existing unmanaged agent/configuration: stop; no automatic adoption")
        if self.marker.exists():
            secure(self.marker)
            record = json.loads(self.marker.read_text())
            if record.get("status") not in {"installed", "installing"}:
                raise RolloutError("Unrecognized managed state")
        return present

    def preflight(self):
        if os.geteuid() != 0:
            raise RolloutError("Run from a root-owned release directory as root")
        verify_package(self.package)
        for path in [self.package, *[self.package / p for p in json.loads((self.package / "MANIFEST.json").read_text())]]:
            secure(path, directory=path.is_dir())
        for directory in self.package.rglob("*"):
            if directory.is_dir():
                secure(directory, directory=True)
        os_release = Path("/etc/os-release").resolve(strict=True)
        secure(os_release)
        values = {}
        for line in os_release.read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                values[key] = value.strip('"')
        if (values.get("ID"), values.get("VERSION_ID")) not in SUPPORTED or platform.machine() != "x86_64":
            raise RolloutError("Supported: Ubuntu 22.04/24.04 or Debian 12, amd64, systemd")
        for tool in ("openssl", "apt-get", "apt-cache", "dpkg", "systemctl", "ss", "curl", "gpg", "runuser"):
            if not shutil.which(tool):
                raise RolloutError(f"Missing prerequisite: {tool}; see 00-START-HIER.md")
        if not Path("/run/systemd/system").is_dir():
            raise RolloutError("A running systemd host is required; containers without systemd are not rollout targets")
        self.foreign_guard()
        self.distribution = values
        for path in (self.etc, self.cert_dir, self.state, self.key, self.identity, self.config, self.marker):
            reject_symlinks(path)
            if path.exists():
                secure(path, directory=path.is_dir())
        fqdn(socket.getfqdn())
        print(f"PASS: {values['ID']} {values['VERSION_ID']}, amd64, local prerequisites and ownership")
        return values

    def hostname(self):
        current = fqdn(socket.getfqdn())
        if self.identity.exists():
            secure(self.identity)
            saved = json.loads(self.identity.read_text())["hostname"]
            if saved != current:
                raise RolloutError("Hostname changed since CSR generation; identity must be reviewed explicitly")
            return saved
        return current

    def prepare(self):
        self.path_setup()
        hostname = self.hostname()
        if self.key.exists() and not self.identity.exists():
            raise RolloutError("Existing unowned key refused; it will not be overwritten or adopted")
        if self.identity.exists() and not self.key.exists():
            raise RolloutError("Saved identity exists but key is missing; refusing implicit key rotation")
        if not self.key.exists():
            key = command(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:4096"])
            atomic(self.key, key)
        secure(self.key)
        if self.key.stat().st_mode & 0o007:
            raise RolloutError("Private key has permissions for other users; fix ownership/access before proceeding")
        public_key = command(["openssl", "pkey", "-in", self.key, "-pubout", "-outform", "DER"])
        key_sha = hashlib.sha256(public_key).hexdigest()
        if self.identity.exists() and json.loads(self.identity.read_text())["public_key_sha256"] != key_sha:
            raise RolloutError("Private key differs from the saved identity")
        if not self.identity.exists():
            atomic(self.identity, json.dumps({"hostname": hostname, "public_key_sha256": key_sha}, indent=2))
        csr = self.state / "outbox" / f"{hostname}.csr"
        if csr.exists():
            command(["openssl", "req", "-in", csr, "-noout", "-verify"])
            csr_pub = command(["openssl", "req", "-in", csr, "-noout", "-pubkey"])
            csr_der = command(["openssl", "pkey", "-pubin", "-outform", "DER"], data=csr_pub)
            subject = command(["openssl", "req", "-in", csr, "-noout", "-subject", "-nameopt", "RFC2253"])
            if csr_der != public_key or subject.decode().strip() != f"subject=CN={hostname}":
                raise RolloutError("Existing CSR identity/key mismatch")
        else:
            atomic(csr, command(["openssl", "req", "-new", "-sha256", "-key", self.key,
                                "-subj", f"/CN={hostname}", "-addext",
                                "extendedKeyUsage=clientAuth,serverAuth"]))
        metadata = {"hostname": hostname, "csr_sha256": hashlib.sha256(csr.read_bytes()).hexdigest(),
                    "public_key_sha256": key_sha, "private_key_exported": False}
        atomic(csr.with_suffix(".request-metadata.json"), json.dumps(metadata, indent=2))
        print(f"CSR: {csr}\nPrivate key stays local. Ask Windows PKI to sign, then place agent.cer/.crt/.pem in {self.state / 'inbox'}")

    def certificate_inputs(self):
        candidates = [self.state / "inbox" / name for name in ("agent.cer", "agent.crt", "agent.pem")
                      if (self.state / "inbox" / name).exists()]
        if len(candidates) != 1:
            raise RolloutError("Place exactly one of agent.cer, agent.crt or agent.pem in inbox")
        ca = self.package / self.site["ca_file"]
        if not ca.exists():
            ca = self.cert_dir / "zabbix_ca.pem"
        if not ca.exists():
            raise RolloutError("Trusted public CA missing: provide common/zabbix_ca.pem via your approved channel")
        intermediates = self.package / self.site["intermediate_file"]
        for path in [*candidates, ca, *([intermediates] if intermediates.exists() else [])]:
            secure(path)
        return candidates[0], ca, intermediates

    def check_certs(self, report=True):
        if not self.identity.exists():
            raise RolloutError("No saved identity; run prepare-csr first")
        hostname = self.hostname()
        leaf, ca, intermediate = self.certificate_inputs()
        # Validation itself leaves no files behind. Reports are explicit outputs.
        with tempfile.TemporaryDirectory(prefix="agentzab-certs-") as tmp:
            result = self.certs.validate(leaf, self.key, ca, intermediate, hostname, Path(tmp))
        if report:
            info = result[2]
            text = (f"Host name: {hostname}\nMonitored by: server at {self.site['server']}:{self.site['port']}\n"
                    "Template: Linux by Zabbix agent active\nStatus: Enabled\n"
                    "Encryption / Connections from host: Certificate ONLY\n"
                    f"Issuer: {info['issuer']}\nSubject: {info['subject']}\n"
                    "Agent interface: not needed for active-only items\n"
                    "Create host manually; no API, HostMetadata or autoregistration used.\n")
            atomic(self.state / "reports/zabbix-host-manual-values.txt", text)
            print(text)
        return result

    def server_check(self, chain, ca_pem):
        with tempfile.TemporaryDirectory(prefix="agentzab-tls-") as tmp:
            tmp = Path(tmp)
            atomic(tmp / "ca.pem", ca_pem)
            atomic(tmp / "chain.pem", chain)
            context = ssl.create_default_context(cafile=str(tmp / "ca.pem"))
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = True
            context.load_cert_chain(str(tmp / "chain.pem"), str(self.key))
            # Direct native TCP is required on a target host (not HTTP CONNECT).
            with socket.create_connection((self.site["server"], self.site["port"]), timeout=10) as raw:
                with context.wrap_socket(raw, server_hostname=self.site["server_certificate_name"]) as tls:
                    peer = tls.getpeercert(binary_form=True)
                    atomic(tmp / "server.pem", ssl.DER_cert_to_PEM_cert(peer))
                    command(["openssl", "x509", "-in", tmp / "server.pem", "-noout", "-checkend",
                             str(self.site["minimum_valid_days"] * 86400)])
                    info = self.certs.info(tmp / "server.pem")
        print("PASS: mTLS handshake, trusted server chain, expected server name and certificate lifetime")
        return info

    def confirm_host(self, supplied):
        expected = self.hostname()
        if supplied is None:
            if not sys.stdin.isatty():
                raise RolloutError("Confirm manual host creation: --confirm-host <exact-hostname>")
            supplied = input(f"After manually creating the host, type its exact name ({expected}): ")
        if supplied != expected:
            raise RolloutError("Host confirmation does not match saved identity")
        print("Host confirmation recorded as an operator assertion, not a server-side verification.")

    def apt_install(self):
        # Use only configured APT sources. Signed Release/Packages metadata and
        # package hashes remain mandatory. Never fetch an unsigned bootstrap .deb.
        environment = os.environ.copy()
        environment["DEBIAN_FRONTEND"] = "noninteractive"
        subprocess.run(["apt-get", "-o", "APT::Get::AllowUnauthenticated=false",
                        "-o", "Acquire::AllowInsecureRepositories=false",
                        "-o", "Acquire::AllowDowngradeToInsecureRepositories=false", "update"],
                       env=environment, check=True, timeout=600)
        listing = command(["apt-cache", "madison", "zabbix-agent2"]).decode()
        version = stable_version([line.split("|")[1].strip() for line in listing.splitlines() if "|" in line])
        installed = subprocess.run(["dpkg-query", "-W", "-f=${Version}", "zabbix-agent2"],
                                   capture_output=True, text=True)
        if installed.returncode == 0:
            newer = subprocess.run(["dpkg", "--compare-versions", installed.stdout, "gt", version])
            if newer.returncode == 0:
                raise RolloutError("Refusing implicit downgrade of installed agent")
        policy = Path("/usr/sbin/policy-rc.d")
        if policy.exists() or policy.is_symlink():
            raise RolloutError("Existing policy-rc.d: no automatic replacement; use a clean target or review service-start policy")
        # New agent must not run with vendor defaults between dpkg and config.
        try:
            fd = os.open(policy, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
            with os.fdopen(fd, "w") as out:
                out.write("#!/bin/sh\n# AgentZab temporary package-install start guard\nexit 101\n")
            os.chmod(policy, 0o755)
            subprocess.run(["apt-get", "-o", "APT::Get::AllowUnauthenticated=false", "install", "-y",
                            "--no-install-recommends", "-o", "Dpkg::Options::=--force-confold",
                            f"zabbix-agent2={version}"], env=environment, check=True, timeout=900)
        finally:
            # Remove only the exact guard created by this process.
            if policy.exists() and policy.read_text() == "#!/bin/sh\n# AgentZab temporary package-install start guard\nexit 101\n":
                policy.unlink()
        print(f"Installed signed APT package: zabbix-agent2={version}")
        return version

    def install(self, confirmation):
        self.foreign_guard()
        chain, ca_pem, info = self.check_certs()
        self.confirm_host(confirmation)
        peer = self.server_check(chain, ca_pem)
        # Resolve package availability before stopping an existing managed service.
        listing = command(["apt-cache", "madison", "zabbix-agent2"]).decode()
        try:
            stable_version([line.split("|")[1].strip() for line in listing.splitlines() if "|" in line])
        except RolloutError:
            setup_repository(self.distribution["ID"], self.distribution["VERSION_ID"])
        policy = Path("/usr/sbin/policy-rc.d")
        if policy.exists() or policy.is_symlink():
            raise RolloutError("Existing policy-rc.d: review required before any service is stopped")
        stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup = self.state / "backups" / stamp
        backup.mkdir(mode=0o700)
        prior_active = subprocess.run(["systemctl", "is-active", "--quiet", "zabbix-agent2"]).returncode == 0
        prior_enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", "zabbix-agent2"],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        targets = [self.config, self.cert_dir / "zabbix-agent2-chain.pem", self.cert_dir / "zabbix-server-trust-ca.pem"]
        prior = {}
        for target in targets:
            if target.exists():
                secure(target)
                prior[target.name] = (target.read_bytes(), stat.S_IMODE(target.stat().st_mode), target.stat().st_gid)
                atomic(backup / target.name, target.read_bytes())
        old_marker = self.marker.read_bytes() if self.marker.exists() else None
        atomic(backup / "service-state.json", json.dumps({"active": prior_active, "enabled": prior_enabled}))
        atomic(self.marker, json.dumps({"status": "installing", "hostname": self.hostname()}))
        try:
            if prior_active:
                command(["systemctl", "stop", "zabbix-agent2"])
            version = self.apt_install()
            gid = grp.getgrnam("zabbix").gr_gid
            # CSR preparation uses umask 077, so a newly created /etc/zabbix
            # is intentionally root-only. The service user needs traversal
            # after installation, including for systemd's ExecStartPre=-T.
            os.chown(self.etc, 0, gid)
            os.chmod(self.etc, 0o750)
            os.chown(self.cert_dir, 0, gid)
            os.chmod(self.cert_dir, 0o750)
            os.chown(self.key, 0, gid)
            os.chmod(self.key, 0o640)
            atomic(targets[1], chain, 0o640, gid)
            atomic(targets[2], ca_pem, 0o640, gid)
            rendered = render(self.hostname(), self.site, self.cert_dir, peer)
            atomic(self.config, rendered, 0o640, gid)
            command(["runuser", "-u", "zabbix", "--", "zabbix_agent2", "-T", "-c", self.config])
            command(["systemctl", "enable", "zabbix-agent2"])
            command(["systemctl", "restart", "zabbix-agent2"])
            record = {"status": "installed", "hostname": self.hostname(), "version": version,
                      "config_sha256": hashlib.sha256(self.config.read_bytes()).hexdigest(),
                      "trust_sha256": hashlib.sha256(ca_pem).hexdigest(),
                      "chain_sha256": hashlib.sha256(chain).hexdigest(),
                      "server_certificate": peer, "agent_certificate": info, "last_backup": str(backup)}
            atomic(self.marker, json.dumps(record, indent=2))
            self.validate()
        except Exception:
            subprocess.run(["systemctl", "stop", "zabbix-agent2"], capture_output=True)
            for target in targets:
                if target.name in prior:
                    data, mode, gid = prior[target.name]
                    atomic(target, data, mode, gid)
                else:
                    target.unlink(missing_ok=True)
            subprocess.run(["systemctl", "enable" if prior_enabled else "disable", "zabbix-agent2"], capture_output=True)
            if old_marker is not None:
                atomic(self.marker, old_marker)
                if prior_active:
                    subprocess.run(["systemctl", "start", "zabbix-agent2"], capture_output=True)
            # First-install failure remains marked 'installing' for a safe retry.
            # Installed packages and PKI actions are not rolled back.
            raise

    def validate(self):
        if not self.marker.exists():
            raise RolloutError("No managed installation")
        record = json.loads(self.marker.read_text())
        if record.get("status") != "installed":
            raise RolloutError("Previous install did not complete; inspect reports/backups and retry install")
        if hashlib.sha256(self.config.read_bytes()).hexdigest() != record["config_sha256"]:
            raise RolloutError("Managed config drift detected; no automatic overwrite during validate")
        if render(self.hostname(), self.site, self.cert_dir, record["server_certificate"]) != self.config.read_text():
            raise RolloutError("Site profile differs from installed config; explicit install required")
        for filename, digest_key in (("zabbix-server-trust-ca.pem", "trust_sha256"),
                                     ("zabbix-agent2-chain.pem", "chain_sha256")):
            if hashlib.sha256((self.cert_dir / filename).read_bytes()).hexdigest() != record[digest_key]:
                raise RolloutError("Managed certificate/CA drift detected; review and use explicit install")
        for path in (self.key, self.config, self.cert_dir / "zabbix-agent2-chain.pem", self.cert_dir / "zabbix-server-trust-ca.pem"):
            secure(path)
            if stat.S_IMODE(path.stat().st_mode) != 0o640 or path.stat().st_gid != grp.getgrnam("zabbix").gr_gid:
                raise RolloutError(f"Managed file must be root:zabbix 0640: {path}")
        for path in (self.etc, self.cert_dir):
            if stat.S_IMODE(path.stat().st_mode) != 0o750 or path.stat().st_gid != grp.getgrnam("zabbix").gr_gid:
                raise RolloutError(f"Managed directory must be root:zabbix 0750: {path}")
        command(["runuser", "-u", "zabbix", "--", "zabbix_agent2", "-T", "-c", self.config])
        command(["systemctl", "is-enabled", "--quiet", "zabbix-agent2"])
        command(["systemctl", "is-active", "--quiet", "zabbix-agent2"])
        listeners = command(["ss", "-H", "-ltn", "sport = :10050"]).strip()
        if listeners:
            raise RolloutError("TCP 10050 is listening; active-only acceptance failed")
        with tempfile.TemporaryDirectory(prefix="agentzab-installed-") as tmp:
            tmp = Path(tmp)
            chainfile = self.cert_dir / "zabbix-agent2-chain.pem"
            blocks = PEM_RE.findall(chainfile.read_bytes())
            atomic(tmp / "leaf.pem", blocks[0] + b"\n")
            atomic(tmp / "intermediates.pem", b"\n".join(blocks[1:]) + b"\n")
            inter = tmp / "intermediates.pem" if len(blocks) > 1 else None
            self.certs.validate(tmp / "leaf.pem", self.key, self.cert_dir / "zabbix-server-trust-ca.pem",
                                inter, self.hostname(), tmp / "checked")
            peer = self.server_check(chainfile.read_bytes(), (self.cert_dir / "zabbix-server-trust-ca.pem").read_bytes())
        if any(peer[key] != record["server_certificate"][key] for key in ("issuer", "subject")):
            raise RolloutError("Server certificate DN changed; review and rerun explicit install")
        # Avoid mistaking historical startup errors for current failures.
        started = command(["systemctl", "show", "-p", "ActiveEnterTimestamp", "--value", "zabbix-agent2"]).decode().strip()
        if not started:
            raise RolloutError("Unable to determine current service start time")
        logs = command(["journalctl", "-u", "zabbix-agent2", "--since", started, "--no-pager", "-n", "100"]).decode()
        errors = [line for line in logs.splitlines() if re.search(
            r"active check configuration.*fail|cannot connect|certificate verify failed|host.*not found|not allowed", line, re.I)]
        if errors:
            raise RolloutError("Agent journal contains connection/configuration failures since service start; inspect journalctl")
        print("PASS: local config, certificates, systemd, active-only port and verified mTLS")
        print("PENDING: confirm fresh values for this exact host under Monitoring > Latest data. Local validation cannot prove ingestion.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["auto", "preflight", "prepare-csr", "check-certs", "install", "validate", "verify-package"])
    parser.add_argument("--confirm-host", help="Operator confirms the manually created Zabbix technical hostname")
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        if args.action == "verify-package":
            verify_package()
            return 0
        rollout = Rollout()
        rollout.preflight()
        # State creation is only performed by explicitly mutating actions.
        if args.action == "preflight":
            return 0
        if args.action in {"auto", "prepare-csr", "install"}:
            rollout.path_setup()
        reject_symlinks(rollout.state / ".lock")
        if not rollout.state.exists():
            raise RolloutError("No prepared state; run prepare-csr first")
        with (rollout.state / ".lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise RolloutError("Another rollout command is running") from exc
            if args.action == "auto":
                if rollout.marker.exists() and json.loads(rollout.marker.read_text()).get("status") == "installed":
                    rollout.validate()
                else:
                    rollout.prepare()
                    candidates = [rollout.state / "inbox" / p for p in ("agent.cer", "agent.crt", "agent.pem")]
                    if not any(p.exists() for p in candidates):
                        print("WAITING_FOR_PKI: no agent certificate yet. No package installed or service started.")
                        return 10
                    rollout.install(args.confirm_host)
            elif args.action == "prepare-csr":
                rollout.prepare()
            elif args.action == "check-certs":
                rollout.check_certs()
            elif args.action == "install":
                rollout.install(args.confirm_host)
            elif args.action == "validate":
                rollout.validate()
        return 0
    except (RolloutError, OSError, ValueError, KeyError, subprocess.SubprocessError, IndexError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
