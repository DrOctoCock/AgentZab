import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("rollout", ROOT / "agentzab/rollout.py")
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


class PKI:
    def __init__(self, path):
        self.path = Path(path)
        self.path.mkdir(exist_ok=True)
        self.root = self.path / "root.pem"
        self.rootkey = self.path / "root.key"
        self.cmd("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", self.rootkey,
                 "-out", self.root, "-days", "365", "-sha256", "-subj", "/CN=AgentZab TEST ONLY Root",
                 "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")

    def cmd(self, *args):
        return r.command(["openssl", *args])

    def leaf(self, name="host.example.test", *, days=90, eku="clientAuth,serverAuth", san=None,
             ca=None, key=None, is_ca=False, sha="sha256"):
        label = f"leaf-{len(list(self.path.glob('leaf-*.pem')))}"
        key = Path(key) if key else self.path / f"{label}.key"
        csr = self.path / f"{label}.csr"
        cert = self.path / f"{label}.pem"
        ext = self.path / f"{label}.ext"
        if not key.exists():
            self.cmd("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", key)
        self.cmd("req", "-new", "-key", key, "-out", csr, "-subj", f"/CN={name}")
        ext.write_text(f"basicConstraints=critical,CA:{'TRUE' if is_ca else 'FALSE'}\n"
                       f"keyUsage=critical,{'keyCertSign,cRLSign' if is_ca else 'digitalSignature,keyEncipherment'}\n"
                       f"extendedKeyUsage={eku}\n" + (f"subjectAltName=DNS:{san}\n" if san else ""))
        issuer_cert, issuer_key = ca or (self.root, self.rootkey)
        if days < 0:
            database = self.path / f"{label}.index"
            database.write_text("")
            serial = self.path / f"{label}.serial"
            serial.write_text("1000\n")
            config = self.path / f"{label}.ca.cnf"
            config.write_text(f"[ca]\ndefault_ca=local\n[local]\ndatabase={database}\n"
                f"new_certs_dir={self.path}\nserial={serial}\ncertificate={issuer_cert}\n"
                f"private_key={issuer_key}\ndefault_md=sha256\npolicy=names\n[names]\ncommonName=supplied\n")
            self.cmd("ca", "-batch", "-config", config, "-in", csr, "-out", cert,
                     "-notext", "-startdate", "20000101000000Z", "-enddate", "20010101000000Z", "-extfile", ext)
        else:
            self.cmd("x509", "-req", "-in", csr, "-CA", issuer_cert, "-CAkey", issuer_key,
                     "-CAcreateserial", "-out", cert, "-days", str(days), f"-{sha}", "-extfile", ext)
        return cert, key


class CertificatesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.temp.name)
        cls.pki = PKI(cls.path)
        cls.leaf, cls.key = cls.pki.leaf()

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def validate(self, leaf=None, key=None, ca=None, inter=None, hostname="host.example.test"):
        with tempfile.TemporaryDirectory() as tmp:
            return r.Certificates(30).validate(leaf or self.leaf, key or self.key,
                    ca or self.pki.root, inter, hostname, Path(tmp) / "validation")

    def test_valid_leaf(self):
        chain, ca, info = self.validate()
        self.assertEqual(info["subject"], "CN=host.example.test")
        self.assertEqual(chain.count(b"BEGIN CERTIFICATE"), 1)
        self.assertIn(b"CERTIFICATE", ca)

    def test_der(self):
        der = self.path / "agent.cer"
        self.pki.cmd("x509", "-in", self.leaf, "-outform", "DER", "-out", der)
        self.assertEqual(self.validate(leaf=der)[2]["subject"], "CN=host.example.test")

    def test_wrong_key(self):
        cert, key = self.pki.leaf()
        with self.assertRaisesRegex(r.RolloutError, "private key"):
            self.validate(key=key)

    def test_der_with_trailing_content_rejected(self):
        der = self.path / "trailing.cer"
        der.write_bytes(self.pki.cmd("x509", "-in", self.leaf, "-outform", "DER") + b"extra")
        with self.assertRaisesRegex(r.RolloutError, "exactly one"):
            self.validate(leaf=der)

    def test_wrong_hostname(self):
        with self.assertRaisesRegex(r.RolloutError, "CN"):
            self.validate(hostname="other.example.test")

    def test_hostname_case_is_significant(self):
        with self.assertRaisesRegex(r.RolloutError, "CN"):
            self.validate(hostname="HOST.example.test")

    def test_wrong_ca(self):
        with tempfile.TemporaryDirectory() as tmp:
            wrong = PKI(tmp)
            with self.assertRaises(r.RolloutError):
                self.validate(ca=wrong.root)

    def test_short_lifetime(self):
        cert, key = self.pki.leaf(days=2)
        with self.assertRaises(r.RolloutError):
            self.validate(cert, key)

    def test_expired(self):
        cert, key = self.pki.leaf(days=-1)
        with self.assertRaises(r.RolloutError):
            self.validate(cert, key)

    def test_missing_client_eku(self):
        cert, key = self.pki.leaf(eku="serverAuth")
        with self.assertRaisesRegex(r.RolloutError, "EKUs"):
            self.validate(cert, key)

    def test_missing_server_eku(self):
        cert, key = self.pki.leaf(eku="clientAuth")
        with self.assertRaisesRegex(r.RolloutError, "EKUs"):
            self.validate(cert, key)

    def test_agent_san_rejected_by_site_policy(self):
        cert, key = self.pki.leaf(san="host.example.test")
        with self.assertRaisesRegex(r.RolloutError, "SAN"):
            self.validate(cert, key)

    def test_ca_as_leaf_rejected(self):
        cert, key = self.pki.leaf(is_ca=True)
        with self.assertRaisesRegex(r.RolloutError, "CA:FALSE"):
            self.validate(cert, key)

    def test_sha1_rejected(self):
        cert, key = self.pki.leaf(sha="sha1")
        with self.assertRaisesRegex(r.RolloutError, "Weak"):
            self.validate(cert, key)

    def test_private_key_in_public_input(self):
        with self.assertRaisesRegex(r.RolloutError, "Private key"):
            r.Certificates(30).public_pem(self.key)

    def test_multiple_leafs_rejected(self):
        path = self.path / "multiple.pem"
        path.write_bytes(self.leaf.read_bytes() * 2)
        with self.assertRaisesRegex(r.RolloutError, "Exactly one"):
            self.validate(leaf=path)

    def test_garbage_rejected(self):
        path = self.path / "garbage.pem"
        path.write_bytes(self.leaf.read_bytes() + b"garbage")
        with self.assertRaises(r.RolloutError):
            self.validate(leaf=path)

    def test_leaf_in_ca_bundle_rejected(self):
        with self.assertRaisesRegex(r.RolloutError, "non-CA"):
            self.validate(ca=self.leaf)

    def test_intermediate_chain_leaf_first_and_root_excluded(self):
        intermediate, int_key = self.pki.leaf("Issuing TEST CA", is_ca=True)
        leaf, key = self.pki.leaf(ca=(intermediate, int_key))
        chain, _, _ = self.validate(leaf, key, inter=intermediate)
        self.assertEqual(chain.count(b"BEGIN CERTIFICATE"), 2)
        self.assertTrue(chain.startswith(leaf.read_bytes()))
        self.assertNotIn(self.pki.root.read_bytes(), chain)

    def test_missing_intermediate_rejected(self):
        intermediate, int_key = self.pki.leaf("Issuing TEST CA", is_ca=True)
        leaf, key = self.pki.leaf(ca=(intermediate, int_key))
        with self.assertRaises(r.RolloutError):
            self.validate(leaf, key)

    def test_duplicate_identical_intermediate_deduplicated(self):
        intermediate, int_key = self.pki.leaf("Duplicate Issuing TEST CA", is_ca=True)
        leaf, key = self.pki.leaf(ca=(intermediate, int_key))
        bundle = self.path / "mixed-ca-bundle.pem"
        bundle.write_bytes(self.pki.root.read_bytes() + intermediate.read_bytes())
        chain, _, _ = self.validate(leaf, key, ca=bundle, inter=intermediate)
        self.assertEqual(chain.count(b"BEGIN CERTIFICATE"), 2)


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        (self.base / "config").mkdir()
        shutil.copy(ROOT / "config/site.json", self.base / "config/site.json")
        self.app = r.Rollout(self.base, self.base / "state", self.base / "etc")

    def tearDown(self):
        self.temp.cleanup()

    def test_profile_endpoint(self):
        self.assertEqual(self.app.site["server"], "ux-zabbix01.unisg.ch")
        self.assertEqual(self.app.site["port"], 10051)

    def test_active_only_config(self):
        text = r.render("host.example.test", self.app.site, Path("/etc/zabbix/certs"),
                        {"issuer": "CN=CA", "subject": "CN=server.example.test"})
        settings = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
        self.assertEqual(settings["TLSConnect"], "cert")
        self.assertEqual(settings["TLSAccept"], "cert")
        for forbidden in ("Server", "Include", "HostMetadata", "HostMetadataItem", "TLSPSKFile", "TLSPSKIdentity", "StatusPort"):
            self.assertNotIn(forbidden, settings)

    def test_fqdn_validation(self):
        for name in ("localhost", "bad_name.example", "-bad.example.test", "a..test", "a.test\nServer=x", "a/host.test"):
            with self.subTest(name=name), self.assertRaises(r.RolloutError):
                r.fqdn(name)
        self.assertEqual(r.fqdn("Host.Example.test."), "Host.Example.test")

    def test_managed_symlink_rejected(self):
        (self.base / "link").symlink_to(self.base / "target")
        with self.assertRaises(r.RolloutError):
            r.atomic(self.base / "link/file", "do not write")
        self.assertFalse((self.base / "target").exists())

    def test_permissions_check(self):
        file = self.base / "unsafe"
        file.write_text("x")
        file.chmod(0o666)
        with self.assertRaisesRegex(r.RolloutError, "writable"):
            r.secure(file, root=False)

    def test_no_foreign_adoption(self):
        self.app.config.parent.mkdir()
        self.app.config.write_text("existing config")
        with self.assertRaisesRegex(r.RolloutError, "unmanaged"):
            self.app.foreign_guard()
        self.assertEqual(self.app.config.read_text(), "existing config")

    def test_host_confirmation_exact(self):
        with patch.object(self.app, "hostname", return_value="Host.example.test"):
            with self.assertRaises(r.RolloutError):
                self.app.confirm_host("host.example.test")
            self.app.confirm_host("Host.example.test")

    def test_choose_latest_stable_patch_and_revision(self):
        self.assertEqual(r.stable_version(["1:7.0.9-1+ubuntu24.04", "1:7.0.32-1+ubuntu24.04",
                         "1:7.0.32-2+ubuntu24.04", "7.4.9-1", "7.0.33rc1-1", "7.0.34~rc1-1"]),
                         "1:7.0.32-2+ubuntu24.04")

    def test_no_supported_version(self):
        with self.assertRaises(r.RolloutError):
            r.stable_version(["7.4.9-1", "8.0.0-1", "7.0.33~rc1-1"])

    def test_prepare_idempotence_and_key_preservation(self):
        # Unit tests run unprivileged; ownership checks are exercised separately.
        real_secure = r.secure
        with patch.object(r, "secure", side_effect=lambda path, **kw: real_secure(path, root=False, **kw)), \
             patch.object(socket, "getfqdn", return_value="host.example.test"):
            self.app.prepare()
            key = self.app.key.read_bytes()
            csr = (self.app.state / "outbox/host.example.test.csr").read_bytes()
            self.app.prepare()
            self.assertEqual(self.app.key.read_bytes(), key)
            self.assertEqual((self.app.state / "outbox/host.example.test.csr").read_bytes(), csr)
            with patch.object(socket, "getfqdn", return_value="changed.example.test"), self.assertRaises(r.RolloutError):
                self.app.prepare()

    def test_existing_key_not_adopted(self):
        self.app.cert_dir.mkdir(parents=True)
        self.app.key.write_text("existing-key")
        real_secure = r.secure
        with patch.object(r, "secure", side_effect=lambda path, **kw: real_secure(path, root=False, **kw)), \
             patch.object(socket, "getfqdn", return_value="host.example.test"), self.assertRaises(r.RolloutError):
            self.app.prepare()
        self.assertEqual(self.app.key.read_text(), "existing-key")

    def test_profile_path_traversal_rejected(self):
        path = self.base / "config/site.json"
        data = json.loads(path.read_text())
        data["ca_file"] = "../escape.pem"
        path.write_text(json.dumps(data))
        with self.assertRaises(r.RolloutError):
            r.Rollout(self.base)


class TLSTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.pki = PKI(Path(cls.temp.name))
        cls.client, cls.clientkey = cls.pki.leaf()
        cls.server, cls.serverkey = cls.pki.leaf("localhost.example.test")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def tls_check(self, expected="localhost.example.test", ca=None, server=None, serverkey=None):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(server or self.server), str(serverkey or self.serverkey))
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(str(self.pki.root))
        def serve():
            try:
                conn, _ = listener.accept()
                with conn:
                    with context.wrap_socket(conn, server_side=True) as tls:
                        tls.recv(1)
            except ssl.SSLError:
                pass
            finally:
                listener.close()
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        app = r.Rollout()
        app.key = self.clientkey
        app.site = {**app.site, "server": "127.0.0.1", "port": listener.getsockname()[1],
                    "server_certificate_name": expected}
        try:
            return app.server_check(self.client.read_bytes(), Path(ca or self.pki.root).read_bytes())
        finally:
            thread.join(timeout=10)

    def test_real_mutual_tls(self):
        self.assertEqual(self.tls_check()["subject"], "CN=localhost.example.test")

    def test_wrong_server_name(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.tls_check(expected="wrong.example.test")

    def test_wrong_server_ca(self):
        with tempfile.TemporaryDirectory() as tmp:
            wrong = PKI(tmp)
            with self.assertRaises(ssl.SSLCertVerificationError):
                self.tls_check(ca=wrong.root)

    def test_expired_server(self):
        cert, key = self.pki.leaf("localhost.example.test", days=-1)
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.tls_check(server=cert, serverkey=key)


if __name__ == "__main__":
    unittest.main()
