#!/usr/bin/env python3
"""Local disposable real Zabbix + mTLS agent test. No production/API access."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from test_rollout import PKI, r

DOCKER = ["docker", "--host=unix:///var/run/docker.sock"]
SERVER = "zabbix/zabbix-server-pgsql:alpine-7.0-latest@sha256:d588ddda13224e6ca526438cc2f764e6da92dd3b248c96827f7063961a10e1e3"
AGENT = "zabbix/zabbix-agent2:alpine-7.0-latest@sha256:5c06f3dd14793bc37b79a78112c78349350564af5678572cec852fba6e8a5e54"
POSTGRES = "postgres:16-alpine@sha256:0cefaabd882e42bcb2a2f3dc56d3ce4770560ba62fd7f197f1a2e008fd5731ab"


def run(args, **kw):
    return subprocess.run(args, check=True, **kw)


def integration():
    run(DOCKER + ["info", "--format", "Docker {{.ServerVersion}}"])
    project = "agentzabtest-" + secrets.token_hex(4)
    results = {"started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "checks": []}
    # Under workspace so the local Docker daemon can mount these files.
    with tempfile.TemporaryDirectory(prefix="agentzab-lab-", dir=ROOT / ".runtime") as directory:
        lab = Path(directory)
        pki = PKI(lab / "pki")
        server, serverkey = pki.leaf("zabbix.lab.test")
        leaf, key = pki.leaf("canary.example.test")
        cert_dir = lab / "certs"
        cert_dir.mkdir()
        cert_dir.chmod(0o755)
        mapping = {"zabbix-server-trust-ca.pem": pki.root, "zabbix-agent2-chain.pem": leaf,
                   "zabbix-agent2.key": key, "server.pem": server, "server.key": serverkey}
        for name, source in mapping.items():
            shutil.copy(source, cert_dir / name)
            # Test-only keys, generated per run, never released; non-root image UID reads them.
            (cert_dir / name).chmod(0o444)
        site = {"server": "zabbix.lab.test", "port": 10051}
        peer = r.Certificates(30).info(server)
        config = r.render("canary.example.test", site, Path("/run/pki"), peer)
        (cert_dir / "agent-production.conf").write_text(config)
        (cert_dir / "agent.conf").write_text(config.replace("LogType=system", "LogType=console"))
        (cert_dir / "agent-production.conf").chmod(0o444)
        (cert_dir / "agent.conf").chmod(0o444)
        password = secrets.token_hex(24)
        compose_file = lab / "compose.json"
        config = {"services": {
            "db": {"image": POSTGRES, "environment": {"POSTGRES_USER": "zabbix", "POSTGRES_DB": "zabbix",
                     "POSTGRES_PASSWORD": password}, "networks": ["lab"],
                   "healthcheck": {"test": ["CMD-SHELL", "pg_isready -U zabbix -d zabbix"],
                                   "interval": "2s", "timeout": "2s", "retries": 60}},
            "server": {"image": SERVER, "networks": {"lab": {"aliases": ["zabbix.lab.test"]}}, "volumes": [f"{cert_dir}:/run/pki:ro"],
                       "environment": {"DB_SERVER_HOST": "db", "POSTGRES_USER": "zabbix", "POSTGRES_DB": "zabbix",
                          "POSTGRES_PASSWORD": password, "ZBX_TLSCAFILE": "/run/pki/zabbix-server-trust-ca.pem",
                          "ZBX_TLSCERTFILE": "/run/pki/server.pem", "ZBX_TLSKEYFILE": "/run/pki/server.key",
                          "ZBX_CACHEUPDATEFREQUENCY": "10"},
                       "depends_on": {"db": {"condition": "service_healthy"}}},
            "agent": {"image": AGENT, "entrypoint": ["zabbix_agent2"],
                      "command": ["-f", "-c", "/run/pki/agent.conf"], "networks": ["lab"],
                      "volumes": [f"{cert_dir}:/run/pki:ro"]}},
                   "networks": {"lab": {"internal": True}}}
        compose_file.write_text(json.dumps(config))
        compose_file.chmod(0o600)
        compose = DOCKER + ["compose", "-p", project, "-f", str(compose_file)]

        def sql(statement):
            return run(compose + ["exec", "-T", "db", "psql", "-U", "zabbix", "-d", "zabbix", "-At", "-v", "ON_ERROR_STOP=1"],
                       input=statement, capture_output=True, text=True).stdout.strip()

        try:
            run(compose + ["up", "-d", "--wait", "--wait-timeout", "120", "db", "server"])
            deadline = time.monotonic() + 180
            while True:
                try:
                    logs = run(compose + ["logs", "server"], capture_output=True, text=True).stdout
                    if sql("SELECT count(*) FROM dbversion;") == "1" and "server #0 started" in logs:
                        break
                except subprocess.CalledProcessError:
                    pass
                if time.monotonic() > deadline:
                    raise AssertionError("Zabbix schema initialization timed out")
                time.sleep(3)
            # Lab fixture mirrors manual frontend settings. Production never uses SQL or API.
            issuer = r.Certificates(30).info(leaf)["issuer"].replace("'", "''")
            subject = r.Certificates(30).info(leaf)["subject"].replace("'", "''")
            sql(f"""UPDATE hosts SET status=1 WHERE host='Zabbix server';
INSERT INTO hosts(hostid,host,name,status,tls_connect,tls_accept,tls_issuer,tls_subject)
VALUES(99001,'canary.example.test','canary.example.test',0,4,4,'{issuer}','{subject}');
INSERT INTO items(itemid,hostid,name,key_,type,value_type,delay,history,trends)
VALUES(99001,99001,'Agent ping','agent.ping',7,3,'5s','1d','1d'),
      (99002,99001,'Uptime','system.uptime',7,3,'5s','1d','1d');
INSERT INTO host_rtdata(hostid) VALUES(99001);
INSERT INTO item_rtdata(itemid) VALUES(99001),(99002);""")
            # Zabbix 7 uses a change journal for incremental config sync.
            # A SQL fixture has no frontend journal events, so load it via a
            # fresh server start rather than pretending config_cache_reload suffices.
            run(compose + ["restart", "server"])
            run(compose + ["run", "--rm", "--no-deps", "agent", "-T", "-c", "/run/pki/agent-production.conf"])
            results["checks"].append("real Agent 2 accepts unmodified rendered production config")
            run(compose + ["up", "-d", "agent"])

            def metrics(since):
                deadline = time.monotonic() + 150
                while True:
                    rows = sql(f"SELECT itemid,value,clock FROM history_uint WHERE itemid IN(99001,99002) AND clock>={since} ORDER BY clock DESC;")
                    values = {}
                    for row in rows.splitlines():
                        item, value, clock = row.split("|")
                        values.setdefault(item, {"value": int(value), "clock": int(clock)})
                    if values.get("99001", {}).get("value") == 1 and values.get("99002", {}).get("value", 0) > 0:
                        return values
                    if time.monotonic() > deadline:
                        raise AssertionError("Fresh agent.ping=1 and system.uptime>0 not ingested over mTLS")
                    time.sleep(3)
            results["metrics_initial"] = metrics(int(time.time()) - 1)
            results["checks"].append("real Zabbix server stores fresh active certificate-only ping and uptime")
            # Prove transport recovers with NEW data after restart, not cached rows.
            since = int(time.time()) + 1
            run(compose + ["restart", "server", "agent"])
            results["metrics_after_restart"] = metrics(since)
            results["checks"].append("fresh measurements after server and agent restart")
            # An unrelated issuer cannot enroll even with the correct host name.
            wrong_pki = PKI(lab / "wrong-pki")
            wrong_leaf, wrong_key = wrong_pki.leaf("canary.example.test")
            wrong = lab / "wrong"
            wrong.mkdir()
            shutil.copytree(cert_dir, wrong, dirs_exist_ok=True)
            for name, source in [("zabbix-agent2-chain.pem", wrong_leaf), ("zabbix-agent2.key", wrong_key)]:
                target = wrong / name
                target.unlink()
                shutil.copy(source, target)
                target.chmod(0o444)
            network = project + "_lab"
            invalid_name = project + "-invalid"
            run(DOCKER + ["run", "-d", "--name", invalid_name, "--network", network,
                          "-v", f"{wrong}:/run/pki:ro", "--entrypoint", "zabbix_agent2", AGENT,
                          "-f", "-c", "/run/pki/agent.conf"], stdout=subprocess.DEVNULL)
            invalid_ip = run(DOCKER + ["inspect", "--format",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", invalid_name],
                capture_output=True, text=True).stdout.strip()
            try:
                deadline = time.monotonic() + 30
                while True:
                    output = run(DOCKER + ["logs", invalid_name], capture_output=True, text=True)
                    logs = output.stdout + output.stderr
                    server_output = run(compose + ["logs", "server"], capture_output=True, text=True)
                    rejected = [line for line in (server_output.stdout + server_output.stderr).splitlines()
                                if invalid_ip in line and re.search(r"unable to get local issuer|certificate verify failed|unknown ca", line, re.I)]
                    if rejected:
                        results["client_rejection"] = "server logged certificate verification failure for the invalid client's IP"
                        break
                    if time.monotonic() > deadline:
                        print(logs[-3000:])
                        raise AssertionError("Invalid certificate did not produce expected TLS rejection")
                    time.sleep(2)
            finally:
                run(DOCKER + ["rm", "-f", invalid_name], stdout=subprocess.DEVNULL)
            results["checks"].append("real agent with untrusted client issuer is rejected by TLS")
            if "--platform" in sys.argv:
                run(compose + ["stop", "agent"])
                from platforms import test_platform
                test_platform(pki=pki, network=network, metrics=metrics)
                results["checks"].append("native Ubuntu APT/systemd full installer workflow and fresh metrics")
            results["result"] = "PASS"
        except Exception:
            # Logs contain only disposable test material, not production keys.
            run(compose + ["logs", "--tail", "70"])
            raise
        finally:
            run(compose + ["down", "--volumes", "--remove-orphans"])
    results["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    output = ROOT / ".runtime" / "integration-result.json"
    output.write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    (ROOT / ".runtime").mkdir(exist_ok=True, mode=0o700)
    integration()
