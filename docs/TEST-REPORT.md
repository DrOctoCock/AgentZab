# Lokaler Abschlussbericht – 26.10.2026

> Historischer Laufzeitbericht. Die Regeneration vom 11.11.2026 wiederholt
> keinen APT-/systemd-/Zabbix-Integrationstest. Der Installer-Code ist unverändert;
> spätere offene Befunde stehen im [Review](REVIEW-V2.2.0-VS-3.0.0.md).
> Aktuelle Buildprüfungen: [Regenerationsnotiz](REGENERATION-2026-11-11.md).

Getestete Implementierung `agentzab/rollout.py`, SHA-256:

```text
340401bc9799016d00ade375ba562dafdf1e80a9baf7d1cc36a46c0b06cedc59
```

Der Hash wurde sowohl im Checkout als auch im tatsächlich ausgeführten nativen
Testcontainer abgeglichen. Standortprofil im Labor gezielt auf den isolierten
Testserver umgestellt; das Release selbst bleibt auf den produktiven, im
Anforderungs-Chat genannten Endpunkt voreingestellt.

| Prüfung | Tatsächliches Ergebnis |
|---|---|
| Regression/PKI/TLS | **37 Tests bestanden**, keine übersprungenen Tests; letzter Lauf 12,440 s |
| Reale Agent-Konfiguration | Offizieller Agent 2 akzeptiert gerenderte Konfiguration mit `-T` |
| Reale aktive mTLS-Daten | `agent.ping=1`, `system.uptime>0` in Zabbix-DB nachgewiesen |
| Server-/Agent-Neustart | Erneut frische Messwerte nach Neustart |
| Fremder Client-Aussteller | Serverseitige Zertifikatsablehnung für die IP des ungültigen Clients nachgewiesen |
| Nativer Installer | Ubuntu 24.04 amd64, verschachteltes echtes systemd; vollständiges prepare/check/auto/install/validate erfolgreich |
| APT | Offizielles signiertes Paket `1:7.0.32-1+ubuntu24.04`; festgelegter Zabbix-2024-Schlüssel |
| Startschutz | Agent vor Zertifikatskonfiguration nicht gestartet; temporäre Startschutzdatei entfernt |
| Identität | CSR/Schlüssel wiederverwendet; privater Schlüssel im nativen Zielcontainer geblieben |
| Wiederholtes auto | Verwaltungszustand unverändert, keine erneute Paketinstallation |
| Nativer Dienstneustart | Danach neue Messwerte und erfolgreiche Validierung |
| Release | Zwei byteidentische ZIP-Builds, entpacktes Manifest, Skriptmodi, keine Zertifikate/Schlüssel, Manipulation abgelehnt |

Ein nativer Messpunkt aus dem abgeschlossenen Lauf: `agent.ping=1` bei
Unix-Zeit `1793007796`, `system.uptime=2383` bei `1793007797`. Diese Werte wurden
aus dem echten Zabbix-Verlauf gelesen, nicht vom Test als Ergebnis vorgegeben.
Abschluss des Integrationstests: `2026-10-26T09:43:41Z`.

Ausgeführte lokale Prüfkomponenten:

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 scripts/build.py
python3 scripts/check-release.py
python3 tests/integration.py --platform
```

Der zusammengefasste lokale Einstieg ist `./scripts/local-ci.sh --full`.
Kein gehosteter CI-Dienst und kein Produktionsdeployment. Das Labor wurde
anschließend einschließlich seiner Zielcontainer, Netze und Datenvolumes entfernt.
Docker-Buildcache und heruntergeladene öffentliche Images bleiben als
Entwicklungswerkzeuge verfügbar.

**Nicht abgenommen:** Ubuntu 22.04 / Debian 12 als native Laufzeit, echter
Hardware-/VM-Boot, produktive Windows-PKI, tatsächliche Unternehmens-CA,
Zertifikatsname des produktiven Monitoring-Endpunkts und dessen Latest-data-Werte.
Für die Produktion gilt deshalb weiterhin [ABNAHME.md](ABNAHME.md).
