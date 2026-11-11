# AgentZab – Linux Agent 2, active-only, Windows-PKI

**Stand 11.11.2026: 3.0.0 erneut paketiert, Funktionsstand unverändert.**
Der spätere Vergleich mit dem Originalpaket v2.2.0 hat offene PKI- und
Schutzfunktionen aufgezeigt. Vor einem produktiven Einsatz den
[Reviewbericht](docs/REVIEW-V2.2.0-VS-3.0.0.md) beachten. Dieser Build behebt
diese Befunde nicht und stellt keine neue Produktionsfreigabe dar.

## Dateien

- [ZIP-Paket 3.0.0](dist/agentzab-linux-mtls-3.0.0.zip)
- [SHA-256-Prüfsumme](dist/agentzab-linux-mtls-3.0.0.zip.sha256)
- [Startanleitung](00-START-HIER.md)
- [Historischer Laufzeit-Testbericht vom 26.10.2026](docs/TEST-REPORT.md)
- [Regeneration und aktuelle Prüfergebnisse](docs/REGENERATION-2026-11-11.md)

Ein lokal ausgeführtes Rollout-Paket für den bestehenden Zabbix-Endpunkt
`ux-zabbix01.unisg.ch:10051`. Kein Ansible, keine Produktions-API,
keine Autoregistrierung. Zertifikate statt PSK. Technischer Hostname und
Hostanlage bleiben gemäß Vorgabe unter Kontrolle des Monitoring-Teams.

**Start:** [00-START-HIER.md](00-START-HIER.md)

Das Release enthält Installer, Standortprofil, PKI-Übergabe, Betriebsanleitung,
Abnahmecheckliste und lokale Tests. Produktionszertifikate sind nicht enthalten.

```sh
./scripts/local-ci.sh --integration
# Vollständiger nativer Ubuntu-/systemd-Test: ./scripts/local-ci.sh --full
# dist/agentzab-linux-mtls-3.0.0.zip + .zip.sha256
```

CI/CD wird lokal ausgeführt; es gibt keinen gehosteten Workflow und keinen
automatischen Rollout in Produktion. Für die Zielsysteme sind Ubuntu 22.04/24.04
und Debian 12, amd64 mit systemd vorgesehen. Die tatsächliche Testabdeckung
und die noch erforderliche Produktionsabnahme stehen in
[docs/VALIDIERUNG.md](docs/VALIDIERUNG.md).

## Design und Grenzen

- Private RSA-4096-Schlüssel entstehen auf dem Zielhost und bleiben dort.
- `auto` ist zweiphasig: erst CSR, nach PKI-Rückgabe und Hostbestätigung Installation.
- Aktive Checks mit gegenseitiger Zertifikatsprüfung; kein Listener auf TCP 10050.
- PEM oder ein DER-X.509-Leaf; Kettenprüfung, CN-/Key-Match und DN-Ermittlung automatisch.
- Verifizierter TLS-Handshake zum Monitoring-Endpunkt, inklusive erwarteten DNS-Namens;
  danach werden Server-Issuer und -Subject in der Agent-Konfiguration eingeschränkt.
- Installation des höchsten stabilen 7.0.x-Paketstands aus den freigegebenen APT-Quellen.
  Falls dort kein 7.0-Paket bekannt ist, Einrichtung des offiziellen 7.0-Repositories
  mit festgelegtem Signaturschlüssel. Keine Änderung auf eine andere Versionslinie.
- Fremdverwaltete Agent-2-Installationen werden abgelehnt. Die fehlende frühe
  Erkennung eines klassischen `zabbix-agent` ist im Review dokumentiert.
- Wiederholtes `auto` nach erfolgreicher Installation validiert nur. Updates,
  Zertifikatserneuerungen und neue Standortprofile benötigen ausdrücklich `install`.
- Lokale Sicherung und Rücknahme der verwalteten Konfiguration bei Installationsfehlern;
  kein vollständiger Paket-, PKI- oder Systemrollback.

Die Grundlage ist der am 26.10.2026 abgerufene
[geteilte Anforderungs-Chat](https://chatgpt.com/share/6adf169a-02e4-83eb-8aad-5f210989b6a6).
Dieses Paket ist eine neue Implementierung. Das später bereitgestellte Original
v2.2.0 wurde separat verglichen; die Unterschiede sind im Review dokumentiert.
Die ursprünglichen Uploads und produktives Zertifikatsmaterial werden nicht
in dieses Repository aufgenommen.
