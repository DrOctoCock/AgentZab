# Validierungsumfang

Dieser Bericht unterscheidet lokale Paketprüfung, lokale reale Integration und
Produktionsabnahme. Aktuelle Befehlsausgaben aus `scripts/local-ci.sh` und
`.runtime/integration-result.json` sind die Belege des jeweiligen Laufs.

## Prüfungen

- Unit-/Regressionstests: reale OpenSSL-Zertifikate und Python-TLS-Verbindungen;
  keine trivialen Null-Testläufe. Positive und negative CA-, CN-, Key-, EKU-,
  SAN-, Laufzeit- und Kettenfälle, FQDN-/Versionsauswahl, Pfadschutz, Fremdschutz
  und unveränderte CSR-/Schlüsselwiederverwendung.
- Release: zweimal byteidentisches ZIP, entpacktes Manifest und ausführbare
  Skripte, keine Schlüssel/Zertifikate, absichtlich manipulierte Datei abgelehnt.
- Reale Integration: Zabbix Server und Agent 2 **7.0.32** sowie PostgreSQL 16
  aus offiziellen, per Digest fixierten Images. Frische `agent.ping`- und
  `system.uptime`-Werte über aktive Zertifikatsverbindungen in der DB; erneut
  frische Werte nach Neustart. Unvertrauenswürdiger Client-Aussteller abgelehnt.
- Die unveränderte erzeugte Produktionskonfiguration wird mit dem echten
  `zabbix_agent2 -T` geprüft. Nur der Container-Lauf ersetzt LogType=system
  durch LogType=console, weil dort kein systemd-Journal läuft.
- Vollständiger nativer Ubuntu-24.04-amd64-Test mit systemd: CSR/Schlüssel auf
  dem Ziel, ausschließlich öffentlicher CSR zur Test-CA übertragen, Zertifikat
  zurückgegeben, offizielles signiertes APT-Paket installiert, `auto`,
  `validate`, unveränderte Wiederholung und neue Messwerte nach Dienstneustart.
  Dieser Test wurde am 26.10.2026 erfolgreich abgeschlossen. Er verwendet
  testweise lokale CA-Signierung, keine produktive Windows-CA.

Der konkrete Abschlussstand steht in [TEST-REPORT.md](TEST-REPORT.md).

## Offene Abnahme außerhalb dieses Labors

Keine produktive Windows-AD-CS-Anfrage, kein Zugriff auf den privaten Schlüssel
oder die CA eurer Organisation, keine Hostanlage und keine Datenabnahme auf
`ux-zabbix01.unisg.ch`. Diese Voraussetzungen dürfen nicht erfunden werden.

Ein Container-Test ersetzt keinen Canary mit echtem Betriebssystem-Boot,
Firewall, DNS, NTP und Windows-PKI. Insbesondere ist der vollständige
APT-/systemd-Rollout wurde für Ubuntu 24.04 lokal ausgeführt. Ubuntu 22.04
und Debian 12 sind im Installer berücksichtigt, wurden hier aber nicht nativ
durchgetestet. Ihre Abnahme darf daraus nicht abgeleitet werden.

Die frühere Chat-Version erwähnte 74 Tests. Diese Zahl wird hier **nicht**
übernommen: nur die von dieser Implementierung wirklich ausgeführten Tests
zählen. Ebenso ist ein laufender Prozess oder TLS-Handshake kein Beweis für
erfolgreiche Produktionsüberwachung.
