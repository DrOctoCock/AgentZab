# Inbetriebnahme auf einem neuen Linux-Host

> Stand 11.11.2026: Dies ist der unveränderte Funktionsstand 3.0.0 mit bekannten
> offenen Befunden. Vor einem produktiven Canary den
> [Review zu v2.2.0](docs/REVIEW-V2.2.0-VS-3.0.0.md) und die
> [Regenerationsnotiz](docs/REGENERATION-2026-11-11.md) lesen.

## Einmal durch das Monitoring-Team

1. `config/site.json` prüfen. Vorbelegt sind `ux-zabbix01.unisg.ch:10051`,
   derselbe erwartete Server-Zertifikatsname und 30 Tage Mindestrestlaufzeit.
   Geprüft wird das Zertifikat des Monitoring-Dienstes auf **10051**, nicht das
   Webfrontend auf 443. Hat es einen anderen genehmigten Namen, diesen zentral
   als `server_certificate_name` eintragen und ein neues Release bauen.
2. Lokal `./scripts/local-ci.sh --integration` ausführen. Release und SHA-256
   intern über einen vertrauenswürdigen Kanal bereitstellen. SHA-256 schützt
   Integrität, ersetzt aber keine Signatur/Authentisierung des Verteilkanals.
3. Öffentliche, freigegebene CA-Datei für beide Vertrauensrichtungen bestimmen:
   Agent vertraut dem Server, Server vertraut der Windows-PKI des Agenten.
   Im aktuellen Standortprofil wird dasselbe CA-Bundle verwendet. Bei getrennten
   PKIs nicht improvisieren: ein gemeinsames freigegebenes Bundle vorbereiten
   und die zusätzliche Vertrauensausweitung prüfen. Keine neue Root-CA automatisch
   aus dem Netzwerk übernehmen.
4. Server/Proxy muss Zertifikatsverbindungen bereits unterstützen und der
   Agent-CA vertrauen. Das Paket verändert dessen Truststore nicht.

## Je Zielhost: zwei Aufrufe, eine externe PKI-Freigabe

Unterstützter Zielumfang: Ubuntu 22.04/24.04 oder Debian 12, **amd64 mit laufendem
systemd**, root und ausgehend DNS/TCP 10051 zum Zabbix-Endpunkt. APT benötigt die
freigegebenen Betriebssystemquellen und ggf. HTTPS zu `repo.zabbix.com`.

Zuerst die Betriebssystem-Werkzeuge aus signierten Quellen bereitstellen:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends python3 openssl ca-certificates curl gnupg iproute2
```

Release-Prüfsumme vor der Übertragung und vor Ausführung abgleichen:

```sh
sha256sum -c agentzab-linux-mtls-3.0.0.zip.sha256
unzip agentzab-linux-mtls-3.0.0.zip
# Eine neue root-kontrollierte Arbeitskopie verwenden, keine fremden Dateien überschreiben.
sudo install -d -m 0700 /root/agentzab-release
sudo cp -a agentzab-linux-mtls-3.0.0 /root/agentzab-release/
sudo chown -R root:root /root/agentzab-release/agentzab-linux-mtls-3.0.0
sudo -i
cd /root/agentzab-release/agentzab-linux-mtls-3.0.0
./install.sh verify-package
```

Öffentliches CA-Material über den genehmigten internen Kanal ergänzen:

```sh
install -o root -g root -m 0644 /freigegebener/pfad/zabbix_ca.pem common/zabbix_ca.pem
# Nur falls Intermediate-CAs benötigt werden:
# install -o root -g root -m 0644 /freigegebener/pfad/issuing.pem common/agent-issuing-chain.pem
```

Die angehängten CA-Dateien sind nicht vom ursprünglichen ZIP-Manifest abgedeckt.
Deren SHA-256 separat mit der internen Freigabe vergleichen. Ist auf dem Zielhost
bereits `/etc/zabbix/certs/zabbix_ca.pem` vertrauenswürdig vorhanden, verwendet
der Installer diese Datei, wenn `common/zabbix_ca.pem` fehlt.

### 1. Lokalen Schlüssel und CSR vorbereiten

```sh
./install.sh auto
```

`WAITING_FOR_PKI` und Exit-Code **10** bedeuten hier einen erwarteten Zwischenstand,
keinen erfolgreichen vollständigen Rollout. Es wurde kein Agent installiert oder
gestartet. Die Ausgabe nennt den tatsächlichen CSR-Pfad:

```text
/var/lib/zabbix-agent2-rollout/outbox/<FQDN>.csr
```

Nur CSR und Request-Metadaten an die Windows-PKI übergeben.
**Der private Schlüssel `/etc/zabbix/certs/zabbix-agent2.key` bleibt auf diesem Host.**
Details für die PKI: [docs/WINDOWS-PKI.md](docs/WINDOWS-PKI.md).

### 2. Zertifikat zurückgeben und Host manuell anlegen

```sh
install -o root -g root -m 0600 /pfad/agent.cer \
  /var/lib/zabbix-agent2-rollout/inbox/agent.cer
./install.sh check-certs
```

Genau eine der Dateien `agent.cer`, `agent.crt`, `agent.pem` ablegen.
PEM und DER werden erkannt; PFX/PKCS#7 werden abgelehnt. Bei Erneuerung alte
Rückgabedateien zuerst gesichert aus der Inbox entfernen.

Das Monitoring-Team übernimmt die ausgegebenen Werte aus
`/var/lib/zabbix-agent2-rollout/reports/zabbix-host-manual-values.txt`:

- **Data collection → Hosts → Create host**: exakter technischer Hostname,
  korrekter Zabbix Server/Proxy und zuständige Hostgruppen.
- Template **Linux by Zabbix agent active**, Status **Enabled**.
- **Encryption → Connections from host: nur Certificate**; Issuer und Subject
  exakt aus dem Bericht übernehmen. Kein PSK und kein unverschlüsselter Fallback.
- Für ausschließlich aktive Agent-Items wird kein Agent-Interface benötigt.

### 3. Installation mit demselben Aufruf fortsetzen

```sh
./install.sh auto
```

Die interaktive Bestätigung verlangt den exakten technischen Hostnamen.
Für kontrollierte nichtinteraktive Ausführung:

```sh
./install.sh auto --confirm-host '<exakter-FQDN-aus-dem-Bericht>'
```

Das ist die Bestätigung des Administrators, **keine** serverseitige Hostprüfung.
Nun werden Zertifikate und Serveridentität geprüft, das signierte 7.0.x-Paket
installiert, Konfiguration und Dateirechte gesetzt und systemd gestartet.

### 4. Ende-zu-Ende abnehmen

```sh
./install.sh validate
```

Zusätzlich im Frontend unter **Monitoring → Latest data** den richtigen Host
auswählen und **neu eingetroffene** Werte von `agent.ping`, `system.uptime`
und den freigegebenen Linux-Items prüfen. Lokal laufender Dienst und erfolgreicher
TLS-Handshake beweisen keine Datenannahme. Die Abnahme ist erst mit dieser Prüfung
und [docs/ABNAHME.md](docs/ABNAHME.md) vollständig.
