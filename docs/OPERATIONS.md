# Betrieb und Fehlerbehebung

## Befehle

| Befehl | Wirkung |
|---|---|
| `verify-package` | Release-Dateihashes prüfen; ohne root nutzbar |
| `preflight` | OS, Architektur, systemd, Werkzeuge, Eigentum, Fremdinstallation prüfen |
| `prepare-csr` | Identität, lokalen Schlüssel und CSR einmalig anlegen; wiederverwendbar |
| `check-certs` | Rückgabe prüfen und Hostwerte ausgeben; keine Paket-/Dienständerung |
| `auto` | CSR-Phase oder Installation; nach Installation nur Validierung |
| `install` | Bewusstes Update/Zertifikatsübernahme mit erneuter Hostbestätigung |
| `validate` | Installierten Zustand und mTLS prüfen; keine Paket-/Dienständerung |

Exit-Codes: `0` lokale Aktion erfolgreich, `10` erwartetes Warten auf PKI,
`1` Fehler. `0` bedeutet bei keiner lokalen Aktion automatisch „Produktionsdaten
im Zabbix-Frontend nachgewiesen“.

## Paketquellen

Der Installer verwendet freigegebene konfigurierte APT-Quellen. Falls noch kein
stabiles 7.0.x-Paket bekannt ist, fügt er das offizielle, distributionsspezifische
7.0-Repository unter `/etc/apt/sources.list.d/agentzab.sources` hinzu. Bereits
abweichende Dateien mit diesem Namen werden nicht überschrieben.

Bootstrap über verifiziertes HTTPS von `repo.zabbix.com`; aus dem offiziellen
Key-Bundle wird ausschließlich dieser Schlüssel exportiert:

```text
Zabbix LLC (Apr 2024)
4C3D 6F2C C75F 5146 754F C374 D913 219A B533 3005
```

Er liegt danach in `/usr/share/keyrings/agentzab-zabbix.gpg`; die APT-Quelle bindet
ihn mit `Signed-By`. Ein Schlüsselwechsel wird nicht automatisch akzeptiert.
APT prüft signierte Metadaten und Paket-Hashes. Weder `curl -k`,
`--allow-unauthenticated` noch ein ausgeschalteter Signaturcheck werden verwendet.
Die offizielle Quelle wurde am 26.10.2026 auf diesen Fingerprint geprüft.
Die Auswahl erfolgt mit `dpkg --compare-versions`, inklusive Epoch und
Paketrevision, ausschließlich stabile 7.0.x. Kein automatisches Downgrade.

Falls interne Mirrors vorgeschrieben sind, vorab deren signierte Quelle
einrichten und sicherstellen, dass ein stabiles 7.0.x-Paket in `apt-cache madison
zabbix-agent2` sichtbar ist. Es werden keine internen Mirror-Adressen erfunden.
Normale APT-Upgrades außerhalb des Installers bleiben Sache der bestehenden
Patch-Policy; das Paket installiert keinen unattended-upgrade-Dienst.

## Schutz bestehender Systeme

Vorhandene Agent-2-Installationen oder Hauptkonfigurationen ohne eigenen
Verwaltungsmarker werden vor Paket- oder Dienständerungen abgelehnt. Nicht auf
dem bereits funktionierenden Datenbank-Agenten als Erst-Canary ausführen.
Kein automatischer Import fremder Schlüssel; kein stiller Wechsel des FQDN.
Weicht der aktuelle Hostname von der gespeicherten CSR-Identität ab, wird gestoppt.

Während `apt install` verhindert eine temporäre `policy-rc.d` den vorzeitigen
Dienststart. Eine bereits existierende `policy-rc.d` wird nicht überschrieben;
der Admin muss die Zielumgebung und ihren Startschutz prüfen. Die temporäre
Datei wird nach normalen Fehlern entfernt. Nach SIGKILL/Stromausfall kann sie
übrig bleiben: Inhalt/Eigentum prüfen und nur die eindeutig vom fehlgeschlagenen
Rollout erzeugte Datei entfernen, dann erneut starten.

Konfiguration hat keine `Include`-Direktive, `Server=`, `HostMetadata`, PSK oder
Status-HTTP-Port. Vorhandene Snippets werden weder ausgeführt noch gelöscht.
Remote-Befehle `system.run[*]` sind ausdrücklich verweigert.

Nach der Installation gehören `/etc/zabbix` und dessen `certs`-Verzeichnis
`root:zabbix` mit Modus `0750`; die verwalteten Konfigurations-/Zertifikatsdateien
und der Schlüssel haben `0640`. Die Agent-Konfiguration wird ausdrücklich mit
`runuser -u zabbix -- zabbix_agent2 -T ...` als tatsächlicher Dienstbenutzer
geprüft. In der vorgelagerten CSR-Phase sind die neu erzeugten Verzeichnisse
noch rootgeschützt; der Schlüssel hat `0600`.

## Erneuerung und Rollback

30 Tage vor Ablauf meldet die Validierung Handlungsbedarf. Wiederholtes `auto`
erneuert nicht selbstständig und aktualisiert keine Pakete. Erneuerung mit
dem bestehenden Schlüssel/CSR bei der PKI beauftragen, genau eine neue Antwort
in die Inbox legen, `check-certs`, Host-DNs bei Änderung manuell aktualisieren,
dann `install --confirm-host <FQDN>`. Keine automatische Schlüsselrotation;
diese benötigt einen separat geplanten Identitätswechsel.

Vor Installation liegen verwaltete Konfiguration und öffentliche Zertifikate
rootgeschützt unter `/var/lib/zabbix-agent2-rollout/backups/<UTC-Zeitstempel>`.
Der vorhandene private Schlüssel wird nicht überschrieben oder in ein Release
kopiert. Auf abgefangene Installationsfehler wird die vorige Konfiguration und
der erfasste Dienstzustand soweit möglich zurückgesetzt. Ein frisch installiertes
Paket kann verbleiben; PKI-Aktionen, APT-Quellen und Paketversionen werden nicht
zurückgerollt. Kein transaktionaler Schutz gegen SIGKILL/Stromausfall.
Host-Backups müssen den Private Key und Verwaltungszustand verschlüsselt enthalten;
keine unverschlüsselte Weitergabe des Zustandsverzeichnisses.

## Diagnose

```sh
systemctl status zabbix-agent2 --no-pager
journalctl -u zabbix-agent2 --since '-10 minutes' --no-pager
ss -ltn 'sport = :10050'
./install.sh check-certs
./install.sh validate
```

`validate` prüft Konfigurationsdrift, Dateirechte, echte Agent-Konfigurationsprüfung,
systemd, fehlenden Listener, Zertifikate und mTLS. Verbindungsfehler seit dem
aktuellen Dienststart werden konservativ gemeldet; nach Behebung und bewusstem
Dienstneustart erneut validieren. Das Skript wartet nicht automatisch auf eine
erfolgreiche PKI-/Netzwerkfreigabe.

Typische Ursachen: FQDN passt nicht exakt zum Host, Host deaktiviert, falsches
Template/Server/Proxy, Certificate nicht exklusiv erlaubt, falscher Issuer/Subject,
fehlende Intermediate-CA, Zertifikat für einen anderen Servernamen oder gesperrtes
ausgehendes TCP 10051. Keine dieser Ursachen durch Ausschalten von TLS lösen.

## Lokale CI/CD

```sh
./scripts/local-ci.sh                 # PKI/Workflow/TLS + reproduzierbares ZIP
./scripts/local-ci.sh --integration   # zusätzlich echter Zabbix-Datenpfad in Docker
./scripts/local-ci.sh --full          # zusätzlich vollständiger nativer Ubuntu-/systemd-Test
```

Die Integration startet isolierte, kurzlebige Container ohne veröffentlichte Ports
und entfernt nur ihre eigenen Container/Netze/Volumes. Keine produktive API oder
SQL-Verbindung. Die Lab-Hostkonfiguration ist eine SQL-Testfixture; im ausgelieferten
Produktionsablauf bleibt die Hostanlage manuell. Testschlüssel werden pro Lauf
erzeugt, sind nicht produktiv vertrauenswürdig und gelangen nicht ins Release.
Docker-Images sind per Digest fixiert. `tests/platforms.py` prüft zusätzlich
APT/systemd in lokalen Wegwerf-Containern, sofern der Docker-Host systemd darin
unterstützt. Dafür verwendet ausschließlich der Wegwerf-Testcontainer
`--privileged`; Produktionsagenten benötigen keine Containerprivilegien.
Docker-Zugriff ist nur auf der Entwicklungsmaschine nötig;
die produktiven Linux-Agenten benötigen Docker nicht.
