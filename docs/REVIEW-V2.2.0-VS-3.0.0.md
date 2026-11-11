# Direkter Paketvergleich – 26.10.2026

**Ergebnis:** AgentZab 3.0.0 ist eine lokal integrierte und getestete
Neuimplementierung, aber kein funktionsgleicher Nachfolger des jetzt vorliegenden
v2.2.0-Pakets. Das Original enthält wichtige PKI- und Schutzfunktionen, die in
3.0.0 fehlen. Vor der produktiven Abnahme sollten diese Unterschiede abgeglichen
werden. Dieser Review verändert weder den Installer noch das bereitgestellte ZIP.

## Geprüfte Artefakte und Vorgehen

- Original-ZIP: `zabbix-agent2-linux-mtls-manual-local-2026-09-11-v2.2.0.zip`.
  SHA-256 stimmt mit der separat übergebenen Prüfsumme überein:
  `2c15449932f098ded05f88484614dcdd633d9345402f84921837a86f86a54d70`.
- 40 ZIP-Einträge, keine absoluten Pfade, Pfadtraversierung oder Symlinks bei
  der kontrollierten Extraktion. Internes `MANIFEST.sha256` vollständig gültig.
- Die separat übergebene `WINDOWS-PKI-HANDOVER.md` ist bytegleich mit der
  entsprechenden Datei im Original-ZIP.
- AgentZab-3.0.0-ZIP bleibt unverändert bei SHA-256
  `e0586193e1ecdafab802aaca8bc83fddaf9c0fdc5d626710735c530acd047c97`.
- Quellcodevergleich und gezielte lokale Nachweise mit generierter Test-PKI.
  Dokumentanweisungen wurden als Prüfgegenstand behandelt; kein produktiver
  Rollout und kein Zugriff auf Unternehmenszertifikate oder den Zabbix-Server.

## Wesentliche Unterschiede

### 1. CSR enthält in 3.0.0 nicht mehr die vereinbarten Organisationsfelder

Das Original erzeugt `C=CH`, `O=University of St.Gallen`, `OU=Zabbix` und den
Host-CN. Diese Belegung steht auch in der beigefügten PKI-Übergabe. 3.0.0 erzeugt
und akzeptiert für seinen gespeicherten CSR ausschließlich `CN=<FQDN>`.

**Nachweis:** Original `scripts/zabbix-agent2-rollout.sh:366` und
`docs/WINDOWS-PKI-HANDOVER.md:26`; Neufassung `agentzab/rollout.py:395`.
Ein tatsächlich erzeugter neuer CSR meldet `subject=CN=host.example.test`.

**Auswirkung:** Die Gleichwertigkeit gegenüber der Windows-PKI-Vorlage ist nicht
gegeben. Falls diese Organisationsfelder voraussetzt, muss die Anfrage angepasst
werden. Eine konkrete Ablehnung durch eure AD CS wurde nicht getestet.

**Empfehlung:** Zentrales CSR-Profil mit den bisherigen Vorgaben übernehmen und
mit der tatsächlich freigegebenen AD-CS-Vorlage abnehmen.

### 2. Getrennte Agent-/Server-Vertrauensketten fehlen in 3.0.0

v2.2.0 unterstützt sowohl ein gemeinsames freigegebenes CA-Bundle als auch
separate `agent-trust-ca.pem` und `server-trust-ca.pem`, jeweils in Inbox oder
zentralem Common-Verzeichnis. Die Rollen bleiben getrennt. 3.0.0 kennt nur einen
`ca_file` und verwendet ihn für beide Richtungen.

**Nachweis:** Original `scripts/lib/auto-pki.py:119`; Neufassung
`agentzab/rollout.py:407`. Ein lokaler Versuch mit separater Agent- und Server-CA
wird vom Original vorbereitet; 3.0.0 meldet eine fehlende gemeinsame CA-Datei.

**Auswirkung:** Ein bisher gültiger Zwei-PKI-Aufbau wird nicht direkt unterstützt.
Ein Zusammenlegen beider CAs wäre eine bewusste Erweiterung des jeweiligen
Vertrauensumfangs und kein gleichwertiger Ersatz.

**Empfehlung:** Beide Rollen wieder getrennt modellieren; gemeinsames Bundle nur
als ausdrücklich gewählte Belegung beider Rollen unterstützen.

### 3. Explizites install kann gespeicherte Server-DNs in 3.0.0 ersetzen

Das Original speichert nach authentisierter Ermittlung den Server-Issuer und
-Subject und lehnt später andere DNs auch beim erneuten Installationslauf ab.
3.0.0 erkennt Änderungen bei `validate` und damit bei wiederholtem `auto`.
Beim expliziten `install` übernimmt es jedoch den frisch ermittelten Gegenpart
in Konfiguration und Marker, ohne ihn vorher gegen den gespeicherten DN zu
vergleichen oder den DN-Wechsel gesondert bestätigen zu lassen.

**Nachweis:** Original `scripts/lib/auto-pki.py:205`; Neufassung
`agentzab/rollout.py:508` und `:559`. Mit zwei gültigen Test-Serverzertifikaten
derselben CA und demselben geprüften Endpoint-Namen, aber unterschiedlichen
Subjects, lehnt das Original die zweite Identität ab. Der neue TLS-Prüfer
akzeptiert sie. Ein separater Kontrollfluss-Test erreicht danach die APT-Phase;
APT und systemd wurden dabei durch Test-Doubles ersetzt und nicht ausgeführt.

**Einordnung:** CA- und Namensprüfung bleiben aktiv. Es handelt sich nicht um
die Annahme beliebiger selbstsignierter Zertifikate. Verloren geht die zusätzliche
Bestätigung eines geänderten, zuvor gespeicherten DNs beim expliziten Update.

**Empfehlung:** Normalen Updatepfad und gesondert freigegebene DN-Migration trennen.

### 4. Klassischer Zabbix-Agent wird von der neuen Eingangssperre nicht erkannt

v2.2.0 prüft ausdrücklich `zabbix-agent` und `zabbix-agent2` vor Paket- und
Dienständerungen. `foreign_guard()` in 3.0.0 fragt nur Agent 2 ab und prüft seine
Hauptkonfiguration. Ein ausschließlich klassischer Agent erfüllt diese Sperre
nicht; eine Portkollision auf 10050 würde erst später bei der Validierung auffallen.

**Nachweis:** Original `scripts/zabbix-agent2-rollout.sh:634`; Neufassung
`agentzab/rollout.py:314`. Ein kontrollierter Paketstatus-Test mit ausschließlich
installiertem `zabbix-agent` passiert die neue Sperre. Keine realen Pakete wurden
dabei geändert. Der geprüfte offizielle Agent-2-DEB enthält kein `Conflicts`-Feld;
eine automatische Entfernung des klassischen Agenten wird hier nicht behauptet.

**Empfehlung:** Klassischen Agenten früh erkennen und eine geplante Migration
verlangen, statt erst nach Änderungen eine Koexistenzstörung zu melden.

### 5. TLS-Prüfverbindungen können in 3.0.0 Umgebungs-Keylogging aktivieren

Der Original-Helfer verwendet einen ausdrücklich aufgebauten `SSLContext` und
ignoriert `SSLKEYLOGFILE`. Die Neufassung benutzt `ssl.create_default_context`,
das die Variable in der geprüften Python-Laufzeit auswertet.

**Nachweis:** Original `scripts/lib/auto-pki.py:188`; Neufassung
`agentzab/rollout.py:447`. Mit gesetzter Variable und lokaler Test-PKI erzeugt
3.0.0 eine 992 Byte große TLS-Schlüsselprotokolldatei; das Original erzeugt keine.
Die Schlüsselwerte wurden nicht ausgegeben und die Testdateien anschließend entfernt.

**Einordnung:** Voraussetzung ist eine entsprechende Umgebungsvariable. Geprüft
wurde die Python-TLS-Prüfverbindung, nicht eine Schlüsselprotokollierung des
laufenden Zabbix-Agenten. Kein Remote-Angriff oder genereller Klartextbetrieb
wurde nachgewiesen.

**Empfehlung:** Für die Probe einen expliziten Kontext ohne umgebungsabhängiges
Keylogging verwenden und diesen Vertrag testen.

### 6. Weitere Funktionen sind reduziert oder entfallen

| Funktion | v2.2.0 | AgentZab 3.0.0 |
|---|---|---|
| PEM-Rückgabe mit Leaf plus CA-Zertifikaten | Leaf auswählen, Kette normalisieren | Mehr als ein PEM-Zertifikat abgelehnt |
| Exakte genehmigte Agent-Paketversion | Zentral konfigurierbar | Stets höchster verfügbarer stabiler 7.0.x-Stand |
| Interner Bootstrap-Mirror | URL plus zwingender SHA-256 konfigurierbar | Vorhandene APT-Quelle möglich, kein gleichwertiger Bootstrap-Override |
| Vorhandene policy-rc.d | Akzeptiert, wenn sie Start mit 101 verweigert | Jede vorhandene Datei wird abgelehnt |
| Status/Workflow anzeigen | Eigene CLI-Befehle | Nicht implementiert |
| Bewusster manueller Rollback | Eigener Befehl, begrenzte Rücknahme zum Vor-Rollout-Zustand | Automatische Rücknahme bei abgefangenen Fehlern, kein gleichwertiger manueller Befehl |
| Hostbestätigung bei unveränderten Identitäten | An Host, Endpoint und Agent-DNs gebunden gespeichert | Bei jedem expliziten Installationslauf erneut erforderlich |
| Bestehende Server-DNs zentral vorgeben | Unterstützt, auch für genehmigte nicht-DNS-Subjects | Kein gleichwertiger DN-Override; DNS-/Namensprüfung erforderlich |
| Bestehende Include-Konfiguration | Einlesen und rekursiv auf Konflikte prüfen | Hauptkonfiguration ohne Includes neu erzeugen |

Die PEM-Rückgabe wurde mit einer lokalen Testdatei reproduziert. Die übrigen
Zeilen sind durch die jeweiligen Konfigurationen und implementierten CLI-Pfade
belegt. Sie sind nicht sämtlich Sicherheitsmängel; mehrere betreffen Bedienung,
Kompatibilität und die ursprünglich vorgesehene Verringerung manueller Arbeit.
Ein automatischer Upgradepfad von einer bestehenden 2.2.0-Installation ist nicht
implementiert; deren Agent-2-Installation wird als fremdverwaltet abgewiesen.

## Originalpaket: positive Ergebnisse und Grenzen

Die Originalprüfungen wurden in einem isolierten Ubuntu-24.04-Container mit
schreibgeschütztem Dateisystem, temporärem Testverzeichnis und ohne externe
Netzverbindung ausgeführt:

- Statische Verträge, Zertifikats-Shellsuite und Konfigurations-Shellsuite: PASS.
- 33 Rollout-Regressionstests: PASS.
- 27 automatische PKI-/Loopback-TLS-Tests: PASS.
- 14 Workflowtests: PASS.

Damit sind die **74 im Original einzeln gezählten Python-Tests reproduziert**,
zusätzlich zu den genannten separaten Suiten. Zunächst scheiterten Tests an
Eigentümer-/umask-Unterschieden auf der Cloud-Maschine und an einem nicht
ausführbaren Container-/tmp. Unter passenden isolierten Testbedingungen mit
root-eigenen Systemdateien, umask 022 und einem ausführbaren Test-/tmp bestanden
sie. Dafür wurden weder Assertions noch die Originalquellen verändert.

Die drei SHA-256-Werte für offizielle Repository-Bootstrap-DEBs wurden jetzt
überprüft: Ubuntu 22.04, Ubuntu 24.04 und Debian 12 stimmen sämtlich mit den
offiziellen HTTPS-Downloads überein. Die frühere NOT-VERIFIED-Angabe war damit
eine damalige Zugriffsgrenze, kein bestätigter falscher Hash.

Die PKI-Handover-Datei enthält einen Dokumentationsrest: Der v2.2.0-Hinweis am
Anfang beschreibt automatische PEM-/DER-Verarbeitung, der spätere Abschnitt
fordert noch manuelle DER-Konvertierung. Die implementierte Normalisierung
akzeptiert DER. Die Weitergabeanleitung sollte dies einheitlich beschreiben.

Für v2.2.0 wurde in diesem Review kein realer APT-/systemd-Rollout ausgeführt.
Für 3.0.0 bleibt der zuvor bestandene native Ubuntu-24.04-/Zabbix-mTLS-Datentest
gültig. Die Testzahlen beider Pakete messen unterschiedliche Umfänge und belegen
keine Funktionsgleichheit. Eine echte Windows-PKI-/Produktionsabnahme fehlt bei
beiden Fassungen.

## Empfehlung

Den ursprünglichen Funktionsvertrag als Referenz übernehmen und die bestätigten
Regressionen in einer abgeglichenen Folgeversion beheben. Die neuen realen
APT-/systemd-/Datenpfadtests beibehalten und um getrennte PKIs, bestehende Agenten,
DN-Migration und die tatsächliche CSR-Vorlage ergänzen. 3.0.0 bis dahin nicht als
funktionsgleichen produktiven Ersatz für v2.2.0 freigeben.
