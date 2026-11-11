# Regeneration vom 11.11.2026

Das Paket `agentzab-linux-mtls-3.0.0.zip` wurde aus dem vorhandenen Repository
neu erzeugt. Der Funktionsstand des Installers bleibt 3.0.0; dies ist keine
Fehlerkorrektur oder neue Produktionsfreigabe.

Installer `agentzab/rollout.py`, unveränderter SHA-256:

```text
340401bc9799016d00ade375ba562dafdf1e80a9baf7d1cc36a46c0b06cedc59
```

Dokumentation und Paketierung wurden für die Ablage im GitHub-Repository ergänzt:
Markdown-README mit Dateilinks, Hinweis auf den späteren Review sowie diese Notiz.
Die zwei Auslieferungsdateien im `dist`-Verzeichnis werden zusammen mit den
Quellen und Tests versioniert. Laufzeitdaten, Schlüssel und Zertifikate bleiben
ausgeschlossen. CI/CD läuft weiterhin lokal; es wird kein GitHub-Actions-Workflow
eingerichtet und kein produktiver Agent ausgerollt.

Die zusätzliche Dokumentation und geänderte Paketierung führen zu einem neuen
ZIP-Hash. Maßgeblich ist die zusammen ausgelieferte `.zip.sha256`-Datei.
Der im historischen Review genannte ZIP-Hash bezeichnet das frühere Archiv.

## Prüfungen dieser Regeneration

Die abschließenden Befehle sind:

```sh
./scripts/local-ci.sh
git diff --check
cd dist
sha256sum -c agentzab-linux-mtls-3.0.0.zip.sha256
```

`local-ci.sh` führt die 37 vorhandenen Regression-/PKI-/TLS-Tests und den
Release-Build mit unabhängiger Reproduktion aus. Die Release-Prüfung kontrolliert
das entpackte Manifest, ausführbare Skriptmodi, den Ausschluss von Zertifikaten
und Schlüsseln sowie die Ablehnung einer manipulierten Paketdatei.

Ergebnis am 11.11.2026: **37 Tests bestanden**, keine übersprungenen Tests
(34,738 Sekunden). Zwei unabhängige ZIP-Builds waren byteidentisch; die 22
manifestierten Paketdateien, Skriptmodi und Manipulationsablehnung wurden
erfolgreich geprüft. Die ZIP-Integritätsprüfung meldet ebenfalls PASS.

Der echte APT-/systemd-/Zabbix-Datentest wurde bei dieser Regeneration nicht erneut
ausgeführt. Seine historischen Ergebnisse vom 26.10.2026 bleiben im
[Testbericht](TEST-REPORT.md) erhalten.

## Offene Befunde bleiben bestehen

Insbesondere sind CSR-Organisationsfelder, getrennte CA-Rollen, die zusätzliche
DN-Wechselsperre bei explizitem `install`, die frühe Erkennung des klassischen
Agenten und die Unterdrückung umgebungsabhängigen TLS-Keyloggings nicht
nachgerüstet. Einzelheiten und weitere Unterschiede beschreibt der
[Reviewbericht](REVIEW-V2.2.0-VS-3.0.0.md). Vor einer Produktionsfreigabe sind diese
Punkte abzugleichen und mit der tatsächlichen Windows-PKI zu prüfen.
