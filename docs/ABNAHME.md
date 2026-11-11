# Canary-Abnahme

Datum / Verantwortliche / Change-ID: __________________________

| Prüfung | Soll | Ergebnis / Beleg |
|---|---|---|
| Release | SHA-256 intern abgeglichen, Manifest erfolgreich | |
| Zielplattform | Unterstützte Distribution, amd64, systemd | |
| CA | Herkunft freigegeben, SHA-256 separat abgeglichen | |
| Identität | FQDN = CSR-CN = Zertifikats-CN = technischer Hostname | |
| Private Key | Lokal, root:zabbix 0640, kein Export | |
| Zertifikat | Kette gültig, beide EKUs, Restlaufzeit ≥30 Tage | |
| Serveridentität | Genehmigter Zertifikatsname und DN, mTLS erfolgreich | |
| Agentversion | Freigegebener stabiler 7.0.x-Stand aus signierter Quelle | |
| Hostanlage | Manuell, richtige Gruppe, Server/Proxy, Enabled | |
| Template | Linux by Zabbix agent active / freigegebene aktive Items | |
| Encryption | Connections from host ausschließlich Certificate, exakte Agent-DNs | |
| Active-only | Kein Server=/Metadata/PSK/Include, kein TCP-10050-Listener | |
| Lokale Prüfung | `validate` erfolgreich | |
| Echte Daten | Neue Zeitstempel, agent.ping=1 und system.uptime>0 im Frontend | |
| Betriebsmetriken | CPU, RAM, Dateisystemwerte plausibel, keine unerklärten unsupported Items | |
| Neustart | Nach Dienst-/Hostneustart neue Messwerte und enabled-Dienst | |
| Wiederholung | Zweites auto installiert/ändert nichts | |
| Erneuerung | Ablaufüberwachung und Verantwortlichkeit festgelegt | |
| Rollback | Vorzustand/Sicherung und Vorgehen geprüft | |

Ziel für den ersten Canary: **100 % der Pflichtprüfungen bestanden**, frische
Messwerte innerhalb von **5 Minuten nach Freigabe/Agentstart** bei regulären
Templateintervallen. Das ist ein Abnahmeziel, kein zugesichertes Produktions-SLA.
Erst danach schrittweise auf weitere Hosts erweitern.

Ohne Produktions-CA, ausgestelltes Agent-Zertifikat, manuell angelegten Host und
bestätigte Latest-data-Werte ist die produktive Definition of Done offen.
