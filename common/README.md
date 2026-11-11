# Vertrauensmaterial einmal zentral ergänzen

`zabbix_ca.pem`: freigegebene öffentliche CA(s), einschließlich Root-CA.
Optional `agent-issuing-chain.pem`: Intermediate-CAs für das Agent-Zertifikat.
Alternativ wird die bestehende, root-kontrollierte Datei
`/etc/zabbix/certs/zabbix_ca.pem` verwendet, wenn die Paket-CA fehlt.

Nur öffentliche Zertifikate verteilen. Kein Private Key gehört in diesen Ordner.
CA-Dateien müssen über einen authentisierten internen Kanal freigegeben werden;
ein Dateipfad im Chat stellt keine CA bereit. Root-Eigentum und keine Schreibrechte
für Gruppe/Andere. Der Release-Build schließt alle Zertifikate und Schlüssel aus.
Die später ergänzte CA ist deshalb nicht vom ursprünglichen Release-Manifest
abgedeckt: deren SHA-256 getrennt über den internen Freigabekanal abgleichen.
