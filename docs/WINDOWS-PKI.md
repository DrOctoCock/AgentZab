# Übergabe an Windows-PKI

Der CSR entsteht auf dem Zielhost: RSA 4096, SHA-256, CN exakt der gespeicherte
Zabbix-FQDN. Der Schlüssel ist unverschlüsselt für den Dienstbetrieb, wird aber
durch root-Eigentum und `0600`, später `root:zabbix 0640`, geschützt.
Kein Export des privaten Schlüssels, kein CA-Schlüssel im Paket.

Die PKI-Vorlage muss die folgenden Merkmale **im ausgestellten Zertifikat** setzen;
CSR-Wünsche allein garantieren das nicht:

| Eigenschaft | Paketpolicy |
|---|---|
| Subject CN | Exakt technischer Zabbix-Hostname, einschließlich Groß-/Kleinschreibung |
| Basic Constraints | CA:FALSE |
| Key Usage | Digital Signature |
| Extended Key Usage | clientAuth **und** serverAuth |
| Signatur | SHA-256 oder stärker, kein MD5/SHA-1 |
| Restlaufzeit | Mindestens 30 Tage |
| SAN | Agent-SAN in dieser konservativen Standortpolicy nicht zugelassen |
| Schlüssel | Öffentlicher Schlüssel aus dem eingereichten CSR |

Die offizielle Zabbix-Dokumentation weist auf TLS-Toolkit-Unterschiede bei
X.509-Erweiterungen hin. Beide EKUs und kein Agent-SAN sind hier eine bewusste
Kompatibilitätspolicy, keine Behauptung, dass aktive TLS-Clients generell keinen
SAN verwenden dürften. Das Serverzertifikat wird unabhängig davon gegen den
erwarteten DNS-Namen geprüft; Python/OpenSSL akzeptiert passende DNS-SANs bzw.
bei fehlendem SAN einen passenden CN.

Beispiel mit tatsächlicher CA und genehmigter Vorlage ersetzen:

```powershell
certreq.exe -submit -config 'CAHOST\CA-NAME' `
  -attrib 'CertificateTemplate:ZabbixLinuxAgent' `
  .\host.example.ch.csr .\agent.cer

# Bei ausstehender Genehmigung:
certreq.exe -retrieve -config 'CAHOST\CA-NAME' <REQUEST-ID> .\agent.cer
```

PEM/Base-64-X.509 oder genau ein DER-X.509-Zertifikat zurückgeben. Eine
PKCS#7-Antwort kann die PKI vor Rückgabe in Leaf und öffentliche Intermediate-CAs
zerlegen; der Installer interpretiert solche Container nicht selbst.
Zwischenzertifikate zentral als `common/agent-issuing-chain.pem` bereitstellen.
Der Installer prüft beide Zwecke, Key-Match, CN, Laufzeit und Kette und erzeugt
eine Leaf-zuerst-Kette ohne Root-Zertifikat. Unvollständige oder mehrdeutige
Ketten werden abgelehnt; Cross-Signing muss zentral eindeutig vorbereitet werden.

Der produktive Server/Proxy muss der ausstellenden PKI bereits vertrauen.
CRL/OCSP und automatische AD-CS-Anmeldung sind nicht implementiert; CA-Sperrung,
Erneuerungsprozess und ggf. `TLSCRLFile` sind vor einem breiten Rollout als eigene
Betriebsanforderung zu klären. Es gibt keinen stillen Verzicht auf Kettenprüfung.

Quellen, abgerufen am 26.10.2026:

- https://www.zabbix.com/documentation/7.0/en/manual/encryption/using_certificates
- https://www.zabbix.com/documentation/7.0/en/manual/appendix/config/zabbix_agent2
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certreq_1
