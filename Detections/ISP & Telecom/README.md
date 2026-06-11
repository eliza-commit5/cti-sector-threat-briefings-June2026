[README.md](https://github.com/user-attachments/files/28850988/README.md)
# Salt Typhoon — Detection Pack

> **TLP:CLEAR.** Detections compiled from primary reporting. Validate every indicator and rule against your own telemetry before operational use.

Maintained by Eliza / elizacommit5

PRC state-sponsored espionage actor — the defining threat to the **ISP / telecom** vertical. Aliases span **OPERATOR PANDA, RedMike, Earth Estries, GhostEmperor, FamousSparrow,** and **UNC2286 / UNC5807**. Has compromised **600+ organizations across 80+ countries**, including major US carriers (AT&T, Verizon, Lumen, T-Mobile), with dwell times measured in years. Primary objective: intercept communications and access lawful-intercept / call-records infrastructure.

## Two detection layers

| Layer | Where it lives | Telemetry you need |
|---|---|---|
| **A — Network devices (the core)** | Cisco IOS XE, edge routers/VPNs | Device config-change logging, web-UI access logs, AAA/TACACS+/RADIUS logs shipped to SIEM |
| **B — Windows/Linux servers** | GhostSpider/Demodex/SnappyBee + Exchange exploitation | Standard EDR/Sysmon, Exchange/IIS logs, sign-in logs |

> Layer A is where Salt Typhoon mostly operates and where most organizations have the **least** visibility. Without network-device logging in your SIEM, the highest-value queries (A1–A3) are blind.

## Files

| File | Platform | What it covers |
|---|---|---|
| `salt_typhoon_splunk.spl` | Splunk SPL | IOS XE web-UI evasion, device config tampering, AAA anomalies, known C2, Exchange webshell, hash retro-hunt |
| `salt_typhoon_defender.kql` | Defender XDR / Sentinel | Web-UI evasion, C2/hashes, Exchange webshell, Demodex driver-load hunt, sign-in anomaly |
| `salt_typhoon_malware.yar` | YARA | Hash rule for the Windows/Linux malware families (honest scope note inside) |

## Key TTPs & artifacts

| Behavior | Tell | Layer |
|---|---|---|
| Initial access | **Stolen credentials** (most common per Talos); plus edge-device CVEs (Cisco IOS XE, Ivanti, Palo Alto, Fortinet) | A/B |
| Web-UI evasion | IOS XE paths percent-encoded: `%77eb%75i`, `%77sma`, double-encoded `%2577..` | A |
| Persistence/pivot | ACL edits to whitelist actor IPs; GRE/IPsec tunnels; Guest Shell enablement; priv-15 accounts | A |
| Credential theft | TACACS+/RADIUS capture on devices | A |
| Backdoors | **GhostSpider** (modular, TLS C2), **SnappyBee/Deed RAT**, **Masol RAT** (Linux) | B |
| Stealth | **Demodex** kernel rootkit | B |
| Exfil | GRE/IPsec tunnels; over C2 | A/B |

### Verified atomic indicators

| Type | Indicator | Notes |
|---|---|---|
| C2 IP | `141.255.164[.]98:2096` | GhostSpider C2 (active Aug 2024) |
| Cert SAN | `palloaltonetworks[.]com` | Typo-squat in GhostSpider C2 certificate |
| Hashes | **TO BE ADDED** | Trend Micro / Kaspersky / ESET appendices |

> Atomic IOCs churn and many Salt Typhoon C2 domains were registered via ProtonMail and rotate; treat the table above as retro-hunt and lead with behaviors.

## MITRE ATT&CK

- **Initial Access** — Valid Accounts (T1078); Exploit Public-Facing Application (T1190)
- **Persistence / Evasion** — Modify System Image / config (T1601); Traffic Signaling & ACL changes; Rootkit (T1014)
- **Credential Access** — Network Sniffing / AAA capture (T1040); Modify Authentication Process (T1556)
- **Command & Control** — Protocol Tunneling: GRE/IPsec (T1572); Encrypted Channel / TLS (T1573)
- **Exfiltration** — Exfil Over C2 / non-C2 channel (T1041, T1048)

## Deployment notes

- **Get network-device logs into your SIEM.** Config-change command logging, IOS XE web-UI/HTTP access logs, and AAA logs are the prerequisite for the layer-A queries. This is the single biggest visibility gap for this actor.
- **Treat credential anomalies as first-class.** Talos found nearly all initial access used valid stolen credentials, so the sign-in anomaly query (KQL #5) and AAA review (SPL A3) are as important as CVE hunting.
- **YARA is a secondary leg** — the network-device activity has no Windows file artifact, and the malware rules are hash-based until you add verified hashes. Don't expect endpoint YARA to catch the core intrusion.
- **The KQL web-UI and C2 queries assume specific Sentinel tables** (`CommonSecurityLog`, device tables) — adjust to your actual log sources.

## Sources

- CISA — [AA25-239A: Countering Chinese State-Sponsored Actors' Compromise of Networks Worldwide](https://www.cisa.gov/news-events/alerts/2025/08/27/cisa-and-partners-release-joint-advisory-countering-chinese-state-sponsored-actors-compromise)
- Trend Micro — [Game of Emperor: Unveiling Long Term Earth Estries Cyber Intrusions](https://www.trendmicro.com/en_us/research/24/k/earth-estries.html)
- Cisco Talos — Salt Typhoon telecom intrusions (stolen-credential initial access)
- Kaspersky — GhostEmperor / Demodex rootkit; ESET — FamousSparrow / SparrowDoor
