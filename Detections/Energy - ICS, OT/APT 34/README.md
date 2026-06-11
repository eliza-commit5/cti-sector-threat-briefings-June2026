# APT34 / OilRig (MOIS) — Detection Pack

> **TLP:CLEAR.** Detections compiled from primary reporting. Validate every indicator and rule against your own telemetry before operational use.

Maintained by Eliza / eliza-commit5

Iranian Ministry of Intelligence and Security (MOIS) actor, also tracked as **OilRig, Helix Kitten, Earth Simnavaz, Cobalt Gypsy, CHRYSENE,** and **GreenBug** (MITRE **G0049**). Active since ~2014, focused on long-dwell espionage against **energy, government, finance, and telecom** across the Middle East and beyond. Signature tradecraft: **DNS-tunneling C2**, **Exchange/EWS email-based C2**, **passive IIS backdoors / webshells**, and .NET backdoors delivered via double-extension lures.

## Files

| File | Platform | What it covers |
|---|---|---|
| `apt34_splunk.spl` | Splunk SPL | DNS tunneling, known C2, EWS email-C2 + inbox-rule abuse, IIS webshell, delivery/persistence |
| `apt34_defender.kql` | Defender XDR / Sentinel | Same logic across `DeviceNetworkEvents`/`DeviceProcessEvents`/`DeviceRegistryEvents` |
| `veaty_spearal.yar` | YARA | High-confidence Spearal (DNS) + Veaty (email-C2) rules + hash rule |

## Signature capabilities

**Spearal** — .NET backdoor using a **custom DNS-tunneling** protocol; data Base32-encoded in subdomains, TXT queries; C2 domain in config (`srvip`/`domn`), default `iqwebservice[.]com`. Protocol verbs: `auth:;`, `cmd:;`, `crs:;`, `crb:;`, `cre:;`, `rok:;`.

**Veaty** — .NET backdoor using **Exchange/EWS email C2** via compromised mailboxes; disables TLS cert validation; tries connection flags `try_defaultcred` → `try_hardcodedCreds` → `try_externalCreds` → `try_trustedNetwork`; hardcoded typo-squat host **`mail.miicrosoft[.]com`**; creates inbox rules to funnel C2 mail to a folder. Overlaps with **Karkoff**.

**Passive IIS backdoors** — `CacheHttp.dll` (IIS Group2 variant), **RGDoor**, **TwoFace** webshell; communicate via encrypted cookies / web requests. Tied to the briefing's "ASPX webshells on Exchange servers."

**Historical** — Saitama (DNS, base36 alphabet, 2022 Jordan), QUADAGENT, ISMAgent, BONDUPDATER, Helminth, SideTwist, STEALHOOK.

## Indicators of compromise

> **Validity warning:** atomic indicators churn; the durable signal is the *behaviors* (DNS tunneling shape, EWS-from-non-Outlook, w3wp spawning shells). Populate hash placeholders from the Check Point appendix.

| Type | Indicator | Notes |
|---|---|---|
| Domain | `iqwebservice[.]com` | Spearal default DNS-tunnel C2 |
| Domain | `mail.miicrosoft[.]com` | Veaty hardcoded fake mail host (typo-squat, two i's) |
| Domain | `asiaworldremit[.]com`, `joexpediagroup[.]com` | Saitama root domains (2022) |
| Mailbox | `*@gov-iq.net` (victim domain) | Veaty C2 mailboxes (campaign-specific) |
| Path | `C:\ProgramData\System Documents\FortiClients.exe` (+ `.config`) | Loader drop location |
| Registry | `HKCU\...\CurrentVersion\Run` value `Forti Startup` | Persistence |
| Lure files | `Avamer.pdf.exe`, `Protocol.pdf.exe`, `IraqiDoc.docx.rar`, `ncms_demo.msi` | Double-extension delivery |
| Config | XML w/ base64 keys: `srvip`, `domn`, `chunk_len`, `creds`, `communicationFolder` | Spearal/Veaty config structure |
| EWS | `https://<server>/EWS/exchange.asmx` | Veaty C2 transport |
| Hashes | **TO BE ADDED** | Paste verified SHA-256 from Check Point appendix |

## MITRE ATT&CK (Enterprise)

- **Initial Access** — Spearphishing Attachment (T1566.001); Valid Accounts (T1078)
- **Execution** — PowerShell (T1059.001); User Execution / double extensions (T1204.002)
- **Persistence** — Run key (T1547.001); Server Software Component: Web Shell / IIS module (T1505.003, T1505.004); Outlook/Exchange rules (T1137.005 / T1564.008)
- **Defense Evasion** — Timestomp (T1070.006); Disable TLS validation
- **Command & Control** — DNS / DNS tunneling (T1071.004, T1572); Email-based C2 over web service (T1071.003 / T1102)
- **Exfiltration** — Exfil over C2 / alternative protocol (T1041, T1048)

## Deployment notes

- **The two YARA binary rules are high-confidence** (distinctive protocol/config strings) and safe to hunt with; the hash rule is inert until you add verified hashes (all-zero placeholder).
- **DNS search needs verbose DNS logging** (Sysmon EID 22, Zeek `dns.log`, or resolver logs). Tune the subdomain-length and unique-query thresholds to your baseline.
- **EWS and inbox-rule detections** require Exchange/IIS logs and M365/Exchange audit (`New-InboxRule`/`Set-InboxRule`). These are some of the most durable APT34 tells.
- **The KQL DNS query (#2) has an environment-finicky line** (longest-label computation) — the durable filter is `strlen(host) > 60` plus a high count of unique subdomains under one parent. Simplify if your tenant rejects the array functions.

## Sources

- Check Point Research — [Targeted Iranian Attacks Against Iraqi Government Infrastructure](https://research.checkpoint.com/2024/iranian-malware-attacks-iraqi-government/) (Veaty/Spearal)
- Fortinet — [Please Confirm You Received Our APT](https://www.fortinet.com/blog/threat-research/please-confirm-you-received-our-apt) (Saitama, 2022)
- ESET / Symantec — IIS Group2 / GreenBug passive IIS backdoors
- MITRE ATT&CK — [G0049 (OilRig)](https://attack.mitre.org/groups/G0049/)
