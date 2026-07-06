# Threat Intelligence Briefs

Open-source cyber threat intelligence (CTI) briefs on threat actors targeting specific industry sectors, written in standard intelligence-product format. Each brief profiles an adversary, maps its tactics to the MITRE ATT&CK framework, lists indicators of compromise, and provides prioritized defensive recommendations for both technical and executive audiences.

## Briefs

| Actor | Type | Target sector | Date | Key techniques | Brief |
|---|---|---|---|---|---|
| Qilin (formerly Agenda) | Ransomware-as-a-Service | Financial services | Jul 2026 | Valid Accounts (T1078), Double Extortion, ESXi/WSL evasion | [Read](briefs/qilin-financial-sector.md) · [IOCs](iocs/qilin-iocs.csv) |

## Methodology

These briefs are built entirely from **open-source intelligence (OSINT)** — vendor threat research, CISA advisories, and public incident reporting — with every factual claim cited to a published source. Adversary behavior is mapped to the [MITRE ATT&CK](https://attack.mitre.org/) framework so techniques can be cross-referenced against a defender's own detection coverage. Each brief is written in two registers: a plain-language executive summary for decision-makers, and a technical TTP/IOC section for security operations teams.

Confidence levels and classification (Traffic Light Protocol) are noted at the top of each brief. All briefs are TLP:CLEAR and contain no confidential or non-public information.

## Why sector-specific?

Generic "top ransomware groups" lists are easy to find. These briefs instead ask a sharper question: *given a specific actor, what does this specific kind of organization need to do about it?* — because a threat that is opportunistic in general is often precise in its impact on a particular sector.

## Author

**Kethan Umanarayanan** — M.S. Cybersecurity candidate, Drexel University
For educational and portfolio purposes.
