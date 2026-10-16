# SOC Homelab — Wazuh SIEM & Detection Engineering

[![Wazuh](https://img.shields.io/badge/SIEM-Wazuh%20v4.14-blue?style=flat-square)](https://wazuh.com)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red?style=flat-square)](https://attack.mitre.org)
[![Labs Completed](https://img.shields.io/badge/Labs%20Completed-2%20Documented-success?style=flat-square)](#lab-execution-matrix)
[![Analyst](https://img.shields.io/badge/Analyst-Jaser%20Halabi-lightgrey?style=flat-square&logo=github)](https://github.com/JaserHalabi)

> A hands-on Security Operations Center (SOC) homelab documenting real-world attack simulations, SIEM log analysis, detection gap assessments, and custom rule development using **Wazuh** mapped against the **MITRE ATT&CK** framework.

---

## Lab Architecture

| Component | Role | Details | IP Address |
|---|---|---|---|
| **Wazuh Manager** | Central SIEM / XDR Server | Wazuh Server v4.14.8 (`node01`) | Homelab Core |
| **Windows 10 Target** | Monitored Endpoint | Windows 10 Home (Agent ID: `003`, active) | `192.168.150.132` |
| **Kali Linux** | Adversary Emulation Node | Offensive security tools (Nmap, NetExec, Hydra) | `192.168.150.135` |

---

## Lab Execution Matrix

| # | Lab Module | MITRE ATT&CK | Focus Area | Status | Date |
|---|---|---|---|:---:|:---:|
| 01 | [Network Service Scanning & Detection Gap](./Network-Service-Scanning/) | [T1046](https://attack.mitre.org/techniques/T1046/) | Nmap reconnaissance detection testing, firewall log gap analysis & remediation | Validated (Rule 92031) | 2026-10-15 |
| 02 | [SMB Brute Force & Credential Access](./SMB-Brute-Force-Detection/) | [T1110](https://attack.mitre.org/techniques/T1110/) | NetExec dictionary attack, Event ID 4625/4624/4740 telemetry, Wazuh correlation & Account Lockout fix | Validated & Mitigated | 2026-10-16 |

> *New SOC labs and detection test cases will be analyzed and published as additional attacks and rules are simulated.*

---

## Detection Engineering Methodology

1. **Adversary Emulation:** Execute targeted attack techniques from Kali Linux mapped to MITRE ATT&CK tactics.
2. **Telemetry Verification:** Query Wazuh SIEM security events to inspect raw log ingestion and alert triggering.
3. **Detection Gap Analysis:** Identify missing audit policies, uncollected log sources, or rule signature limitations when attacks pass undetected.
4. **Remediation & Custom Rules:** Enable endpoint telemetry (Windows Event Logs, Firewall, Sysmon) and author custom Wazuh XML rules to close the gap.

---

_Maintained by **[Jaser Halabi](https://github.com/JaserHalabi)**_
