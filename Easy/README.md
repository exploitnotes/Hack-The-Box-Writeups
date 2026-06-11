# 🟢 HackTheBox: Easy Tier Writeups

This directory serves as a collection of writeups for **Easy-difficulty** machines on HackTheBox. These machines are chosen to build and reinforce foundational penetration testing skills, focusing on thorough enumeration and understanding common service vulnerabilities.

---

##  Typical Methodology

For most machines in this category, I follow a standard workflow:

1. **Service Enumeration:** Identifying running services and version detection via `nmap`.
2. **Web Analysis:** Checking for common CMS vulnerabilities (like XWiki), directory brute-forcing, and source code review.
3. **Exploitation:** Leveraging public CVEs or misconfigured services to gain initial access.
4. **Privilege Escalation:** Performing local enumeration to find SUID binaries, cron jobs, or PATH hijacking opportunities.

---

##  Machine Index

| Machine Name | OS | Main Vulnerability | Difficulty (User/Root) | Link |
| :--- | :--- | :--- | :--- | :--- |
| **Editor** | Linux | CVE-2025-24893 (RCE) | 🟢 / 🟢 | [Writeup](./Editor/README.md) |
| **Expressway** | Linux | IKE Agressive mode/ Custom SUID Binary | 🟢 / 🟢 | [Writeup](./Expressway/README.md) |
| **MonitorsFour** | Linux | CVE-2025-24367(RCE)/ Exposed Docker Remote API (Unauthenticated) | 🟢 / 🟢 | [Writeup](./MonitorsFour/README.md) |
| **Facts** | Linux | Information Disclosure + Misconfiguration | 🟢 / 🟢 | [Writeup](./Facts/README.md) |
| **WingData** | Linux | Web Application Vulnerability (Auth/Injection) | 🟢 / 🟢 | [Writeup](./Wingdata/README.md) |
| **CCTV** | Mar 2026 | Internal Reconnaissance, API Abuse, Service Misconfiguration | 🟢 / 🟢 |[Writeup](./Easy/README.md) |
| **Kobold** | Mar 2026 | JSON Injection, RCE (CVE-2026-23744), Docker Privilege Escalation, Container Escape | 🟢 / 🟢 | [Writeup](./Kobold/README.md) |
| **Support** | Mar 2026 | AD Enumeration, SMB Anonymous Access, .NET Decompilation, Credential Decryption, LDAP Abuse, RBCD (Resource-Based Constrained Delegation), Kerberos Impersonation | 🟢 / 🟢 | [Writeup](./Support/README.md) |
| **Silentium** | Linux | Subdomain Fuzzing → API Auth Bypass (forgot-password) → Flowise RCE (CVE-2025-59528) → Docker Root → Credential Extraction → SSH Access → Gogs Discovery → CVE-2025-8110 RCE → Root | 🟢 / 🟢 | [Writeup](./Silentium/README.md) |
| **TwoMillion** | Linux | JS Analysis → Invite Code Generation → API Enumeration → Admin Privilege Escalation → Command Injection → Reverse Shell → Credential Reuse → SSH Access → OverlayFS PrivEsc (CVE-2023-0386) → Root | 🟢 / 🟢 | [Writeup](./TwoMillion/README.md) |
| **Reactor** | Linux | Next.js Fingerprinting → CVE-2025-55182 (Unauth RCE) → SQLite DB Loot → MD5 Hash Cracking → SSH Access → Node Inspector Abuse (--inspect as root) → Root | 🟢 / 🟢 | [Writeup](./Reactor/README.md) |
| **Facts** | Linux | Camaleon CMS Recon → CVE-2024-46987 (LFI) → CVE-2025-2304 (Mass Assignment → Admin) → LocalStack S3 Creds Leak → SSH Key Retrieval → Passphrase Crack → SSH Access → Facter Custom Ruby (sudo NOPASSWD) → Root | 🟢 / 🟢 | [Writeup](./Facts/README.md) |
---

##  Common Tools Used

* **Scanning:** `nmap`, `rustscan`.
* **Web:** `gobuster`, `feroxbuster`, `burpsuite`.
* **PrivEsc:** `linpeas.sh`, `pspy`, `ndsudo`.

---

[ Back to Main Portfolio](../README.md)