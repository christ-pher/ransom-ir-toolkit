# White Rabbit Ransomware (FIN8/Sardonic) - Technical Analysis

**Classification:** TLP:AMBER - Restricted to incident response team and authorized stakeholders only
**Document Type:** DFIR Technical Reference
**Last Updated:** 2026-02-19
**Applicability:** Active incident - White Rabbit + Mario (RansomHouse) joint campaign targeting Windows infrastructure

---

## Executive Summary

White Rabbit is a ransomware family with confirmed operational ties to **FIN8**, a financially motivated threat group tracked since at least 2016. White Rabbit was first observed in the wild in **December 2021** and is deployed as a late-stage payload via FIN8's **Sardonic** backdoor infrastructure.

Key characteristics that distinguish White Rabbit from other ransomware families:

- **Command-line password gate**: The binary requires a specific password argument at execution time to decrypt and activate its internal payload. Without the correct password, the binary is inert. This serves as both an anti-analysis mechanism and a sandbox evasion technique.
- **Per-file ransom notes**: Every encrypted file receives a corresponding `.scrypt.txt` ransom note, producing a high volume of IOC-bearing artifacts.
- **File extension**: Encrypted files are appended with `.scrypt`.
- **Double extortion model**: Victims face both encryption and data publication threats.

This incident involves a **documented joint campaign pattern** in which White Rabbit (FIN8) targets Windows machines while Mario (RansomHouse) encrypts ESXi virtual machine infrastructure. This pattern was first documented by Resecurity in 2023 as the "Cyber-Extortion Trinity" involving BianLian, White Rabbit, and Mario. Recovery must address both encryption families independently.

---

## Threat Actor Profile: FIN8

### Background

FIN8 is a financially motivated cybercrime group that has been active since at least **2016**. The group originally specialized in **Point of Sale (POS) malware** campaigns targeting the retail and hospitality sectors, deploying memory-scraping tools to harvest payment card data from POS terminals.

Beginning around **2021**, FIN8 pivoted to ransomware operations, leveraging their existing access infrastructure and tooling to deploy White Rabbit as a monetization vehicle.

### Attribution Chain

Multiple independent security vendors have established the FIN8-to-White Rabbit link:

- **Trend Micro** (January 2022): Identified White Rabbit samples and linked execution infrastructure to known FIN8 TTPs.
- **Lodestone**: Published detailed technical analysis establishing the FIN8 connection through shared infrastructure, tooling overlap, and operational patterns.

The primary attribution indicator is the use of **Sardonic** as the delivery and C2 mechanism for White Rabbit payloads.

### FIN8 Tooling Arsenal

| Tool | Type | Role |
|---|---|---|
| **Sardonic** | C++-based backdoor | Primary C2 and payload delivery platform; plugin architecture allows modular capability loading |
| **BADHATCH** | Backdoor | Earlier-generation backdoor; predecessor to Sardonic in some operational contexts |
| **ShellTea / PunchBuggy** | Backdoor / loader | Legacy POS-era tooling; may still appear in environments with long-term FIN8 persistence |
| **White Rabbit** | Ransomware | Late-stage encryption payload deployed through Sardonic |

### Sardonic Backdoor Details

Sardonic is the critical link between FIN8 infrastructure and White Rabbit deployment:

- Written in C++ with a modular plugin architecture
- Supports arbitrary plugin loading for capability extension
- Provides persistent remote access to compromised environments
- Handles lateral movement coordination and payload staging
- C2 communications should be considered a high-priority network forensic target

---

## Execution Flow

### Phase 1: Initial Access and Staging

1. **Initial access** is achieved through standard FIN8 TTPs:
   - Spear-phishing with weaponized attachments or links
   - Exploitation of public-facing applications
   - Use of valid credentials (purchased from access brokers or harvested in prior operations)

2. **Sardonic backdoor deployment** establishes persistent C2:
   - Dropped to disk in `%TEMP%`, `%APPDATA%`, or other user-writable locations
   - Persistence established via registry run keys, scheduled tasks, or service installation
   - Plugin modules loaded to extend capabilities as needed

3. **Reconnaissance and lateral movement**:
   - Active Directory enumeration
   - Credential harvesting (Mimikatz, LSASS dumping, Kerberoasting)
   - SMB-based lateral movement to additional hosts
   - Privilege escalation to Domain Admin or equivalent

4. **Pre-encryption staging**:
   - Data exfiltration for double extortion leverage
   - Identification of backup systems and security tooling
   - Positioning of White Rabbit binary on target hosts

### Phase 2: Password-Protected Execution

This is the defining characteristic of White Rabbit's execution model:

```
white_rabbit.exe -p KissMe123
```

**Critical details:**

- The password is passed as a **command-line argument** (typically `-p` or `--password`).
- The password varies **per campaign** and may be unique to the target environment.
- Without the correct password, the binary **does not encrypt anything**. It will either exit silently or produce no meaningful activity.
- The password is used to **decrypt the internal payload/configuration** that is embedded in the binary in encrypted form.
- This mechanism serves multiple purposes:
  - **Anti-analysis**: Automated sandbox detonation will not trigger the payload without the password.
  - **Anti-reverse-engineering**: Static analysis of the binary without the password does not expose the encryption logic or configuration.
  - **Operational security**: If the binary is intercepted or recovered, it cannot be trivially analyzed without the password.

**Forensic implication:** If the binary is recovered from disk, the command-line password may be recoverable from:
- Process creation event logs (Event ID 4688 with command-line auditing enabled)
- Sardonic C2 communication logs (if network capture is available)
- ShimCache / AmCache artifacts
- Prefetch files (may contain partial command-line context)
- PowerShell script block logs or transcript logs (if the execution was scripted)

### Phase 3: Encryption Process

Once the password successfully decrypts the internal payload, the following sequence executes:

1. **Internal configuration decryption**: The embedded payload is decrypted using the command-line password, exposing the encryption configuration, RSA public key, ransom note template, and file targeting rules.

2. **Drive and share enumeration**: The ransomware enumerates all available storage:
   - Local drives (fixed, removable)
   - Mapped network drives
   - Accessible SMB/UNC shares (including administrative shares such as `C$`, `ADMIN$`)

3. **Process and service termination**: Processes that may hold file locks are terminated to maximize encryption coverage:
   - Database engines (SQL Server, MySQL, Oracle, PostgreSQL)
   - Email servers (Exchange)
   - Office applications (Word, Excel, Outlook)
   - Backup agents and services
   - Security and monitoring tools

4. **Shadow copy destruction**:
   ```
   vssadmin delete shadows /all /quiet
   ```
   This command is executed to eliminate Volume Shadow Copy Service snapshots, removing the most accessible recovery option on Windows systems.

5. **File encryption loop** (per target file):
   - a. Read the original file content
   - b. Generate a unique symmetric key for this file
   - c. Encrypt file content using the symmetric key (AES or equivalent)
   - d. Encrypt the per-file symmetric key using the embedded RSA public key
   - e. Write the encrypted data with the `.scrypt` extension appended to the original filename
   - f. Drop a ransom note as `original_filename.scrypt.txt`
   - g. Delete the original file

6. **Wallpaper modification** (variant-dependent): Some variants change the desktop wallpaper to display a ransom notification.

### Encryption Architecture

The encryption scheme follows industry-standard hybrid encryption, which is **cryptographically sound when properly implemented**:

| Component | Algorithm | Purpose |
|---|---|---|
| **Asymmetric** | RSA | Per-file symmetric key encryption; public key is embedded in the binary |
| **Symmetric** | AES (or equivalent) | Bulk file content encryption; unique key per file |

**Key hierarchy:**

```
RSA Private Key (held by threat actor)
  |
  +-- RSA Public Key (embedded in binary)
        |
        +-- Per-File Symmetric Key (randomly generated, encrypted with RSA public key)
              |
              +-- Encrypted File Content
```

**Analysis notes:**

- The RSA public key **can** be extracted from the binary for forensic documentation and campaign correlation.
- Without the corresponding RSA private key (held exclusively by the threat actor), **decryption of encrypted files is not possible** through cryptographic means.
- Each file's unique symmetric key means partial key recovery does not assist with other files.

---

## Ransom Note Analysis

### Distribution Pattern

White Rabbit drops a `.scrypt.txt` ransom note for **every single encrypted file**. This is in contrast to ransomware families that drop a single note per directory. The per-file note pattern results in a high volume of ransom note artifacts, which has both forensic value (more IOCs) and operational impact (significant disk write activity and inode consumption).

### Note Structure

The typical White Rabbit ransom note follows this template:

```
** Your files have been encrypted by White Rabbit **

Your unique ID: [VICTIM_ID]

All your files have been encrypted due to a security problem with your server.
To restore them you need to contact us.

Contact us:
Email: [email]@protonmail.com
TOX: [76-char hex string]
Tor: http://[...].onion/[path]

DO NOT try to recover files yourself - you will damage them.
You have [X] days to contact us before your data is published.
[BTC address for payment]
```

### Note Contents and IOC Value

Each ransom note contains multiple extractable indicators of compromise:

| Field | IOC Type | Intelligence Value |
|---|---|---|
| **Email addresses** | Contact infrastructure | Track across campaigns; report to email providers (ProtonMail, Tutanota) for takedown; correlate with other ransomware families |
| **Tor/.onion URLs** | Negotiation/leak infrastructure | Monitor for victim data publication; map threat actor infrastructure |
| **BTC addresses** | Financial infrastructure | Blockchain analysis for payment tracking; identify shared wallets across campaigns; law enforcement coordination |
| **TOX Messenger IDs** | Contact infrastructure | Cross-reference with other ransomware campaigns; TOX IDs are persistent identifiers |
| **Victim IDs** | Campaign tracking | Determine campaign scope; correlate with other victims; establish whether multiple victim IDs indicate multiple compromised segments |
| **Deadline timestamps** | Temporal intelligence | Establish incident timeline; determine threat actor's operational tempo |

**Action item:** Extract all IOCs from recovered `.scrypt.txt` notes and feed into threat intelligence platform. Every unique note should be parsed, as field values may vary across notes within the same campaign if the threat actor uses per-victim or per-segment configurations.

---

## Joint Campaign Context: BianLian + White Rabbit + Mario (RansomHouse)

### Campaign Pattern

This incident follows a documented multi-actor extortion pattern first reported by **Resecurity in 2023** under the title "Exposing Cyber-Extortion Trinity." The pattern involves three distinct ransomware operations targeting the same victim, either through shared access or coordinated deployment.

### Observed Roles in This Incident

| Actor | Target | Encryption |
|---|---|---|
| **Mario (RansomHouse)** | ESXi virtual machine infrastructure | Babuk-derived encryption of VMDK/VM files |
| **White Rabbit (FIN8)** | Windows machines | .scrypt encryption of Windows file systems |
| **BianLian** | Possible involvement in initial access and/or data exfiltration | Under investigation |

### Operational Implications

- **Shared access broker**: The most likely explanation for multi-actor targeting is a shared initial access broker (IAB) who sold or provided access to the victim environment to multiple ransomware operators independently or as a package.
- **Multiple ransom demands**: The victim may receive separate ransom demands from different groups, each threatening independent data publication.
- **Independent recovery tracks**: Recovery from White Rabbit encryption and Mario encryption must be addressed as **separate technical problems** with different tooling, keys, and threat actor engagement considerations.
- **Compounded exfiltration risk**: Multiple actors may have independently exfiltrated data, increasing the scope of potential data exposure even if one group's demands are addressed.

---

## Recovery Assessment

### Decryptor Availability: NONE

As of this writing, **no public decryptor exists** for White Rabbit ransomware.

The following repositories and resources have been checked:

| Source | Status |
|---|---|
| NoMoreRansom Project | Negative |
| Emsisoft Decryption Tools | Negative |
| Avast Decryption Tools | Negative |
| Kaspersky RakhniDecryptor / NoRansom | Negative |
| Bitdefender Decryption Tools | Negative |
| ID Ransomware (Michael Gillespie) | Identified but no decryptor |

The encryption implementation (RSA + symmetric hybrid) is **cryptographically sound** if properly implemented, and no implementation weaknesses have been publicly documented for White Rabbit.

There are **no known leaked private keys** for White Rabbit (in contrast to Babuk, whose source code and some keys have been leaked, which is relevant to the parallel Mario recovery track).

### Recovery Vectors to Investigate

The following recovery angles should be pursued in priority order:

1. **Volume Shadow Copy recovery**
   - White Rabbit executes `vssadmin delete shadows /all /quiet` but this command may fail or execute incompletely in certain conditions.
   - Check for surviving shadow copies: `vssadmin list shadows`
   - Use tools such as ShadowExplorer or Arsenal Image Mounter to examine any surviving snapshots.
   - If the system was disconnected from power rapidly, the deletion may not have completed.

2. **Backup recovery**
   - Identify all backup systems and verify their integrity.
   - Check for offline, air-gapped, or cloud-based backups that were outside the encryption scope.
   - Verify backup agent logs to determine whether backup infrastructure was compromised.

3. **Deleted file recovery**
   - White Rabbit deletes original files after writing the encrypted version.
   - Deleted file content may still reside on disk if the sectors have not been overwritten.
   - Use forensic recovery tools (FTK, EnCase, Autopsy, PhotoRec) to attempt recovery of deleted originals.
   - **Time-critical**: The longer the system remains in use after encryption, the lower the probability of successful recovery.
   - SSDs with TRIM enabled significantly reduce recovery probability.

4. **Implementation bug exploitation**
   - Some White Rabbit variants have exhibited bugs in file enumeration logic, resulting in certain files or directories being **skipped during encryption**.
   - Conduct a thorough audit of all drives and shares to identify any files that may have escaped encryption.
   - Compare file system metadata (MFT analysis) against encrypted file inventory to identify gaps.

5. **Memory forensics**
   - **NOT APPLICABLE in this case**: The affected machine was powered off, destroying volatile memory contents.
   - Had the machine remained powered on, memory analysis could potentially have recovered:
     - The command-line password
     - Symmetric keys in process memory
     - The decrypted internal payload
   - **Lesson learned for future incidents**: If White Rabbit encryption is detected in progress or recently completed, **do not power off the machine**. Capture a full memory dump first.

---

## MITRE ATT&CK Mapping

The following ATT&CK techniques are associated with White Rabbit operations in the context of FIN8/Sardonic deployment:

| Technique ID | Technique Name | Context in This Incident |
|---|---|---|
| **T1059.001** | Command and Scripting Interpreter: PowerShell | Sardonic deployment, payload staging, and execution scripting |
| **T1059.003** | Command and Scripting Interpreter: Windows Command Shell | Password-protected White Rabbit binary execution via cmd.exe |
| **T1027** | Obfuscated Files or Information | White Rabbit binary contains password-encrypted internal payload |
| **T1140** | Deobfuscate/Decode Files or Information | Runtime decryption of internal payload using command-line password |
| **T1490** | Inhibit System Recovery | Shadow copy deletion via vssadmin |
| **T1489** | Service Stop | Termination of database, email, backup, and security services |
| **T1486** | Data Encrypted for Impact | Core ransomware function; .scrypt file encryption |
| **T1005** | Data from Local System | File enumeration across local drives prior to encryption |
| **T1021.002** | Remote Services: SMB/Windows Admin Shares | Network share discovery and encryption across SMB |
| **T1082** | System Information Discovery | Environment enumeration for drive and share mapping |
| **T1057** | Process Discovery | Identification of processes to terminate before encryption |
| **T1562.001** | Impair Defenses: Disable or Modify Tools | Termination of security monitoring and endpoint protection tools |

---

## File System Artifacts

### Encrypted File Artifacts

| Artifact | Location | Description |
|---|---|---|
| `*.scrypt` | All targeted drives and shares | Encrypted file; original filename preserved with .scrypt appended |
| `*.scrypt.txt` | Adjacent to each .scrypt file | Per-file ransom note containing IOCs |

### Binary and Tooling Artifacts

| Artifact | Likely Location | Description |
|---|---|---|
| White Rabbit PE executable | Variable; may use innocuous or randomized filename | The ransomware binary itself; PE format |
| Sardonic backdoor components | `%TEMP%`, `%APPDATA%`, `%PROGRAMDATA%` | C++ backdoor modules and plugins |
| Sardonic persistence mechanisms | Registry run keys, scheduled tasks, services | Persistence artifacts from Sardonic installation |

### Forensic Evidence Sources

| Source | What to Look For |
|---|---|
| **Windows Event Logs** | Event ID 4688 (process creation with command-line logging) for the White Rabbit execution command and password; Event ID 7045 (service installation) for Sardonic persistence; Event IDs 1102/104 for log clearing |
| **VSS/Backup Logs** | Evidence of `vssadmin delete shadows` execution and success/failure |
| **Prefetch** | `*.pf` files for White Rabbit binary and any associated tools |
| **AmCache / ShimCache** | Execution evidence for White Rabbit and Sardonic binaries |
| **MFT ($MFT)** | File creation timestamps for .scrypt and .scrypt.txt files to establish encryption timeline; deleted file entries for original files |
| **Registry** | Sardonic persistence keys; desktop wallpaper modification (if applicable) |
| **NTFS USN Journal** | Detailed file operation timeline: create, rename, delete operations during encryption |

---

## Detection Signatures and Hunting Indicators

### YARA Rule Indicators

The following strings and patterns are relevant for YARA rule development or binary identification:

- Literal string: `White Rabbit` (present in binary metadata or ransom note template)
- Extension reference: `.scrypt` (hardcoded in encryption routine)
- Command-line argument parsing patterns: `-p`, `--password` (argument handling code)
- RSA key material: `BEGIN PUBLIC KEY` or raw ASN.1 DER-encoded key structures
- Shadow copy deletion: `vssadmin delete shadows /all /quiet`
- Process termination lists: Strings referencing database, email, and backup process names

### Network Detection Indicators

| Indicator | Detection Method |
|---|---|
| Sardonic C2 traffic | Network signature matching against known Sardonic communication patterns; look for beaconing behavior to external IPs |
| Tor connectivity | Connections to known Tor entry/guard nodes (post-encryption note access) |
| Anomalous SMB activity | High-volume file read/write operations across multiple shares in rapid succession; mass file rename operations |
| Data exfiltration | Large outbound data transfers to cloud storage, FTP, or actor-controlled infrastructure prior to encryption |

### Endpoint Detection Indicators

| Indicator | Description |
|---|---|
| Mass file rename operations | Rapid `.scrypt` extension appending across multiple directories |
| Shadow copy deletion | `vssadmin.exe` execution with `delete shadows` arguments |
| Bulk process termination | Rapid termination of database, email, and backup processes |
| High-entropy file writes | Encrypted file content produces high Shannon entropy values |
| Per-file .txt creation | Unusual pattern of creating a .txt file for every file written |

---

## References

1. **Trend Micro** - "New Ransomware Spotted: White Rabbit and Its Evasion Tactics" (January 2022). Initial public analysis of White Rabbit execution mechanics and FIN8 linkage.
2. **Lodestone** - "White Rabbit Ransomware and the FIN8 Connection." Technical attribution analysis establishing FIN8 infrastructure overlap.
3. **Resecurity** - "Ransomware Landscape: BianLian, White Rabbit, and Mario Exposing Cyber-Extortion Trinity" (2023). Documentation of the joint campaign pattern observed in this incident.
4. **Michael Gillespie / ID Ransomware** - White Rabbit identification entries and submission tracking.
5. **FireEye/Mandiant** - Historical FIN8 reporting, including POS malware campaigns, BADHATCH, and ShellTea/PunchBuggy analysis.
6. **Bitdefender** - FIN8 threat group analysis and Sardonic backdoor technical reporting.

---

## Document Control

This document is maintained as a living reference for the active incident response engagement. All IOCs extracted during analysis should be cross-referenced with this document and fed into the team's threat intelligence platform. Updates should be appended with timestamps as new findings emerge.
