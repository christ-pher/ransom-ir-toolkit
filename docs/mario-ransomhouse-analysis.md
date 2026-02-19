# Mario Ransomware (RansomHouse) - Technical Analysis

**Classification:** TLP:AMBER -- For incident response team use only
**Last Updated:** 2026-02-19
**Document Purpose:** DFIR reference for active Mario/RansomHouse engagement

---

## Executive Summary

Mario is a ransomware variant operated by the RansomHouse threat group, built on top of the leaked Babuk ransomware source code (publicly disclosed on underground forums in September 2021). Its primary operational focus is the encryption of VMware ESXi hypervisor environments, where it targets virtual machine disk images and associated metadata to maximize disruption across virtualized infrastructure.

Key technical characteristics:

- **Deployment mechanism:** MrAgent, a purpose-built orchestration tool for mass deployment across ESXi hosts.
- **Encryption scheme:** Sosemanuk stream cipher keyed via Curve25519 ECDH key exchange, with SHA-256 key derivation. This is inherited nearly verbatim from Babuk's ESXi locker codebase.
- **Intermittent encryption:** Newer variants employ sparse/intermittent encryption for files exceeding an 8 GB threshold, encrypting fixed-size blocks at intervals rather than the full file. This is the primary data recovery opportunity.
- **File extensions:** `.emario` (older variant, full encryption) and `.omario` (newer variant, intermittent encryption).
- **Joint operations:** Mario has been documented operating in concert with White Rabbit (linked to FIN8) and BianLian in coordinated multi-group extortion campaigns targeting the same victims.

There is no publicly available universal decryptor for Mario. Recovery efforts should focus on exploiting the intermittent encryption gaps in large files and on structural recovery of VMDK contents.

---

## Threat Actor Profile

### RansomHouse Group

RansomHouse positions itself as a "mediator" between victims and the consequences of their own poor security posture, rather than as a traditional ransomware operator. This framing is a social engineering tactic designed to lower negotiation resistance and shift perceived blame onto the victim organization.

- **First observed:** Mid-2022.
- **Operational model:** Data extortion with optional encryption. RansomHouse has historically operated both with and without deploying encryptors, sometimes relying purely on data theft and leak threats. The Mario encryptor represents their destructive capability when encryption is deployed.
- **Known victims (public):**
  - AMD (claimed June 2022, data exfiltration)
  - Keralty / Sanitas (Colombian healthcare conglomerate, November 2022)
  - Multiple Italian organizations
  - Various mid-market enterprises across Europe and Latin America
- **Leak site:** Operates a Tor-based data leak site for victim shaming and data publication.
- **State-affiliated usage:** CISA Advisory AA24-241A (August 2024) documented Iranian cyber actors deploying RansomHouse tooling as part of broader campaigns against U.S. and allied organizations. This indicates that RansomHouse tools may be accessible to or shared with state-affiliated threat actors, complicating attribution.

### Relationship to Other Groups

RansomHouse does not operate in isolation. The group maintains relationships with initial access brokers and has been observed sharing infrastructure with other extortion operations. The joint campaign with BianLian and White Rabbit (detailed below) is the most significant documented example of this cooperative model.

---

## Kill Chain / Attack Flow

The following attack flow represents the typical Mario deployment sequence targeting ESXi infrastructure, synthesized from published incident reports and vendor research.

### Phase 1: Initial Access

Initial access to the ESXi management plane is achieved through one or both of the following vectors:

- **Exploitation of ESXi OpenSLP vulnerabilities:**
  - CVE-2019-5544 -- OpenSLP heap overwrite (CVSS 9.8). Allows unauthenticated remote code execution on the ESXi host.
  - CVE-2020-3992 -- OpenSLP use-after-free (CVSS 9.8). Allows unauthenticated remote code execution via a crafted SLP message.
  - CVE-2021-21974 -- OpenSLP heap overflow (CVSS 8.8). The same vulnerability class exploited by ESXiArgs in early 2023.
- **Compromised credentials:** Stolen or brute-forced ESXi root credentials, vCenter administrative credentials, or SSH keys. Often obtained through prior compromise of the Windows domain (credential harvesting from domain controllers, LSASS dumps, etc.) where vCenter is domain-joined.

In joint campaigns, BianLian or other partners may handle initial access and lateral movement, handing off ESXi-level access to the Mario operator for encryption.

### Phase 2: MrAgent Deployment and Orchestration

Once access to the ESXi management plane is established, the operator deploys MrAgent, a custom-built orchestration tool designed specifically for mass ransomware deployment across ESXi infrastructure.

MrAgent performs the following actions:

1. **C2 communication:** Establishes a connection to the operator's command-and-control server to receive deployment instructions and report status.
2. **Host discovery:** Enumerates accessible ESXi hosts across the target environment.
3. **Firewall disabling:** Executes commands to disable the ESXi firewall on each target host, ensuring unimpeded encryptor execution and C2 connectivity.
4. **Encryptor deployment:** Transfers the Mario encryptor binary (ELF) to each target ESXi host.
5. **Configuration:** Passes per-host encryption parameters to the encryptor (target paths, encryption mode, file extension, ransom note content).
6. **Concurrent execution:** Launches the encryptor across multiple hosts simultaneously to minimize the window for detection and response.
7. **Status reporting:** Reports encryption progress and completion status back to C2.

MrAgent is a significant force multiplier. Without it, an attacker would need to manually deploy and execute the encryptor on each ESXi host individually. MrAgent automates this into a single coordinated operation.

### Phase 3: Pre-Encryption Preparation

Before the encryptor begins encrypting files, it performs preparatory actions on each ESXi host:

- **Virtual machine shutdown:** All running VMs are powered off to release file locks on VMDK, VMEM, and VSWP files. This is typically accomplished via `vim-cmd vmsvc/power.off` or `esxcli vm process kill` commands.
- **Snapshot deletion:** Existing VM snapshots are deleted to prevent rollback-based recovery. This removes delta VMDK files and snapshot metadata.
- **Process termination:** Any processes that may hold locks on target files are terminated.

### Phase 4: Encryption

The encryptor targets the following file types within ESXi datastores:

| File Type | Description | Impact |
|-----------|-------------|--------|
| `.vmdk` | Virtual machine disk images | Primary target -- contains all guest OS and application data |
| `.vmem` | VM memory snapshots | Contains memory state; may hold credentials and transient data |
| `.vswp` | VM swap files | Contains swapped-out VM memory pages |
| `.log` | ESXi and VM log files | Encrypted to hinder forensic analysis |

The encryption process is detailed in the Encryption Architecture section below.

### Phase 5: Ransom Note Delivery

A plaintext ransom note is dropped in each directory containing encrypted files. The note directs the victim to a Tor-based negotiation portal operated by RansomHouse.

---

## Encryption Architecture

### Cryptographic Primitives

Mario's encryption scheme is inherited from Babuk's ESXi locker and uses the following cryptographic primitives:

| Component | Algorithm | Implementation |
|-----------|-----------|----------------|
| Key Exchange | Curve25519 ECDH | donna implementation (same as Babuk) |
| Stream Cipher | Sosemanuk | eSTREAM portfolio cipher, from the ECRYPT project |
| Key Derivation | SHA-256 | Standard; used to derive the Sosemanuk key from the ECDH shared secret |

**On Sosemanuk:** Sosemanuk is a software-oriented stream cipher selected for the eSTREAM portfolio by the ECRYPT project. It is a well-studied cipher with no known practical cryptanalytic attacks against its full specification. The choice of Sosemanuk (rather than AES or ChaCha20) is a direct artifact of Babuk's original design and has been carried forward into Mario without modification.

### Per-File Encryption Process

For each target file, the encryptor performs the following operations:

```
1. KEYGEN:    Generate ephemeral Curve25519 keypair
                ephemeral_private = random(32 bytes)
                ephemeral_public  = Curve25519_base(ephemeral_private)

2. ECDH:      Compute shared secret
                shared_secret = Curve25519(ephemeral_private, attacker_static_public)
              The attacker's static public key is hardcoded in the encryptor binary.

3. KDF:       Derive symmetric key
                sosemanuk_key = SHA-256(shared_secret)

4. ENCRYPT:   Encrypt file contents with Sosemanuk
                ciphertext = Sosemanuk(sosemanuk_key, plaintext)
              (Encryption mode -- full or intermittent -- depends on variant and file size.)

5. FOOTER:    Append ephemeral public key to encrypted file
                encrypted_file = ciphertext || ephemeral_public (32 bytes)

6. RENAME:    Rename file with ransomware extension
                original.vmdk -> original.vmdk.emario (or .omario)
```

**Decryption requirement:** To decrypt a file, one must possess the attacker's static Curve25519 private key. This key is used to compute the same ECDH shared secret from the per-file ephemeral public key stored in the file footer:

```
shared_secret = Curve25519(attacker_static_private, ephemeral_public)
sosemanuk_key = SHA-256(shared_secret)
plaintext     = Sosemanuk(sosemanuk_key, ciphertext)
```

Without the attacker's static private key, the per-file Sosemanuk key cannot be derived, and the encrypted content cannot be recovered through cryptanalytic means.

### Encryption Modes (Version Differences)

Two distinct encryption behaviors have been observed across Mario variants, corresponding to an evolution in the encryptor's file handling logic.

#### Older Variant -- Full/Linear Encryption

- **Behavior:** Encrypts the entire file content from beginning to end, regardless of file size.
- **Extension:** `.emario`
- **Performance:** Slow on large VMDK files (100+ GB). Full encryption of a large datastore can take hours.
- **Recovery impact:** No unencrypted regions within the file body. Recovery is limited to the file footer (32-byte ephemeral pubkey) and any structural artifacts that survive the stream cipher overwrite.

#### Newer Variant -- Intermittent/Sparse Encryption

- **Behavior:** Applies a size-based threshold to determine encryption mode:
  - **Files < 8 GB:** Encrypted in their entirety (same as the older variant).
  - **Files >= 8 GB:** Intermittent encryption is applied. The encryptor writes encrypted blocks of a fixed size at regular intervals throughout the file, leaving gaps of unencrypted plaintext data between encrypted blocks.
- **Extension:** `.emario` or `.omario` (the `.omario` extension is more commonly associated with the newer variant, but both have been observed).
- **Performance:** Dramatically faster on large files. Intermittent encryption can process a 500 GB VMDK in a fraction of the time required for full encryption.
- **Dual-key possibility:** Some analysis suggests newer variants may use a dual-key approach, applying different keys to different sections of the file. This has implications for any partial decryption attempt but does not affect data carving from unencrypted gaps.
- **Recovery impact:** This is the primary recovery opportunity. Large VMDK files (which virtually always exceed 8 GB) will contain significant regions of unencrypted plaintext data. See the Recovery Opportunities section for detailed exploitation guidance.

### Babuk Lineage and Code Reuse

The Babuk ransomware source code was leaked on the RAMP underground forum in September 2021. This leak included the complete source for Babuk's ESXi, NAS, and Windows lockers. Mario reuses Babuk's ESXi locker codebase with minimal modification:

- **Curve25519 implementation:** The donna implementation of Curve25519, identical to Babuk's.
- **Sosemanuk implementation:** Byte-for-byte identical to Babuk's Sosemanuk code.
- **File footer format:** The same 32-byte ephemeral public key appended to each encrypted file, in the same position and format as Babuk.
- **File targeting logic:** Similar file extension targeting and directory traversal patterns.

The primary differences between Mario and stock Babuk are:

- The addition of the MrAgent orchestration layer.
- The introduction of intermittent encryption for large files.
- Updated hardcoded attacker public keys.
- Modified ransom note content and communication channels.

**Other known Babuk derivatives** (for cross-reference during analysis):

- ESXiArgs (mass exploitation campaign, February 2023)
- Cheerscrypt
- RTM Locker
- RA Group (RA World)
- Dataf Locker
- Lock4
- Babuk Tortilla (variant with recovered keys)

**Known Babuk private keys:** The Avast Babuk decryptor release includes 14+ known Babuk private keys recovered from various sources. These keys correspond to specific original Babuk victims and the Tortilla variant. While Mario almost certainly uses different attacker keys, testing these known keys against Mario-encrypted files is a zero-cost operation that should be performed as part of any recovery effort.

---

## MrAgent Deployment Tool -- Technical Detail

MrAgent is a custom deployment and orchestration tool attributed to RansomHouse, documented in detail by Trellix and Northwave researchers in their "RansomHouse am See" publication.

### Architecture

MrAgent operates as a lightweight agent-server model:

- **Agent (MrAgent binary):** Deployed on a foothold system with network access to ESXi hosts. The agent is an ELF binary compiled for Linux.
- **C2 server:** Operated by the attacker, provides deployment instructions and receives status updates.

### Capabilities

| Capability | Description |
|------------|-------------|
| Host discovery | Enumerates ESXi hosts reachable from the deployment position |
| Credential management | Manages and applies credentials for ESXi host authentication |
| Firewall manipulation | Disables ESXi firewall rules (`esxcli network firewall set --enabled false`) |
| Binary transfer | Transfers the Mario encryptor binary to each target host |
| Configuration injection | Passes per-host parameters: target paths, encryption mode, extension, ransom note |
| Concurrent deployment | Launches encryption on multiple hosts in parallel |
| Status reporting | Reports per-host encryption status (started, in progress, complete, error) back to C2 |
| Welcome message override | Can modify the ESXi DCUI welcome message to display ransom demands on the physical console |

### Detection Opportunities

- Anomalous SSH sessions to ESXi hosts from non-administrative source IPs.
- ESXi firewall state changes (`esxcli network firewall set --enabled false`).
- Bulk VM power-off events in vCenter logs.
- New ELF binaries appearing on ESXi hosts outside of normal patching or provisioning workflows.
- Outbound network connections from ESXi hosts to non-VMware IP addresses.

---

## Joint Campaign: BianLian + White Rabbit + Mario

### Overview

Resecurity documented a coordinated extortion campaign in 2023 involving three distinct threat groups targeting the same victim organizations, referred to as the "Cyber-Extortion Trinity." The three groups are:

1. **BianLian** -- Go-based ransomware group that has shifted toward pure data extortion. Handles initial access, lateral movement, and data exfiltration.
2. **White Rabbit** -- Windows-focused ransomware linked to FIN8 (Syssphinx). Targets Windows servers and workstations.
3. **Mario (RansomHouse)** -- Targets VMware ESXi infrastructure for encryption.

### Operational Division

The campaign follows a division-of-labor model:

| Group | Role | Target |
|-------|------|--------|
| BianLian | Initial access, reconnaissance, data exfiltration | Active Directory, file servers, databases |
| White Rabbit | Windows encryption | Windows servers, workstations, application servers |
| Mario | ESXi encryption | VMware hypervisors, virtual machine disk images |

### Implications for Incident Response

- **Multiple ransom demands:** The victim may receive separate ransom demands from each group, each claiming a different scope of compromise.
- **Shared access:** If one group is detected and evicted, the others may retain independent access through separate persistence mechanisms.
- **Broader scope:** IR teams must investigate Windows, Linux, and ESXi environments concurrently. Focusing remediation on only one platform will leave the other attack vectors intact.
- **Data exfiltration assumption:** If Mario encryption is observed, assume that data exfiltration has already occurred via BianLian or another partner. This affects notification obligations and negotiation posture.

---

## Recovery Opportunities

### Primary: Intermittent Encryption Data Recovery

This is the highest-yield recovery approach for Mario-encrypted environments where the newer variant was deployed.

**Applicability:** Files >= 8 GB encrypted by the newer Mario variant (intermittent encryption mode). Most production VMDKs exceed this threshold.

**Principle:** The intermittent encryption scheme leaves significant contiguous regions of unencrypted plaintext data between encrypted blocks. These regions contain intact filesystem structures, file contents, and metadata that can be recovered through standard forensic carving techniques.

**Recovery Procedure:**

1. **Do not modify the encrypted VMDK files.** Work on forensic copies or read-only mounts.

2. **Entropy analysis:** Use a tool such as `binwalk -E` or a custom entropy scanner to map the encrypted file, identifying regions of high entropy (encrypted blocks) and low entropy (plaintext regions). This produces a block map of recoverable regions.

   ```
   # Example: generate entropy plot
   binwalk -E encrypted_file.vmdk.omario
   ```

3. **Construct a skip map:** Based on the entropy analysis, construct a skip map (or ddrescue mapfile) that identifies the byte offsets and lengths of all plaintext regions.

4. **Extract plaintext regions:** Use `dd` with skip/seek parameters or `ddrescue` with the skip map to extract only the plaintext regions into a contiguous image or set of chunks.

5. **File carving:** Run file carving tools against the extracted plaintext regions:
   - **PhotoRec** -- General-purpose file carver; effective for documents, images, databases.
   - **bulk_extractor** -- Extracts structured data (email addresses, credit card numbers, URLs) from raw disk images.
   - **foremost** -- Signature-based file carver.
   - **NTFS/ext4 metadata recovery** -- If enough MFT entries or inode tables survive in plaintext regions, filesystem structure can be partially reconstructed.

6. **VMDK-aware reconstruction:** If the VMDK descriptor file survives (it is a small text file and may not be encrypted or may fall within a plaintext gap), use it to understand the extent layout. Flat-extent references in the descriptor can help map recovered data back to its correct position within the virtual disk.

7. **Database recovery:** For database servers (SQL Server, PostgreSQL, MySQL), database page structures within plaintext regions may allow partial database reconstruction. Database-specific recovery tools should be applied to carved data.

**Expected yield:** Variable depending on the specific encryption block size and interval used by the variant. In observed cases, 60-80% of the raw file content may remain in plaintext for large VMDKs. Actual recoverable file yield depends on filesystem fragmentation, file sizes, and alignment with plaintext regions.

### Secondary: Known Babuk Key Testing

**Applicability:** All Mario-encrypted files.

**Principle:** Mario is derived from Babuk, and the Avast Babuk decryptor contains 14+ known Babuk static private keys. While the probability that Mario reuses any of these keys is very low (Mario operators almost certainly generated their own keypairs), the cost of testing is effectively zero.

**Procedure:**

1. Extract the 32-byte ephemeral public key from the footer of an encrypted file:
   ```
   # Extract last 32 bytes of encrypted file
   tail -c 32 encrypted_file.vmdk.emario > ephemeral_pubkey.bin
   ```

2. For each known Babuk private key, compute the ECDH shared secret and attempt Sosemanuk decryption of a small portion of the file.

3. Verify decryption by checking for known file signatures (e.g., VMDK magic bytes `KDMV` at offset 0, or `COWD` for COW disks).

4. If a key match is found, full decryption of all files encrypted with that key is possible.

**Tools:** The Avast Babuk decryptor can be used directly, or the key testing can be scripted using a Curve25519 library (e.g., libsodium) and the Sosemanuk reference implementation.

### Tertiary: VMDK Structure Recovery

**Applicability:** ESXi datastore environments.

- **VMDK descriptor files** are small text files (typically < 1 KB) that describe the virtual disk layout. Due to their small size, they may not be targeted by the encryptor, or they may fall entirely within a plaintext region in intermittent encryption mode. If recovered, they provide the mapping between flat-extent files and the virtual disk geometry.
- **VMX configuration files** define VM hardware configuration (CPU, memory, network, disk controller assignments). These are also small text files and may survive.
- **ESXi datastore metadata** (e.g., `.vmsd` snapshot descriptor files, `.nvram` BIOS configuration) may survive and aid in VM reconstruction.

### Quaternary: Backup and Replication Recovery

Before investing significant effort in cryptographic or carving-based recovery, verify:

- **Backup systems:** Veeam, Commvault, Veritas, or other backup solutions may have recent backup copies on storage not accessible from the ESXi management plane.
- **Replication targets:** vSphere Replication, Zerto, or SRM may have replica VMs at a secondary site.
- **Offsite/cloud copies:** Cloud-tiered backups, AWS S3 immutable copies, Azure Blob immutable storage.
- **SAN/NAS snapshots:** Storage-layer snapshots on the SAN or NAS backing the ESXi datastores may predate the encryption event.

---

## Indicators of Compromise (IOCs)

### File-Based Indicators

| Indicator | Type | Description |
|-----------|------|-------------|
| `.emario` | File extension | Encrypted file, older Mario variant |
| `.omario` | File extension | Encrypted file, newer Mario variant |
| Ransom note (text file) | File artifact | Dropped in each directory containing encrypted files; references RansomHouse Tor portal |
| MrAgent binary | ELF binary | Orchestration tool; may be found in `/tmp`, `/var/tmp`, or attacker-created directories on ESXi hosts |
| Mario encryptor | ELF binary | The encryption payload deployed by MrAgent to each ESXi host |

### Behavioral Indicators

- Mass VM power-off events in rapid succession.
- ESXi firewall disabled across multiple hosts simultaneously.
- SSH connections to ESXi hosts from unexpected source IPs.
- New ELF binaries written to ESXi local storage.
- Outbound connections from ESXi hosts to external IP addresses.
- ESXi DCUI welcome message modified to display ransom text.
- Bulk file rename operations adding `.emario` or `.omario` extensions.
- Snapshot deletion across multiple VMs in rapid succession.

### MITRE ATT&CK Mapping

| Technique ID | Technique Name | Context in Mario/RansomHouse Operations |
|---|---|---|
| T1190 | Exploit Public-Facing Application | Exploitation of ESXi OpenSLP vulnerabilities (CVE-2019-5544, CVE-2020-3992, CVE-2021-21974) for initial access to hypervisors |
| T1078 | Valid Accounts | Use of compromised ESXi root credentials or vCenter administrative accounts for hypervisor access |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | MrAgent executes ESXi shell commands for firewall disabling, VM shutdown, and encryptor execution |
| T1562.004 | Impair Defenses: Disable or Modify System Firewall | MrAgent disables the ESXi firewall via `esxcli network firewall set --enabled false` |
| T1489 | Service Stop | Forced shutdown of all running VMs to release file locks on VMDK/VMEM/VSWP files before encryption |
| T1486 | Data Encrypted for Impact | Mario encrypts VMDK, VMEM, VSWP, and LOG files using Sosemanuk + Curve25519 ECDH |
| T1490 | Inhibit System Recovery | Deletion of VM snapshots to prevent rollback-based recovery |
| T1071 | Application Layer Protocol | MrAgent C2 communication for deployment orchestration and status reporting |

### CVEs Exploited

| CVE | Product | Vulnerability | CVSS | Notes |
|-----|---------|--------------|------|-------|
| CVE-2019-5544 | VMware ESXi OpenSLP | Heap overwrite | 9.8 | Unauthenticated RCE; patched in ESXi 6.0/6.5/6.7 updates |
| CVE-2020-3992 | VMware ESXi OpenSLP | Use-after-free | 9.8 | Unauthenticated RCE; patched in ESXi 6.5/6.7/7.0 updates |
| CVE-2021-21974 | VMware ESXi OpenSLP | Heap overflow | 8.8 | Unauthenticated RCE; same vulnerability class exploited by ESXiArgs; patched in ESXi 6.5/6.7/7.0 updates |

**Mitigation note:** All three CVEs target the OpenSLP service on ESXi. Disabling SLP (`/etc/init.d/slpd stop && esxcli network firewall ruleset set -r CIMSLP -e 0`) or upgrading to ESXi 8.0 (where OpenSLP is disabled by default) eliminates this attack surface.

---

## Forensic Analysis Notes

### Extracting the Attacker's Static Public Key

The attacker's Curve25519 static public key is hardcoded in the Mario encryptor binary. Extracting it enables:

- Confirmation that all encrypted files in the environment were encrypted by the same attacker key.
- Comparison with known Babuk attacker keys to rule out key reuse.
- Potential future decryption if the attacker's private key is ever recovered (law enforcement seizure, leak, etc.).

To extract: reverse-engineer the ELF encryptor binary. The static public key is typically stored as a 32-byte constant referenced during the ECDH computation. Look for Curve25519 function calls and trace back to the hardcoded key buffer.

### Distinguishing Mario Variants

| Characteristic | Older Variant | Newer Variant |
|----------------|---------------|---------------|
| Extension | `.emario` | `.emario` or `.omario` |
| Large file handling | Full encryption | Intermittent (>= 8 GB threshold) |
| Entropy profile | Uniform high entropy | Alternating high/low entropy blocks |
| File footer | 32-byte ephemeral pubkey | 32-byte ephemeral pubkey (same format) |
| Recovery potential | Low (full encryption) | High (intermittent gaps) |

To determine which variant was deployed: run an entropy analysis on a large encrypted file. If the entropy profile shows regular alternation between high-entropy (encrypted) and low-entropy (plaintext) blocks, the newer intermittent variant was used.

### Timeline Reconstruction

Key log sources for timeline reconstruction:

- **vCenter events database:** VM power state changes, task events, user login events.
- **ESXi hostd logs:** `/var/log/hostd.log` -- VM operations, datastore access.
- **ESXi shell logs:** `/var/log/shell.log` -- Shell commands executed (may capture MrAgent commands).
- **ESXi auth logs:** `/var/log/auth.log` -- SSH authentication events.
- **ESXi vobd logs:** `/var/log/vobd.log` -- VMkernel observations, including firewall changes.
- **SAN/NAS access logs:** May show anomalous access patterns from ESXi hosts during encryption.

---

## References

1. **Unit 42 (Palo Alto Networks).** "RansomHouse Encryption Upgrade." 2024. Analysis of updated Mario encryption capabilities including intermittent encryption.

2. **Kudelski Security.** "Dissecting Babuk Ransomware Cryptography." Technical deep-dive into Babuk's Curve25519 + Sosemanuk implementation, directly applicable to Mario.

3. **SentinelOne.** "Hypervisor Ransomware -- Multiple Threat Actor Groups Hop on Leaked Babuk Code to Build ESXi Lockers." 2023. Comprehensive survey of Babuk-derived ESXi ransomware families including Mario.

4. **Resecurity.** "Ransomware Deployment Attempts: BianLian, White Rabbit, and Mario Joint Campaign." 2023. Documentation of the coordinated triple-extortion campaign.

5. **Northwave / Trellix.** "RansomHouse am See." Technical analysis of MrAgent deployment tool and RansomHouse operational procedures.

6. **CISA Advisory AA24-241A.** "Iranian Cyber Actors Targeting Critical Infrastructure Using Brute Force and RansomHouse." August 2024. Documents Iranian state-affiliated actors deploying RansomHouse tooling.

7. **CISA.** "ESXiArgs-Recover" (GitHub repository). Recovery script for ESXiArgs ransomware; techniques applicable to other Babuk-derived ESXi encryptors.

8. **Avast.** "Babuk Ransomware Decryptor." Includes 14+ recovered Babuk private keys; available for download from Avast's free decryptor tools page.

---

*End of document. For questions or updates, contact the incident response lead.*
