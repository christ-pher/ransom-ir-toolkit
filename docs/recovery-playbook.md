# Recovery Playbook - Dual Ransomware Incident (Mario + White Rabbit)

## Incident Summary

| Parameter | Detail |
|---|---|
| **Mario (RansomHouse)** | ESXi VMs encrypted, `.emario`/`.omario` extensions |
| **White Rabbit (FIN8)** | Windows machine encrypted, `.scrypt` extensions |
| **ESXi Hosts** | Rebooted/reinstalled - no memory forensics possible |
| **White Rabbit Machine** | Powered off - RAM not available |
| **Backups** | No VM backups survived; some old data on separate server |
| **Public Decryptors** | None available for either variant (confirmed) |

---

## Recovery Priority Matrix

| Priority | Approach | Target | Probability | Effort |
|---|---|---|---|---|
| **P0** | Intermittent encryption data carving | Mario-encrypted VMDKs | **HIGH** | Medium |
| **P1** | Filesystem metadata recovery | Mario-encrypted VMDKs | **MEDIUM** | Low |
| **P2** | Old server data consolidation | Separate server | **CERTAIN** | Low |
| **P3** | VMDK structure recovery | ESXi datastores | **MEDIUM** | Low |
| **P4** | Babuk key testing | Mario-encrypted files | **VERY LOW** | Very Low |
| **P5** | Deleted file recovery (White Rabbit) | Windows disk | **LOW** | Medium |
| **P6** | Shadow copy recovery (White Rabbit) | Windows VSS | **VERY LOW** | Low |

---

## P0: Intermittent Encryption Data Carving (PRIMARY)

**Why this works:** Mario's newer variant uses intermittent/sparse encryption for files over 8 GB. Most VMDKs are well over this threshold, meaning large portions of each VMDK remain unencrypted and contain recoverable data.

### Step 1: Inventory Encrypted VMDKs

```bash
# On the ESXi datastore, find all encrypted VMDK files
find /vmfs/volumes/ -name "*.emario" -o -name "*.omario" | sort > /tmp/encrypted_vmdk_list.txt

# Also find any surviving VMDK descriptor files
find /vmfs/volumes/ -name "*.vmdk" -not -name "*flat*" | sort > /tmp/vmdk_descriptors.txt

# Record file sizes (critical for determining encryption mode)
find /vmfs/volumes/ -name "*.emario" -o -name "*.omario" -exec ls -lh {} \; > /tmp/vmdk_sizes.txt
```

### Step 2: Deploy Toolkit

```bash
# Transfer toolkit to forensic workstation with datastore access
tar xzf ransom-toolkit.tar.gz
cd ransom/
./deploy.sh
```

### Step 3: Entropy Analysis (Map Encrypted vs. Plaintext Regions)

```bash
# Scan a single VMDK to verify the approach works
./scan-vmdk /path/to/largest-vm-flat.vmdk.emario \
    --output-dir /output/entropy_results/ \
    --format text html json

# Review the text map output - look for plaintext regions (░ characters)
# The recovery percentage tells you how much data is potentially recoverable

# If the approach works, batch-scan all VMDKs
./scan-vmdk batch /vmfs/volumes/datastore1/ \
    --output-dir /output/entropy_results/
```

**Expected results for intermittent encryption:**
- Files < 8 GB: ~0% recovery (fully encrypted)
- Files 8-50 GB: 50-80% recovery (intermittent gaps)
- Files 50-200 GB: 80-95% recovery (larger ratio of plaintext)
- Files > 200 GB: 90-98% recovery (vast majority is plaintext)

### Step 4: Data Carving

```bash
# Carve files from the largest/most valuable VMDKs first
./carve-vmdk /path/to/vm-flat.vmdk.emario \
    --analysis-file /output/entropy_results/vm-flat.vmdk.emario.json \
    --output-dir /output/carved_files/ \
    --categories document database image archive

# Generate PhotoRec skip maps for deeper carving
./carve-vmdk skip-map /path/to/vm-flat.vmdk.emario \
    --analysis-file /output/entropy_results/vm-flat.vmdk.emario.json \
    --output /output/skip_maps/vm-flat.map
```

### Step 5: PhotoRec Deep Carving (Force Multiplier)

```bash
# Use PhotoRec with the skip map for 300+ file signature support
# PhotoRec can find file types our carver doesn't cover
photorec /d /output/photorec_carved/ /path/to/vm-flat.vmdk.emario
# When prompted, select the skip map to focus on plaintext regions only
```

### Step 6: Validate and Organize Recovered Data

```bash
# Check recovered files are valid (not corrupted)
file /output/carved_files/*
# Attempt to open representative samples of each file type
# Organize by type and original VM if determinable
```

---

## P1: Filesystem Metadata Recovery

**Why this works:** NTFS MFT and ext4 inodes are typically at known offsets. Even partially encrypted, the MFT may survive and provide a complete listing of all files that existed pre-encryption.

### For Windows VMs (NTFS)
```bash
# The MFT is typically near the beginning of the NTFS volume
# Use the entropy map to find low-entropy regions near the volume start
# Look for FILE0 signatures (46 49 4C 45) in plaintext regions

# If MFT is in a plaintext region, extract it:
# 1. Find NTFS boot sector (EB 52 90 4E 54 46 53) in carved data
# 2. Read MFT cluster offset from boot sector
# 3. Extract MFT entries for file listing

# Tools: analyzeMFT, MFTECmd (Eric Zimmerman), or Autopsy
```

### For Linux VMs (ext4)
```bash
# ext4 superblock is at offset 1024 (0x400) from partition start
# Look for magic bytes 53 EF at offset 0x38 within the superblock
# Group descriptors follow, pointing to inode tables
```

---

## P2: Old Server Data Consolidation

```bash
# Inventory the separate server with old data
find /path/to/old/server/ -type f | wc -l
du -sh /path/to/old/server/

# Create an inventory for the client
find /path/to/old/server/ -type f -exec ls -lh {} \; > /tmp/old_data_inventory.txt

# Compare with any recovered file listings from P1
# Identify gaps and overlaps
```

---

## P3: VMDK Structure Recovery

**Why this works:** VMDK descriptor files are small text files that may not have been encrypted, or may exist in plaintext regions. They tell us the original VM disk layout.

```bash
# Check for surviving descriptor files
find /vmfs/volumes/ -name "*.vmdk" -not -name "*flat*" -exec cat {} \;

# Even encrypted descriptors might have the text portion in a plaintext region
# The descriptor tells us:
# - Original VM disk size
# - Extent file names and sizes
# - Disk geometry
```

---

## P4: Babuk Key Testing

**Why this works (probably won't):** Mario is derived from Babuk source code. 14+ known Babuk private keys exist from the Avast decryptor. If Mario operators reused a leaked key (unlikely but free to check), full decryption is possible.

```bash
# Analyze .emario headers first
./analyze-emario batch /vmfs/volumes/datastore1/ \
    --output-dir /output/emario_analysis/

# Review key analysis - check for any key reuse across files
./analyze-emario keys /vmfs/volumes/datastore1/ \
    --output /output/emario_analysis/key_comparison.json

# Test known Babuk keys against encrypted files
./test-babuk-keys batch /vmfs/volumes/datastore1/ \
    --output-dir /output/key_test_results/ \
    --stop-on-match

# Expected result: No match (Mario operators almost certainly use their own keys)
# But: zero cost to verify, and a match would mean full recovery
```

---

## P5: Deleted File Recovery (White Rabbit)

**Why this might work:** White Rabbit deletes the original file after encrypting it. If the original file's disk sectors haven't been overwritten, the data may be recoverable.

**Prerequisites:** The Windows disk must be imaged or mounted read-only.

```bash
# Image the Windows disk first (if not already done)
dc3dd if=/dev/sdX of=/output/windows_disk.dd hash=sha256 log=/output/imaging.log

# Run file carving on the raw disk image
photorec /d /output/wr_recovered/ /output/windows_disk.dd

# Or use Autopsy/Sleuth Kit for filesystem-aware recovery
fls -r -p /output/windows_disk.dd > /output/file_listing.txt
```

**Important:** Recovery probability depends heavily on:
- How much disk activity occurred after encryption (the machine was powered off, which is good)
- Disk utilization (more free space = better recovery chance)
- SSD vs HDD (HDD is much better for recovery due to no TRIM)

---

## P6: Shadow Copy Recovery (White Rabbit)

**Why this probably won't work:** White Rabbit runs `vssadmin delete shadows /all /quiet`. But sometimes this fails (UAC, partial execution, errors).

```bash
# Mount the Windows disk read-only
mount -o ro,loop /output/windows_disk.dd /mnt/windows/

# Check for VSS artifacts
ls -la /mnt/windows/System\ Volume\ Information/

# Use vshadowinfo/vshadowmount to check for surviving shadow copies
vshadowinfo /output/windows_disk.dd
# If any exist:
vshadowmount /output/windows_disk.dd /mnt/vss/
ls /mnt/vss/
```

---

## IOC Collection (White Rabbit)

While recovery is limited for White Rabbit, IOC extraction is valuable for threat intelligence and potential law enforcement reporting.

```bash
# Parse all ransom notes
./analyze-whiterabbit parse /path/to/encrypted/directory/ \
    --output-dir /output/wr_iocs/ \
    --format markdown csv json yara

# Review consolidated IOCs
cat /output/wr_iocs/ioc_report.md

# The YARA rules can be shared with the security community
cat /output/wr_iocs/white_rabbit_campaign.yar
```

---

## Decision Tree

```
Is the file a Mario-encrypted VMDK (.emario/.omario)?
├── YES
│   ├── Is the file > 8 GB?
│   │   ├── YES → P0: High recovery probability via intermittent encryption gaps
│   │   └── NO → P4: Test Babuk keys (low probability), otherwise unrecoverable
│   └── Run entropy analysis first to confirm encryption pattern
└── NO (White Rabbit .scrypt file)
    ├── Was the Windows machine imaged before reboot?
    │   ├── YES → P5: Attempt deleted file recovery from disk image
    │   └── NO → P6: Check for shadow copies, otherwise limited to IOC extraction
    └── IOC extraction is always valuable regardless of recovery outcome
```

---

## Success Criteria

| Metric | Target |
|---|---|
| VMDKs scanned with entropy analyzer | 100% of .emario/.omario files |
| Recovery percentage identified | Report per-VMDK |
| Files carved from plaintext regions | Maximize document/database recovery |
| Babuk keys tested | All 14+ keys against all encrypted files |
| White Rabbit IOCs extracted | All available from .scrypt.txt notes |
| Client data inventory | Complete listing of recoverable + old server data |

---

## Post-Recovery Recommendations

1. **Validate recovered data** with the client before any cleanup
2. **Preserve all evidence** - do not modify original encrypted files
3. **Document chain of custody** for all recovered data
4. **Report IOCs** to relevant ISACs and law enforcement
5. **Monitor** extracted onion URLs / BTC addresses for data publication
6. **Engage** with NoMoreRansom project - submit samples for future decryptor development
