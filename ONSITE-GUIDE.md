# On-Site Field Reference

Quick-reference for the ransomware IR toolkit. Covers setup, every tool, and the full recovery workflow.

**Incident:** Mario (RansomHouse) on ESXi + White Rabbit (FIN8) on Windows
**No public decryptors exist for either variant.**

---

## 1. Pre-Flight Checklist

Before starting recovery work, verify:

- [ ] Forensic workstation has Python 3.10+ installed
- [ ] Evidence drives/datastores are mounted **read-only**
- [ ] Output directory is on a **separate** drive from evidence
- [ ] Chain of custody documentation is started
- [ ] Write blockers in place for any physical media
- [ ] Toolkit tarball integrity verified against checksums

```bash
# Verify toolkit integrity (run from USB or separate copy)
sha256sum -c checksums.sha256
```

---

## 2. Setup

```bash
# 1. Extract toolkit
tar xzf ransom-toolkit.tar.gz
cd ransom/

# 2. Deploy (creates venv, installs vendored deps, compiles native code, runs self-test)
./deploy.sh

# 3. Verify self-test passes — all modules should show [OK]
# If warnings about gcc: Sosemanuk will use Python fallback (slower but functional)

# 4. Create output directory on separate drive
mkdir -p /output/{entropy_results,carved_files,skip_maps,emario_analysis,key_test_results,wr_iocs,photorec_carved}
```

If deploy.sh fails on vendored install:
```bash
# Manual install from vendor/
source venv/bin/activate
pip install --no-index --find-links=vendor/ cryptography rich
pip install --no-index --find-links=vendor/ pefile  # optional
```

---

## 3. Tool Quick-Reference

### scan-vmdk — Map encrypted vs plaintext regions

```bash
# Single file scan
./scan-vmdk /path/to/vm-flat.vmdk.emario \
    --output-dir /output/entropy_results/ \
    --format text html json

# Batch scan all encrypted VMDKs in a datastore
./scan-vmdk batch /vmfs/volumes/datastore1/ \
    --output-dir /output/entropy_results/

# Output: text map (visual), HTML report, JSON (machine-readable)
# Look for recovery percentage — that's how much data is potentially recoverable
```

### carve-vmdk — Extract files from plaintext regions

```bash
# Carve files (uses entropy analysis results)
./carve-vmdk /path/to/vm-flat.vmdk.emario \
    --analysis-file /output/entropy_results/vm-flat.vmdk.emario.json \
    --output-dir /output/carved_files/ \
    --categories document database image archive

# Generate PhotoRec skip map (for deeper carving with 300+ signatures)
./carve-vmdk skip-map /path/to/vm-flat.vmdk.emario \
    --analysis-file /output/entropy_results/vm-flat.vmdk.emario.json \
    --output /output/skip_maps/vm-flat.map
```

### analyze-emario — Inspect .emario/.omario headers

```bash
# Single file
./analyze-emario /path/to/file.emario

# Batch analysis
./analyze-emario batch /vmfs/volumes/datastore1/ \
    --output-dir /output/emario_analysis/

# Key comparison across files (detect key reuse)
./analyze-emario keys /vmfs/volumes/datastore1/ \
    --output /output/emario_analysis/key_comparison.json
```

### test-babuk-keys — Test known Babuk keys

```bash
# Test all 14+ known keys against all encrypted files
./test-babuk-keys batch /vmfs/volumes/datastore1/ \
    --output-dir /output/key_test_results/ \
    --stop-on-match

# Expected: no match. But zero cost to run.
# A match = full decryption possible.
```

### analyze-whiterabbit — Extract IOCs from White Rabbit artifacts

```bash
# Parse ransom notes and extract IOCs
./analyze-whiterabbit parse /path/to/encrypted/directory/ \
    --output-dir /output/wr_iocs/ \
    --format markdown csv json yara

# Review IOC report
cat /output/wr_iocs/ioc_report.md

# Generated YARA rules for threat intel sharing
cat /output/wr_iocs/white_rabbit_campaign.yar
```

### qb-scan — Search for QuickBooks data in encrypted files

```bash
# Search for QB indicators using entropy analysis
./qb-scan search /path/to/vm-flat.vmdk.emario \
    --analysis-file /output/entropy_results/vm-flat.vmdk.emario.json \
    --output-dir /output/qb_hits/

# Search entire file without analysis (slower)
./qb-scan search /path/to/file.vbk.emario \
    --output-dir /output/qb_hits/

# Extract data windows around QB hits for manual inspection
./qb-scan extract /path/to/vm-flat.vmdk.emario \
    --analysis-file /output/entropy_results/vm-flat.vmdk.emario.json \
    --output-dir /output/qb_extracted/ \
    --window 10M
```

### Direct Python module invocation (alternative)

```bash
source venv/bin/activate
python3 -m tools.vmdk_entropy_analyzer.cli --help
python3 -m tools.vmdk_data_carver.cli --help
python3 -m tools.quickbooks_scanner.cli --help
python3 -m tools.emario_header_analyzer.cli --help
python3 -m tools.babuk_key_tester.cli --help
python3 -m tools.white_rabbit_analyzer.cli --help
```

---

## 4. QuickBooks Recovery (Top Priority)

**The client's most critical data is QuickBooks.** Company files (.QBW), backups (.QBB), transaction logs (.TLG), and interchange files (.IIF) are the primary recovery targets. QuickBooks data may live inside Mario-encrypted VMDKs and also inside Mario-encrypted Veeam backup files (.vbk/.vib/.vrb).

### QuickBooks File Types

| Extension | Format | Recovery Method |
|-----------|--------|-----------------|
| .QBW | Pervasive PSQL database (no universal magic) | `qb-scan` content search |
| .QBB | ZIP archive containing QBW | `carve-vmdk --categories quickbooks` (PK header) |
| .QBM | Portable company file | `qb-scan` content search |
| .TLG | Transaction log | `qb-scan` content search |
| .IIF | Tab-delimited text interchange | `carve-vmdk --categories quickbooks` (!TRNS/!HDR magic) |
| .OFX | Open Financial Exchange | `carve-vmdk --categories quickbooks` (OFXHEADER magic) |

### Step-by-Step QuickBooks Recovery

```bash
# 1. Scan encrypted VMDKs for entropy map
./scan-vmdk scan /path/to/vm-flat.vmdk.emario \
    --output-dir /output/entropy_results/

# 2. Carve QuickBooks files with magic-byte signatures (IIF, OFX, QBB)
./carve-vmdk carve /path/to/vm-flat.vmdk.emario \
    --analysis-file /output/entropy_results/vm-flat.vmdk.emario.json \
    --output-dir /output/carved_files/ \
    --categories quickbooks

# 2b. Validate carved QB files (filter false positives)
./qb-validate /output/carved_files/ \
    --output-dir /output/validated_qb/

# 3. Deep search for QBW/TLG files (no clean magic signature)
./qb-scan search /path/to/vm-flat.vmdk.emario \
    --analysis-file /output/entropy_results/vm-flat.vmdk.emario.json \
    --output-dir /output/qb_hits/

# 4. Extract data windows around QB hits for manual inspection
./qb-scan extract /path/to/vm-flat.vmdk.emario \
    --analysis-file /output/entropy_results/vm-flat.vmdk.emario.json \
    --output-dir /output/qb_extracted/ \
    --window 10M

# 5. Also scan Veeam backup files if present
./scan-vmdk scan /path/to/backup.vbk.emario \
    --output-dir /output/entropy_results/
./qb-scan search /path/to/backup.vbk.emario \
    --analysis-file /output/entropy_results/backup.vbk.emario.json \
    --output-dir /output/qb_hits/
```

### Where QuickBooks Files Live on Windows VMs

```
C:\Users\Public\Documents\Intuit\QuickBooks\Company Files\
C:\Users\<username>\Documents\Intuit\QuickBooks\
C:\ProgramData\Intuit\QuickBooks\
```

### Validating Recovered QuickBooks Data

- **QBB files** are ZIP archives — if recovered, unzip to get the QBW inside: `unzip recovered.qbb`
- **IIF files** are plain text — open with any text editor to verify content
- **QBW files** — look for "Intuit" and "QuickBooks" strings; valid files can be opened in QuickBooks Desktop
- **TLG files** — pair with the matching QBW for transaction replay in QuickBooks
- **Partial QBW recovery** — if the QBW is incomplete, look for the TLG (transaction log) which can replay transactions into an older QBW backup

---

## 4a. Veeam Backup Recovery

If the client used Veeam Backup & Replication, backup files may contain the QuickBooks VMs. Veeam files (.vbk full, .vib incremental, .vrb reverse incremental) can be scanned with the same entropy analysis + carving pipeline.

```bash
# 1. Find Veeam backup files
find /path/to/backups/ -name "*.vbk" -o -name "*.vib" -o -name "*.vrb" -o \
    -name "*.vbk.emario" -o -name "*.vib.emario" | sort

# 2. Scan Veeam files for encryption pattern
./scan-vmdk scan /path/to/backup.vbk.emario \
    --output-dir /output/entropy_results/

# 3. Carve recoverable files from plaintext regions
./carve-vmdk carve /path/to/backup.vbk.emario \
    --analysis-file /output/entropy_results/backup.vbk.emario.json \
    --output-dir /output/carved_files/ \
    --categories quickbooks document database

# 4. Search for QB data inside Veeam backup blocks
./qb-scan search /path/to/backup.vbk.emario \
    --analysis-file /output/entropy_results/backup.vbk.emario.json \
    --output-dir /output/qb_hits/

# 5. Batch scan all evidence files at once (VMDKs + Veeam + encrypted)
./scan-vmdk batch /path/to/evidence/ \
    --output-dir /output/entropy_results/
```

**Note:** If Veeam compression was enabled, direct carving may find fewer results — use PhotoRec with skip maps as a fallback for compressed backup blocks.

---

## 5. Recovery Workflow (Priority Order)

### P0: Intermittent Encryption Data Carving [HIGH probability]

**Why it works:** Mario uses intermittent encryption for files >8 GB. Most VMDKs are well above this, leaving 50-95% of data unencrypted.

```
Step 1: Inventory    →  find /vmfs/volumes/ -name "*.emario" -o -name "*.omario" | sort
Step 2: Scan         →  ./scan-vmdk batch <datastore> --output-dir /output/entropy_results/
Step 3: Prioritize   →  Start with largest VMDKs (highest recovery %)
Step 4: Carve        →  ./carve-vmdk <file> --analysis-file <json> --output-dir /output/carved_files/
Step 5: PhotoRec     →  Generate skip map, then run PhotoRec for 300+ file types
Step 6: Validate     →  file /output/carved_files/* — verify recovered files open correctly
```

### P1: Filesystem Metadata Recovery [MEDIUM probability]

**NTFS (Windows VMs):** Look for MFT at known offset. Search for `FILE0` signatures (hex `46 49 4C 45`) in plaintext regions.
```bash
# If MFT is recovered, parse it:
pip install --no-index --find-links=vendor/ analyzeMFT
analyzeMFT.py -f /output/carved/MFT -o /output/mft_analysis.csv
```

**ext4 (Linux VMs):** Superblock at offset 1024, magic bytes `53 EF` at offset 0x438.

### P2: Old Server Data Consolidation [CERTAIN]

```bash
find /path/to/old/server/ -type f | wc -l
du -sh /path/to/old/server/
find /path/to/old/server/ -type f -exec ls -lh {} \; > /tmp/old_data_inventory.txt
```

### P3: VMDK Structure Recovery [MEDIUM probability]

```bash
# Check for surviving descriptor files (small text, may not be encrypted)
find /vmfs/volumes/ -name "*.vmdk" -not -name "*flat*" -exec cat {} \;
```

### P4: Babuk Key Testing [VERY LOW probability, zero cost]

```bash
./analyze-emario batch /vmfs/volumes/datastore1/ --output-dir /output/emario_analysis/
./test-babuk-keys batch /vmfs/volumes/datastore1/ --output-dir /output/key_test_results/ --stop-on-match
```

### P5: Deleted File Recovery — White Rabbit [LOW probability]

```bash
# Image the Windows disk first
dc3dd if=/dev/sdX of=/output/windows_disk.dd hash=sha256 log=/output/imaging.log

# File carving
photorec /d /output/wr_recovered/ /output/windows_disk.dd

# Or filesystem-aware recovery
fls -r -p /output/windows_disk.dd > /output/file_listing.txt
```

### P6: Shadow Copy Recovery — White Rabbit [VERY LOW probability]

White Rabbit runs `vssadmin delete shadows /all /quiet`, but sometimes this fails.

```bash
vshadowinfo /output/windows_disk.dd
# If copies exist:
vshadowmount /output/windows_disk.dd /mnt/vss/
ls /mnt/vss/
```

---

## 5. Decision Tree

```
What are you looking at?
│
├── Mario-encrypted VMDK (.emario / .omario)?
│   ├── File > 8 GB?
│   │   ├── YES → P0: Entropy scan → carve plaintext regions (50-95% recovery)
│   │   │         Then: ./qb-scan to find QuickBooks data specifically
│   │   └── NO  → P4: Test Babuk keys (unlikely match), otherwise unrecoverable
│   │
│   ├── VMDK descriptor file (.vmdk, not *flat*)?
│   │   └── P3: May be unencrypted — check contents directly
│   │
│   └── Not sure about encryption mode?
│       └── Run ./analyze-emario to check header → .emario = full, .omario = intermittent
│
├── Veeam backup file (.vbk / .vib / .vrb / .vbk.emario)?
│   └── Scan with ./scan-vmdk → carve → ./qb-scan for QuickBooks data
│       (Same pipeline as VMDKs — Veeam files contain VM disk blocks)
│
├── White Rabbit encrypted file (.scrypt)?
│   ├── Windows disk available and not reimaged?
│   │   ├── YES → P5: Image disk → PhotoRec for deleted originals
│   │   └── NO  → IOC extraction only (./analyze-whiterabbit)
│   │
│   └── Shadow copies might exist?
│       └── P6: vshadowinfo to check
│
├── Unencrypted old server data?
│   └── P2: Inventory and consolidate immediately
│
└── Recovered/carved data to validate?
    └── Run `file` command, attempt to open samples, cross-reference with MFT if available
```

---

## 6. External Tools

All bundled in `external-tools/` for offline use.

### PhotoRec / TestDisk

Pre-compiled static binaries — no installation needed.

```bash
# Run PhotoRec for deep file carving (300+ signatures)
./external-tools/testdisk-7.2/photorec_static /d /output/photorec_carved/ /path/to/vmdk.emario

# Run TestDisk for partition recovery
./external-tools/testdisk-7.2/testdisk_static /path/to/disk.img

# Identify file types
./external-tools/testdisk-7.2/fidentify_static /output/carved_files/
```

### ddrescue

Source tarball included. Compile on-site if needed:

```bash
# Extract and compile (requires gcc and lzip)
cd external-tools/
lzip -d ddrescue-1.28.tar.lz    # or use tar --lzip
tar xf ddrescue-1.28.tar
cd ddrescue-1.28/
./configure && make
# Binary: ./ddrescue

# Copy only plaintext regions using our skip map
./ddrescue --domain-mapfile=/output/skip_maps/vm-flat.map \
    /path/to/encrypted.vmdk.emario \
    /output/partial_recovery.img \
    /output/ddrescue.log
```

### CISA ESXiArgs-Recover

Bash scripts for recovering ESXiArgs-encrypted VMs (similar Babuk derivative).

```bash
cd external-tools/ESXiArgs-Recover/
chmod +x recover.sh
./recover.sh /vmfs/volumes/datastore1/vm_name/
```

Reconstructs VMDK descriptors for cases where Mario encrypted the descriptor file but left the flat file partially intact.

### CyberChef

Offline data analysis — runs entirely in a browser with no server needed.

```bash
cd external-tools/
unzip CyberChef_v10.22.1.zip -d CyberChef/
# Open CyberChef/CyberChef_v10.22.1.html in any browser
```

Useful for: Base64 decoding, hex analysis, hashing, XOR, extracting strings from binary data.

### YARA (via yara-python)

Bundled in vendor/ for IOC rule scanning.

```bash
source venv/bin/activate
pip install --no-index --find-links=vendor/ yara-python
python3 -c "import yara; rule = yara.compile(filepath='/output/wr_iocs/white_rabbit_campaign.yar'); matches = rule.match('/path/to/suspect/file'); print(matches)"
```

### analyzeMFT

Bundled in vendor/ for NTFS MFT parsing.

```bash
source venv/bin/activate
pip install --no-index --find-links=vendor/ analyzeMFT
analyzeMFT.py -f /path/to/carved/MFT -o /output/mft_analysis.csv
```

---

## 7. Expected Results

### Recovery by VMDK size (Mario intermittent encryption)

| VMDK Size | Expected Recovery | Notes |
|-----------|-------------------|-------|
| < 8 GB | ~0% | Fully encrypted (.emario), not intermittent |
| 8 - 50 GB | 50 - 80% | Intermittent gaps, moderate recovery |
| 50 - 200 GB | 80 - 95% | Large plaintext regions |
| > 200 GB | 90 - 98% | Vast majority is plaintext |

### Recovery by file type (from carving)

| File Type | Recovery Quality | Notes |
|-----------|-----------------|-------|
| Documents (PDF, DOCX, XLSX) | Good | Header-based carving, file boundaries detectable |
| Databases (SQL, MDF) | Good | Large contiguous regions often survive |
| Images (JPEG, PNG) | Good | Clear signatures, bounded by EOF markers |
| Archives (ZIP, 7z) | Moderate | Must carve complete archive to decompress |
| Virtual disks (nested) | Moderate | May need reassembly |
| Executables | Low priority | Can be redownloaded/reinstalled |

### Babuk key test expectations

- **14+ known keys** tested against each file
- **Expected outcome:** No match (Mario operators use their own keys)
- **If match found:** Full decryption is possible — stop everything and decrypt

### White Rabbit recovery

- **File recovery (P5):** Depends on disk activity post-encryption. Machine was powered off = better odds.
- **Shadow copies (P6):** Usually deleted, but worth checking.
- **IOC extraction:** Always succeeds — valuable for threat intel regardless.

---

## 8. Troubleshooting

### deploy.sh fails

| Error | Fix |
|-------|-----|
| "Python 3.10+ required" | Install Python 3.10+: `apt install python3.10` |
| Vendored install fails | Run manually: `pip install --no-index --find-links=vendor/ cryptography rich` |
| gcc not found | Optional — Sosemanuk uses Python fallback. Install: `apt install gcc` |
| Permission denied on wrappers | Run: `chmod +x scan-vmdk carve-vmdk analyze-emario test-babuk-keys analyze-whiterabbit` |

### Tool errors

| Problem | Cause | Fix |
|---------|-------|-----|
| "Output directory is inside evidence path" | Safety check: output can't be on evidence drive | Use a separate drive/directory for output |
| Entropy scan shows 100% high entropy | File is fully encrypted (.emario, <8GB) | This file is not recoverable via carving — try P4 |
| Entropy scan shows 0% high entropy | File may not be encrypted | Verify with `./analyze-emario` — could be a descriptor file |
| Carver finds no files | Plaintext regions may not contain file headers | Try PhotoRec with skip map for deeper carving |
| Key tester hangs | Large file + Python Sosemanuk = slow | Compile C library: `cd tools/babuk_key_tester/csrc && gcc -O2 -shared -fPIC -o libsosemanuk.so sosemanuk.c` |
| PhotoRec: too many false positives | Scanning encrypted regions | Use skip map to limit to plaintext regions only |

### Performance

| Operation | Expected Duration | Notes |
|-----------|-------------------|-------|
| Entropy scan (100GB VMDK) | 5-15 min | Two-pass strategy, I/O bound |
| File carving (100GB VMDK) | 10-30 min | Depends on plaintext region count |
| Babuk key test (per file) | <1 min (C) / 5 min (Python) | C implementation is 10-100x faster |
| PhotoRec deep carve | 30-60 min per 100GB | CPU + I/O intensive |

### Evidence safety verification

All tools enforce read-only access. To verify:
```bash
# Check that tools open files read-only
strace -e openat ./scan-vmdk /path/to/file.emario --output-dir /tmp/test/ 2>&1 | grep emario
# Should show O_RDONLY flag only
```

---

## Quick Command Cheat Sheet

```bash
# === SETUP ===
tar xzf ransom-toolkit.tar.gz && cd ransom/ && ./deploy.sh
mkdir -p /output/{entropy_results,carved_files,skip_maps,qb_hits,qb_extracted,emario_analysis,key_test_results,wr_iocs,photorec_carved}

# === QUICKBOOKS RECOVERY (top priority) ===
# 1. Inventory all encrypted files (VMDKs + Veeam backups)
find /vmfs/volumes/ -name "*.emario" -o -name "*.omario" -o -name "*.vbk*" -exec ls -lh {} \;

# 2. Scan all evidence files (VMDKs + Veeam + encrypted)
./scan-vmdk batch /vmfs/volumes/datastore1/ --output-dir /output/entropy_results/

# 3. Carve QuickBooks files first
./carve-vmdk carve /path/to/largest.vmdk.emario \
    --analysis-file /output/entropy_results/largest.vmdk.emario.json \
    --output-dir /output/carved_files/ \
    --categories quickbooks

# 3b. Validate carved QB files (filter false positives from step 3)
./qb-validate /output/carved_files/ --output-dir /output/validated_qb/

# 4. Deep QB search (finds QBW/TLG without magic signatures)
./qb-scan search /path/to/largest.vmdk.emario \
    --analysis-file /output/entropy_results/largest.vmdk.emario.json \
    --output-dir /output/qb_hits/

# 5. Extract QB data windows for manual inspection
./qb-scan extract /path/to/largest.vmdk.emario \
    --analysis-file /output/entropy_results/largest.vmdk.emario.json \
    --output-dir /output/qb_extracted/ --window 10M

# === GENERAL DATA RECOVERY ===
# 6. Carve all file types from highest-value VMDKs
./carve-vmdk carve /path/to/largest.vmdk.emario \
    --analysis-file /output/entropy_results/largest.vmdk.emario.json \
    --output-dir /output/carved_files/ \
    --categories document database image archive

# 7. Generate skip map + run PhotoRec
./carve-vmdk skip-map /path/to/vm.vmdk.emario \
    --analysis-file /output/entropy_results/vm.vmdk.emario.json \
    --output /output/skip_maps/vm.map
./external-tools/testdisk-7.2/photorec_static /d /output/photorec_carved/ /path/to/vm.vmdk.emario

# 8. Test Babuk keys (free, run in background)
./test-babuk-keys batch /vmfs/volumes/datastore1/ --output-dir /output/key_test_results/ --stop-on-match

# === WHITE RABBIT IOCs ===
./analyze-whiterabbit parse /path/to/encrypted/ --output-dir /output/wr_iocs/ --format markdown csv json yara

# === VALIDATE ===
file /output/carved_files/*
ls -lhS /output/carved_files/ | head -20
```
