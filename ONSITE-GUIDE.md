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

### Direct Python module invocation (alternative)

```bash
source venv/bin/activate
python3 -m tools.vmdk_entropy_analyzer.cli --help
python3 -m tools.vmdk_data_carver.cli --help
python3 -m tools.emario_header_analyzer.cli --help
python3 -m tools.babuk_key_tester.cli --help
python3 -m tools.white_rabbit_analyzer.cli --help
```

---

## 4. Recovery Workflow (Priority Order)

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
│   │   └── NO  → P4: Test Babuk keys (unlikely match), otherwise unrecoverable
│   │
│   ├── VMDK descriptor file (.vmdk, not *flat*)?
│   │   └── P3: May be unencrypted — check contents directly
│   │
│   └── Not sure about encryption mode?
│       └── Run ./analyze-emario to check header → .emario = full, .omario = intermittent
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

# === MARIO RECOVERY (do these in order) ===
# 1. Inventory
find /vmfs/volumes/ -name "*.emario" -o -name "*.omario" -exec ls -lh {} \;

# 2. Scan all VMDKs
./scan-vmdk batch /vmfs/volumes/datastore1/ --output-dir /output/entropy_results/

# 3. Carve from highest-value VMDKs first
./carve-vmdk /path/to/largest.vmdk.emario \
    --analysis-file /output/entropy_results/largest.vmdk.emario.json \
    --output-dir /output/carved_files/ \
    --categories document database image archive

# 4. Generate skip map + run PhotoRec
./carve-vmdk skip-map /path/to/vm.vmdk.emario \
    --analysis-file /output/entropy_results/vm.vmdk.emario.json \
    --output /output/skip_maps/vm.map
./external-tools/testdisk-7.2/photorec_static /d /output/photorec_carved/ /path/to/vm.vmdk.emario

# 5. Test Babuk keys (free, run in background)
./test-babuk-keys batch /vmfs/volumes/datastore1/ --output-dir /output/key_test_results/ --stop-on-match

# === WHITE RABBIT IOCs ===
./analyze-whiterabbit parse /path/to/encrypted/ --output-dir /output/wr_iocs/ --format markdown csv json yara

# === VALIDATE ===
file /output/carved_files/*
ls -lhS /output/carved_files/ | head -20
```
