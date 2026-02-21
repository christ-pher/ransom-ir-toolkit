# Post-Scan Next Steps: VMDK Recovery Field Guide

> Practical field reference for checking scan results on a ~150 GB VMDK and executing recovery steps.
> Keep this open on your laptop when you head back on-site.

---

## 1. Reading the Scan Results

### The Key Metric: Recovery Percentage

At **150 GB**, the VMDK falls in a sweet spot for Mario's intermittent encryption:

| File Size | Expected Plaintext | Outlook |
|-----------|-------------------|---------|
| < 8 GB | ~0% | Fully encrypted (bad) |
| 8-50 GB | 50-80% | Partial recovery |
| **50-200 GB** | **80-95%** | **Good recovery (your case)** |
| > 200 GB | 90-98% | Excellent recovery |

- **80-95% plaintext** = newer Mario variant (intermittent encryption, 8 GB threshold) -- this is the good outcome
- **~0% plaintext** = older variant (full file encryption) -- very limited recovery options

### Terminal Entropy Map

The scan produces a visual entropy map:

```
░░░░░░░██████░░░░░░░░░░░░░░████░░░░░░░░░░░░░
```

- `░` = plaintext (recoverable)
- `█` = encrypted

**Good result**: Patchwork of `░` and `█` -- intermittent encryption with large plaintext gaps.
**Bad result**: Solid `█` wall -- full encryption.

### Entropy Thresholds

| Entropy (bits/byte) | Classification |
|---------------------|---------------|
| ~8.0 (7.95-8.0) | Sosemanuk cipher output (encrypted) |
| 7.0-7.9 | Compressed data (potentially recoverable) |
| < 7.0 | Plaintext / structured binary (recoverable) |
| ~0 | Zeroed / sparse regions |

The scan uses **7.9 bits/byte** as the cutoff between encrypted and recoverable.

### Check the Output Files

Look in your output directory for:

| File | Purpose |
|------|---------|
| `*.json` | Machine-readable analysis -- **you need this for all next steps** |
| HTML report | Visual report to show the client (if `--format html` was passed) |
| Terminal text map | Quick visual overview |

**JSON summary section** has what you need:

```json
{
  "summary": {
    "total_encrypted": ...,
    "total_plaintext": ...,
    "recovery_percentage": ...,
    "encrypted_percentage": ...,
    "scan_duration_seconds": ...
  }
}
```

---

## 2. Next Steps for Positive Results

If the scan shows 80-95% plaintext, execute these in priority order. Steps 1 and 2 can run in parallel.

### Step 1 (P0): File Carving from Plaintext Regions

Primary recovery path. Uses 50+ file signatures to extract recognizable files from plaintext gaps.

```bash
./carve-vmdk carve /path/to/vm-flat.vmdk.emario \
    --analysis-file /output/vm-flat.vmdk.emario.json \
    --output-dir /output/carved/ \
    --categories document database image archive quickbooks
```

**Categories available**: document (PDF, DOCX, XLSX, PPTX, RTF), image (JPEG, PNG, GIF, BMP, TIFF), database (SQLite, NTFS MFT, ext4 superblocks), virtualization (VMDK, VHD, Veeam VBK), archive, quickbooks.

### Step 2 (P0a): QuickBooks Deep Search

Run in parallel with Step 1 if the client uses QuickBooks. QB files (`.QBW`) don't have universal magic signatures, so they need specialized scanning.

```bash
# Search for QB indicators in plaintext regions
./qb-scan search /path/to/vm-flat.vmdk.emario \
    --analysis-file /output/vm-flat.vmdk.emario.json \
    --output-dir /output/qb_hits/

# Extract data windows around any hits
./qb-scan extract /path/to/vm-flat.vmdk.emario \
    --analysis-file /output/vm-flat.vmdk.emario.json \
    --output-dir /output/qb_extracted/ \
    --window 10M
```

QB file types being searched:

| Extension | Description | Magic Signature |
|-----------|-------------|----------------|
| `.QBW` | Pervasive PSQL database (primary) | No universal magic |
| `.QBB` | ZIP archive containing QBW | `PK\x03\x04` |
| `.TLG` | Transaction log | -- |
| `.IIF` | Tab-delimited interchange | `!TRNS\t`, `!HDR\t`, `!ACCNT\t` |
| `.OFX` | Open Financial Exchange | `OFXHEADER:` |

Indicators scanned for: `Intuit`, `QuickBooks`, `QBFS`, `.QBW`, `.TLG`, `.QBB` (and lowercase variants).

### Step 3 (P1): Filesystem Metadata Recovery

If NTFS MFT entries or ext4 superblocks are recovered from plaintext regions, you can reconstruct original file/directory structure. This makes carved files more useful -- turns `recovered_00142.pdf` into something identifiable.

### Step 4 (P2): PhotoRec Deep Carve (300+ file types)

For anything the built-in carver missed. Generate a skip map so PhotoRec skips encrypted regions:

```bash
# Create skip map
./carve-vmdk skip-map /path/to/vm-flat.vmdk.emario \
    --analysis-file /output/vm-flat.vmdk.emario.json \
    --output /output/skip_maps/vm.map

# Run PhotoRec with the skip map
./external-tools/testdisk-7.2/photorec_static /d /output/photorec/ \
    /path/to/vm-flat.vmdk.emario
```

### Step 5 (P4): Babuk Key Test

Mario uses the same Sosemanuk cipher as Babuk. The toolkit has 14+ known Babuk private keys from the Avast decryptor. Low probability of a match (Mario operators use their own keys), but zero cost to try:

```bash
./test-babuk-keys /path/to/vm-flat.vmdk.emario
```

Tests all known keys against the file's ephemeral Curve25519 public key in the footer (last 32 bytes). Expected result: no match, but worth confirming.

---

## 3. What to Tell the Client

### Positive Results (80-95% plaintext)

> "The ransomware used intermittent encryption on this disk. Because the file is 150 GB, large portions were skipped by the malware, leaving recoverable data in the gaps."

> "We can extract documents, databases, images, and other recognizable files from the unencrypted regions."

> "File carving won't preserve original filenames or folder structure, but we can recover the actual content."

If they use QuickBooks:

> "We have specialized tools to search for QuickBooks data specifically, even without standard file headers."

**Set expectations:**

- Carved files lose their original names and folder paths -- they get generic names like `recovered_00142.pdf`
- Each carved file gets an entropy check -- if it's still above 7.9, it's encrypted junk and gets rejected automatically
- Recovery rate is for raw disk regions -- actual usable file recovery will be lower since files need intact headers

### Negative Results (~0% plaintext)

> "This disk was hit with full-file encryption -- the older Mario variant. Data carving from this specific file won't yield results."

**Pivot to other evidence:**

- Veeam backups (`.vbk` / `.vib` / `.vrb`) -- may also be encrypted but worth scanning
- Other VMDKs on the host
- Shadow copies (usually fails but worth checking)
- Deleted file recovery
- VMDK descriptor files (often unencrypted, contain VM disk layout metadata)

---

## 4. Pre-Visit Checklist

Before heading back on-site:

- [ ] Confirm the scan finished -- check for the JSON output file in the output directory
- [ ] Note the **plaintext %** from the report summary
- [ ] If positive, **kick off the carve immediately** -- it will take time on 150 GB
- [ ] Run the **QB scan in parallel** if QuickBooks is relevant to this client
- [ ] Generate the **HTML report** to have something visual for the client conversation
- [ ] Bring this document up on your laptop for quick command reference

### Output Directories to Check

```
/output/
  entropy_results/    # Scan results (JSON, HTML)
  carved_files/       # General file carving output
  skip_maps/          # PhotoRec skip maps
  qb_hits/            # QuickBooks indicator matches
  qb_extracted/       # QuickBooks data extractions
  key_test_results/   # Babuk key test results
```

---

## 5. Recovery Priority Reference

| Priority | Task | Notes |
|----------|------|-------|
| P0a | QuickBooks content search | Primary business target |
| P0 | General file carving (50+ signatures) | Intermittent encryption data carving |
| P1 | Filesystem metadata recovery | NTFS MFT, ext4 superblocks |
| P2 | PhotoRec deep carve | 300+ file signatures, fallback |
| P3 | VMDK descriptor file recovery | Often unencrypted |
| P4 | Babuk key testing | Low probability, zero cost |
| P5 | Deleted file recovery | White Rabbit (Windows) |
| P6 | Shadow copy recovery | Usually fails, worth checking |

---

## 6. Technical Quick Reference

**Mario/RansomHouse encryption details:**

- Stream cipher: Sosemanuk (eSTREAM portfolio, same as Babuk)
- Key exchange: Curve25519 ECDH
- Key derivation: SHA-256
- Footer: 32-byte per-file ephemeral Curve25519 public key appended
- Extensions: `.emario` (older/full or newer/intermittent), `.omario` (newer/intermittent)

**Scan two-pass strategy:**

- Pass 1 (coarse): 1 MiB blocks for fast overview
- Pass 2 (fine): 4 KiB blocks at boundaries for precision

**Available CLI tools:**

```
./scan-vmdk          # VMDK entropy analyzer
./carve-vmdk         # VMDK data carver
./qb-scan            # QuickBooks content scanner
./analyze-emario     # Emario header analyzer
./test-babuk-keys    # Babuk key tester
./analyze-whiterabbit # White Rabbit analyzer
```
