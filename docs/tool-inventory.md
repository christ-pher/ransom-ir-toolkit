# External Tool Inventory

Tools referenced in recovery procedures. Download and vendor these for the offline toolkit where applicable.

---

## Decryptor Resources

### NoMoreRansom Project
- **URL:** https://www.nomoreransom.org/
- **Status:** No decryptor available for Mario or White Rabbit (confirmed)
- **Action:** Check periodically - new decryptors are added as keys are recovered

### Avast Babuk Decryptor
- **URL:** https://www.avast.com/ransomware-decryption-tools
- **Direct:** https://files.avast.com/files/decryptor/avast_decryptor_babuk.exe
- **Purpose:** Contains known Babuk private keys; Mario is a Babuk derivative
- **Usage:** Windows executable - extract keys from binary for use with our key tester
- **Notes:** 14+ known Babuk victim keys embedded. Our `test-babuk-keys` tool implements the same ECDH + Sosemanuk logic natively on Linux.

### Emsisoft Decryptor Collection
- **URL:** https://www.emsisoft.com/en/ransomware-decryption/
- **Status:** No Mario or White Rabbit decryptor available

### Kaspersky RakhniDecryptor / NoRansom
- **URL:** https://noransom.kaspersky.com/
- **Status:** No applicable decryptor

### Bitdefender Decryptor Collection
- **URL:** https://www.bitdefender.com/blog/labs/bitdefender-offers-free-universal-decryptor-for-revil-sodinokibi-ransomware/
- **Status:** No applicable decryptor

---

## VMDK / Disk Recovery Tools

### CISA ESXiArgs-Recover
- **URL:** https://github.com/cisagov/ESXiArgs-Recover
- **Purpose:** Recovery script for ESXiArgs ransomware (another Babuk derivative)
- **Relevance:** Similar encryption approach. The script recovers VM flat files from encrypted VMDKs by reconstructing the VMDK descriptor. May be adaptable for Mario cases where descriptors were encrypted.
- **Usage:**
  ```bash
  git clone https://github.com/cisagov/ESXiArgs-Recover.git
  cd ESXiArgs-Recover
  chmod +x recover.sh
  ./recover.sh /vmfs/volumes/datastore1/vm_name/
  ```

### PhotoRec / TestDisk
- **URL:** https://www.cgsecurity.org/wiki/PhotoRec
- **Package:** `testdisk` (includes both PhotoRec and TestDisk)
- **Purpose:** File carving from raw disk images with 300+ file signature support
- **Usage with skip maps:**
  ```bash
  # Install
  apt install testdisk  # or from source

  # Run against VMDK with our generated skip map
  photorec /d /output/carved/ /path/to/vm-flat.vmdk.emario
  ```
- **Notes:** Use our entropy analyzer's skip map output to focus PhotoRec on plaintext regions only, dramatically reducing processing time and false positives.

### qemu-nbd (QEMU Network Block Device)
- **URL:** Included with QEMU (`apt install qemu-utils`)
- **Purpose:** Mount VMDK files as block devices for analysis
- **Usage:**
  ```bash
  # Load NBD kernel module
  modprobe nbd max_part=16

  # Connect VMDK as block device
  qemu-nbd -r -c /dev/nbd0 /path/to/vm.vmdk  # -r = read-only

  # Now /dev/nbd0 is a block device, partitions at /dev/nbd0p1, etc.
  fdisk -l /dev/nbd0

  # Mount a partition read-only
  mount -o ro /dev/nbd0p1 /mnt/vmdk/

  # Disconnect when done
  qemu-nbd -d /dev/nbd0
  ```
- **Notes:** Only works with non-encrypted or partially-recovered VMDKs. Useful for examining carved/reconstructed disk images.

### ddrescue
- **URL:** https://www.gnu.org/software/ddrescue/
- **Package:** `gddrescue` (apt) or `ddrescue` (source)
- **Purpose:** Data recovery copying tool that works with our skip maps
- **Usage:**
  ```bash
  # Copy only plaintext regions from encrypted VMDK
  ddrescue --domain-mapfile=skip_map.txt \
      /path/to/encrypted.vmdk.emario \
      /output/partial_recovery.img \
      /output/ddrescue.log
  ```

### Sleuth Kit / Autopsy
- **URL:** https://www.sleuthkit.org/
- **Purpose:** Filesystem forensic analysis
- **Components:**
  - `fls` - List files and directories (including deleted)
  - `icat` - Extract file by inode number
  - `mmls` - Display partition layout
  - `fsstat` - Filesystem statistics
- **Usage:**
  ```bash
  # List partitions in a disk image
  mmls /output/partial_recovery.img

  # List files (including deleted) in a partition
  fls -r -p -o <partition_offset> /output/partial_recovery.img

  # Extract a specific file by inode
  icat -o <partition_offset> /output/partial_recovery.img <inode> > recovered_file
  ```

---

## Forensic Analysis Tools

### Volatility 3
- **URL:** https://github.com/volatilityfoundation/volatility3
- **Purpose:** Memory forensics framework
- **Relevance:** NOT applicable in this case (ESXi hosts were rebooted, Windows machine powered off)
- **Notes:** In future incidents, prioritize memory acquisition before any reboot. Ransomware keys may be recoverable from RAM.

### Eric Zimmerman Tools (Windows Forensics)
- **URL:** https://ericzimmerman.github.io/
- **Relevant tools:**
  - `MFTECmd` - Parse NTFS MFT entries recovered from carved data
  - `RECmd` - Parse Windows registry hives
  - `EvtxECmd` - Parse Windows Event Logs
  - `PECmd` - Parse Prefetch files
  - `LECmd` - Parse LNK files
- **Notes:** These run on Windows. Use Wine or a Windows forensic workstation.

### analyzeMFT
- **URL:** https://github.com/dkovar/analyzeMFT
- **Purpose:** Python-based MFT parser (runs on Linux)
- **Usage:**
  ```bash
  pip install analyzeMFT
  analyzeMFT.py -f /output/carved/MFT -o /output/mft_analysis.csv
  ```

---

## IOC and Threat Intelligence Tools

### YARA
- **URL:** https://virustotal.github.io/yara/
- **Package:** `apt install yara` or `pip install yara-python`
- **Purpose:** Pattern matching for malware identification
- **Usage with our generated rules:**
  ```bash
  yara /output/wr_iocs/white_rabbit_campaign.yar /path/to/suspicious/files/
  ```

### CyberChef
- **URL:** https://gchq.github.io/CyberChef/
- **Purpose:** Data transformation and analysis (decoding, hashing, crypto operations)
- **Notes:** Standalone HTML file, works offline. Useful for quick analysis of extracted artifacts.

---

## Python Dependencies (Vendored)

These are pre-downloaded in `vendor/` for offline installation:

| Package | Version | Purpose |
|---|---|---|
| `cryptography` | >= 41.0.0 | X25519 Curve25519 ECDH, SHA-256 for Babuk key testing |
| `rich` | >= 13.0.0 | Terminal formatting, progress bars, tables |
| `pefile` | >= 2023.2.7 | Optional: PE binary analysis for White Rabbit samples |

### Pre-downloading Wheels (build machine)
```bash
# On the build machine with internet access:
pip download -d vendor/ -r requirements.txt --python-version 3.10 --platform manylinux2014_x86_64
```

---

## Checksums

Verify tool integrity after transfer to client environment:

```bash
# Generate checksums on build machine
cd /path/to/ransom/
find . -type f -exec sha256sum {} \; > checksums.sha256

# Verify on target machine
sha256sum -c checksums.sha256
```
