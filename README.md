# Ransomware Incident Response Toolkit

Custom tooling for a dual ransomware incident involving **Mario (RansomHouse)** on ESXi and **White Rabbit (FIN8)** on Windows. Built for offline deployment to a forensic workstation.

## Quick Start

```bash
# On the target forensic workstation:
tar xzf ransom-toolkit.tar.gz
cd ransom/
./deploy.sh

# Scan a Mario-encrypted VMDK for recoverable data:
./scan-vmdk /vmfs/volumes/datastore1/vm-flat.vmdk.emario --output-dir /output/

# Carve files from plaintext regions:
./carve-vmdk /path/to/vm-flat.vmdk.emario \
    --analysis-file /output/vm-flat.vmdk.emario.json \
    --output-dir /output/carved/

# Test known Babuk keys (long shot):
./test-babuk-keys batch /vmfs/volumes/datastore1/ --output-dir /output/keys/

# Extract White Rabbit IOCs:
./analyze-whiterabbit parse /path/to/encrypted/dir/ --output-dir /output/iocs/
```

## Tools

| Tool | Command | Purpose |
|------|---------|---------|
| **VMDK Entropy Analyzer** | `./scan-vmdk` | Map encrypted vs plaintext regions in Mario-encrypted VMDKs |
| **VMDK Data Carver** | `./carve-vmdk` | Extract files from unencrypted VMDK regions |
| **Emario Header Analyzer** | `./analyze-emario` | Analyze .emario file headers, detect Mario version |
| **Babuk Key Tester** | `./test-babuk-keys` | Test known Babuk private keys against encrypted files |
| **White Rabbit Analyzer** | `./analyze-whiterabbit` | Parse ransom notes, extract IOCs, analyze PE binaries |

## Recovery Strategy

**Primary approach:** Mario uses intermittent encryption for files >8GB. Most VMDKs are well above this threshold, leaving 50-95% of data unencrypted and recoverable via entropy analysis + file carving.

See [docs/recovery-playbook.md](docs/recovery-playbook.md) for the full step-by-step procedure.

## Documentation

- [Mario/RansomHouse Technical Analysis](docs/mario-ransomhouse-analysis.md)
- [White Rabbit/FIN8 Technical Analysis](docs/white-rabbit-analysis.md)
- [Recovery Playbook](docs/recovery-playbook.md)
- [External Tool Inventory](docs/tool-inventory.md)

## Requirements

- Python 3.10+
- Linux forensic workstation (SIFT, REMnux, Ubuntu, etc.)
- gcc (optional, for native Sosemanuk cipher; Python fallback available)
- No internet access required (dependencies vendored in `vendor/`)

## Deployment

Built on a development machine, transferred to the client environment:

```bash
# On build machine: vendor dependencies
pip download -d vendor/ -r requirements.txt

# Package
tar czf ransom-toolkit.tar.gz ransom/

# Transfer to target (USB, SCP, etc.)
# On target:
tar xzf ransom-toolkit.tar.gz
cd ransom/
./deploy.sh
```

## Evidence Safety

All tools enforce read-only access to evidence files:
- Files opened with `O_RDONLY` + `mmap.ACCESS_READ`
- Output written to separate directories only
- Output directories validated to be outside evidence paths
- All file access logged for audit trail
