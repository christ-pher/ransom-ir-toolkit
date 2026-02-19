#!/usr/bin/env bash
# deploy.sh - One-command setup for the ransomware incident response toolkit
# Run this on the target forensic workstation after transferring the toolkit.
#
# Usage: ./deploy.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/venv"
VENDOR_DIR="${SCRIPT_DIR}/vendor"
CSRC_DIR="${SCRIPT_DIR}/tools/babuk_key_tester/csrc"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()    { echo -e "${CYAN}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC}   $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[FAIL]${NC} $*"; }

echo ""
echo "==========================================="
echo "  Ransomware IR Toolkit - Deployment Setup"
echo "==========================================="
echo ""

# --- Check Python ---
PYTHON=""
for candidate in python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" &>/dev/null; then
        version=$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        major=$("$candidate" -c 'import sys; print(sys.version_info.major)')
        minor=$("$candidate" -c 'import sys; print(sys.version_info.minor)')
        if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    error "Python 3.10+ is required but not found."
    error "Install Python 3.10+ and try again."
    exit 1
fi

info "Found Python: $PYTHON ($($PYTHON --version))"

# --- Create virtual environment ---
if [ -d "$VENV_DIR" ]; then
    info "Virtual environment already exists at ${VENV_DIR}"
else
    info "Creating virtual environment..."
    "$PYTHON" -m venv "$VENV_DIR"
    success "Virtual environment created at ${VENV_DIR}"
fi

# Activate venv
source "${VENV_DIR}/bin/activate"

# --- Install dependencies ---
if [ -d "$VENDOR_DIR" ] && [ "$(ls -A "$VENDOR_DIR" 2>/dev/null)" ]; then
    info "Installing vendored dependencies from ${VENDOR_DIR}..."
    pip install --no-index --find-links="$VENDOR_DIR" -r "${SCRIPT_DIR}/requirements.txt" --quiet 2>/dev/null || {
        warn "Vendored install failed, trying with internet..."
        pip install -r "${SCRIPT_DIR}/requirements.txt" --quiet
    }
else
    info "No vendored packages found. Installing from PyPI..."
    pip install -r "${SCRIPT_DIR}/requirements.txt" --quiet
fi
success "Python dependencies installed"

# --- Compile Sosemanuk C code (optional) ---
if [ -d "$CSRC_DIR" ]; then
    if command -v gcc &>/dev/null; then
        info "Compiling Sosemanuk C implementation..."
        gcc -O2 -shared -fPIC \
            -o "${CSRC_DIR}/libsosemanuk.so" \
            "${CSRC_DIR}/sosemanuk.c" 2>/dev/null && \
            success "Sosemanuk native library compiled" || \
            warn "Sosemanuk C compilation failed - will use Python fallback"
    else
        warn "gcc not found - will use Python fallback for Sosemanuk cipher"
    fi
fi

# --- Make CLI wrappers executable ---
info "Setting permissions on CLI wrappers..."
chmod +x "${SCRIPT_DIR}/scan-vmdk" \
         "${SCRIPT_DIR}/carve-vmdk" \
         "${SCRIPT_DIR}/analyze-emario" \
         "${SCRIPT_DIR}/test-babuk-keys" \
         "${SCRIPT_DIR}/analyze-whiterabbit" \
         "${SCRIPT_DIR}/qb-scan" 2>/dev/null || true
success "CLI wrappers ready"

# --- Self-test ---
info "Running self-test..."
SELF_TEST_OK=true

"$PYTHON" -c "from tools.common.entropy import calculate_entropy; assert abs(calculate_entropy(bytes(range(256))) - 8.0) < 0.01" 2>/dev/null && \
    success "  Entropy module OK" || { error "  Entropy module FAILED"; SELF_TEST_OK=false; }

"$PYTHON" -c "from tools.common.safe_io import SafeReader; print('OK')" 2>/dev/null && \
    success "  Safe I/O module OK" || { error "  Safe I/O module FAILED"; SELF_TEST_OK=false; }

"$PYTHON" -c "from tools.common.file_signatures import SIGNATURES; assert len(SIGNATURES) >= 25" 2>/dev/null && \
    success "  File signatures module OK ($(python3 -c 'from tools.common.file_signatures import SIGNATURES; print(len(SIGNATURES))') signatures)" || { error "  File signatures module FAILED"; SELF_TEST_OK=false; }

"$PYTHON" -c "from tools.common.vmdk_parser import VMDKType, find_evidence_files" 2>/dev/null && \
    success "  VMDK parser module OK" || { error "  VMDK parser module FAILED"; SELF_TEST_OK=false; }

"$PYTHON" -c "from tools.quickbooks_scanner.scanner import QuickBooksScanner" 2>/dev/null && \
    success "  QuickBooks scanner module OK" || { error "  QuickBooks scanner module FAILED"; SELF_TEST_OK=false; }

"$PYTHON" -c "from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey" 2>/dev/null && \
    success "  Cryptography library OK (X25519)" || { error "  Cryptography library FAILED"; SELF_TEST_OK=false; }

"$PYTHON" -c "import rich; print('OK')" 2>/dev/null && \
    success "  Rich library OK" || warn "  Rich library not available (degraded terminal output)"

echo ""
if [ "$SELF_TEST_OK" = true ]; then
    echo "==========================================="
    echo -e "  ${GREEN}Deployment complete!${NC}"
    echo "==========================================="
    echo ""
    echo "  Available tools:"
    echo "    ./scan-vmdk <file>              VMDK entropy analyzer"
    echo "    ./carve-vmdk <file>             VMDK data carver"
    echo "    ./qb-scan <file>               QuickBooks content scanner"
    echo "    ./analyze-emario <file|dir>     Emario header analyzer"
    echo "    ./test-babuk-keys <file|dir>    Babuk key tester"
    echo "    ./analyze-whiterabbit <dir>     White Rabbit analyzer"
    echo ""
    echo "  Or run directly:"
    echo "    source venv/bin/activate"
    echo "    python3 -m tools.vmdk_entropy_analyzer.cli --help"
    echo ""
else
    echo "==========================================="
    echo -e "  ${YELLOW}Deployment completed with warnings${NC}"
    echo "==========================================="
    echo "  Some modules failed self-test. Check errors above."
    echo ""
fi
