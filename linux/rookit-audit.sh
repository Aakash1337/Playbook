#!/usr/bin/env bash

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

REPORT="rootkit_audit_$(hostname)_$(date +%F_%H-%M-%S).log"

# Force no pagers anywhere
export PAGER=cat
export SYSTEMD_PAGER=cat

# Redirect everything to report
exec > >(tee -a "$REPORT") 2>&1

echo "========================================="
echo " Linux Rootkit Audit - $(date)"
echo " Host: $(hostname)"
echo "========================================="
echo

# ------------------------------
# Detect Package Manager
# ------------------------------
if command -v apt >/dev/null 2>&1; then
    PKG="apt"
elif command -v dnf >/dev/null 2>&1; then
    PKG="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG="yum"
else
    echo "[!] No supported package manager found."
    exit 1
fi

echo "[+] Detected package manager: $PKG"
echo

# ------------------------------
# Install rkhunter (non-interactive)
# ------------------------------
echo "[+] Installing rkhunter..."

if [ "$PKG" = "apt" ]; then
    sudo -n apt update -y
    sudo -n apt install -y rkhunter debsums
elif [ "$PKG" = "dnf" ]; then
    sudo -n dnf install -y rkhunter
elif [ "$PKG" = "yum" ]; then
    sudo -n yum install -y rkhunter
fi

echo
echo "[+] Updating rkhunter database..."
sudo -n rkhunter --update || true

echo
echo "[+] Running rkhunter check (non-interactive)..."
sudo -n rkhunter --check --skip-keypress --nocolors || true

# ------------------------------
# Binary Integrity Check
# ------------------------------
echo
echo "========================================="
echo "[+] Checking system binary integrity"
echo "========================================="

if [ "$PKG" = "apt" ]; then
    if command -v debsums >/dev/null 2>&1; then
        echo "[+] Running debsums -s"
        sudo -n debsums -s 2>/dev/null || true
    fi
else
    echo "[+] Running rpm -Va"
    sudo -n rpm -Va | grep '^..5' || true
fi

# ------------------------------
# Check Critical Binaries
# ------------------------------
echo
echo "========================================="
echo "[+] Checking critical binaries"
echo "========================================="

CRITICAL_BINS=(
/bin/ls
/bin/ps
/bin/netstat
/usr/bin/ssh
/bin/login
/bin/bash
/usr/bin/top
)

for BIN in "${CRITICAL_BINS[@]}"; do
    if [ -f "$BIN" ]; then
        echo "---- $BIN ----"
        ls -la "$BIN"
        sha256sum "$BIN"
        echo
    else
        echo "[!] $BIN not found"
    fi
done

# ------------------------------
# Kernel Module Checks
# ------------------------------
echo
echo "========================================="
echo "[+] Loaded Kernel Modules (lsmod)"
echo "========================================="
lsmod || true

echo
echo "========================================="
echo "[+] /proc/modules"
echo "========================================="
sudo -n cat /proc/modules || true

echo
echo "========================================="
echo "[+] /sys/module listing"
echo "========================================="
sudo -n find /sys/module -maxdepth 1 -type d || true

# ------------------------------
# Compare module counts
# ------------------------------
echo
echo "========================================="
echo "[+] Comparing module counts"
echo "========================================="

LSMOD_COUNT=$(lsmod | wc -l || echo 0)
PROC_COUNT=$(cat /proc/modules | wc -l || echo 0)
SYS_COUNT=$(find /sys/module -maxdepth 1 -type d | wc -l || echo 0)

echo "lsmod count: $LSMOD_COUNT"
echo "/proc/modules count: $PROC_COUNT"
echo "/sys/module count: $SYS_COUNT"

echo
echo "========================================="
echo "[+] Audit Complete"
echo "Report saved to: $REPORT"
echo "========================================="
