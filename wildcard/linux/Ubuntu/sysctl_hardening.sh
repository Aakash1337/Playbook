#!/bin/bash

SYSCTL_FILE="/etc/sysctl.conf"

# Ensure script is run with sudo
if [[ "$EUID" -ne 0 ]]; then
  echo "Please run as root or use sudo."
  exit 1
fi

declare -A settings=(
  ["net.ipv4.tcp_rfc1337"]="1"
  ["net.ipv4.tcp_syncookies"]="1"
  ["net.ipv4.ip_forward"]="1"
  ["net.ipv4.conf.all.accept_source_route"]="0"
  ["net.ipv4.conf.default.accept_source_route"]="0"
  ["net.ipv4.conf.all.send_redirects"]="0"
  ["net.ipv4.conf.default.send_redirects"]="0"
  ["net.ipv4.conf.all.log_martians"]="1"
  ["net.ipv4.conf.default.rp_filter"]="1"
  ["net.ipv4.conf.all.rp_filter"]="1"
  ["net.ipv4.conf.all.accept_redirects"]="0"
  ["net.ipv4.conf.default.accept_redirects"]="0"
  ["net.ipv6.conf.all.disable_ipv6"]="1"
  ["net.ipv6.conf.default.disable_ipv6"]="1"
  ["fs.suid_dumpable"]="0"
  ["kernel.randomize_va_space"]="2"
  ["kernel.exec-shield"]="1"
)

echo "Applying sysctl hardening to $SYSCTL_FILE..."

for key in "${!settings[@]}"; do
  value="${settings[$key]}"
  if grep -qE "^$key=" "$SYSCTL_FILE"; then
    sed -i "s|^$key=.*|$key=$value|" "$SYSCTL_FILE"
  else
    echo "$key=$value" >> "$SYSCTL_FILE"
  fi
done

echo "Updated $SYSCTL_FILE"

echo "Reloading sysctl settings..."
sysctl -p "$SYSCTL_FILE"

echo "sysctl settings applied."
