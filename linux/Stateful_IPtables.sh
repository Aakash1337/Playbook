#!/bin/bash

SCRIPT_PATH="$(realpath "$0")"

RULES_FILE="/etc/iptables.rules"
HASH_FILE="/etc/iptables.rules.hash"
SERVICE_FILE="/etc/systemd/system/firewall-watchdog.service"

# --------------------
# Flush rules
# --------------------
flush_rules() {
    echo "Flushing iptables rules..."

    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    iptables -t nat -F
    iptables -t mangle -F
    iptables -F
    iptables -X

    echo "iptables rules flushed."
}

# --------------------
# Watchdog check
# --------------------
firewall_watchdog() {

CURRENT_HASH=$(iptables-save | sha256sum | awk '{print $1}')
KNOWN_HASH=$(cat "$HASH_FILE" 2>/dev/null | awk '{print $1}')

if [[ "$CURRENT_HASH" != "$KNOWN_HASH" ]]; then
    echo "[!] Firewall tampering detected! Restoring rules..."
    iptables-restore < "$RULES_FILE"
fi
}

# --------------------
# Install systemd watchdog
# --------------------
install_systemd_service() {

echo "Setting up systemd firewall watchdog..."

# Save rules
iptables-save > "$RULES_FILE"
chmod 600 "$RULES_FILE"

# Save hash
iptables-save | sha256sum > "$HASH_FILE"
chmod 600 "$HASH_FILE"

# Create service
cat <<EOF | sudo tee "$SERVICE_FILE" > /dev/null
[Unit]
Description=Firewall Watchdog Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do $SCRIPT_PATH watchdog; sleep 5; done'
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

# Reload + enable
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable --now firewall-watchdog.service

echo "Systemd watchdog installed and running."
}

# --------------------
# Stateful firewall
# --------------------
configure_iptables_stateful() {

echo "Applying STATEFUL firewall..."

flush_rules

iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# SSH
if [[ -z "$AUTO_SSH" ]]; then
    read -rp "Allow SSH (Y/N)? " answer
else
    answer="$AUTO_SSH"
fi

if [[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]; then
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
fi

# Ports
if [[ -z "$AUTO_PORTS" ]]; then
    read -rp "Enter ports to open (space-separated): " ports
else
    ports="$AUTO_PORTS"
fi

for port in $ports; do
    iptables -A INPUT -p tcp --dport "$port" -m conntrack --ctstate NEW -j ACCEPT
done

# Outbound
iptables -A OUTPUT -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-request -m conntrack --ctstate NEW -j ACCEPT

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

echo "Stateful firewall applied."

# Enable watchdog
if [[ -z "$AUTO_PORTS" ]]; then
    read -rp "Enable firewall watchdog (systemd)? (Y/N): " persist
    if [[ "${persist,,}" == "y" || "${persist,,}" == "yes" ]]; then
        install_systemd_service
    fi
fi
}

# --------------------
# Stateless firewall
# --------------------
configure_iptables_stateless() {

echo "Applying STATELESS firewall..."

flush_rules

iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# SSH
if [[ -z "$AUTO_SSH" ]]; then
    read -rp "Allow SSH (Y/N)? " answer
else
    answer="$AUTO_SSH"
fi

if [[ "${answer,,}" == "y" || "${answer,,}" == "yes" ]]; then
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A OUTPUT -p tcp --sport 22 -j ACCEPT
fi

# Ports
if [[ -z "$AUTO_PORTS" ]]; then
    read -rp "Enter ports to open (space-separated): " ports
else
    ports="$AUTO_PORTS"
fi

for port in $ports; do
    iptables -A INPUT -p tcp --dport "$port" -j ACCEPT
    iptables -A OUTPUT -p tcp --sport "$port" -j ACCEPT
done

# ICMP replies only
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

echo "Stateless firewall applied."

# Enable watchdog
if [[ -z "$AUTO_PORTS" ]]; then
    read -rp "Enable firewall watchdog (systemd)? (Y/N): " persist
    if [[ "${persist,,}" == "y" || "${persist,,}" == "yes" ]]; then
        install_systemd_service
    fi
fi
}

# --------------------
# CLI mode (watchdog)
# --------------------
if [[ "$1" == "watchdog" ]]; then
    firewall_watchdog
    exit 0
fi

# CLI mode (automation)
if [[ "$1" == "stateful" || "$1" == "stateless" ]]; then
    MODE="$1"
    AUTO_PORTS="$2"
    AUTO_SSH="$3"

    if [[ "$MODE" == "stateful" ]]; then
        configure_iptables_stateful
    else
        configure_iptables_stateless
    fi
    exit 0
fi

reset_firewall_system() {

echo "[!] Resetting firewall system..."

# Stop and disable watchdog
if systemctl is-active --quiet firewall-watchdog.service; then
    echo "Stopping watchdog service..."
    sudo systemctl stop firewall-watchdog.service
fi

if systemctl is-enabled --quiet firewall-watchdog.service 2>/dev/null; then
    echo "Disabling watchdog service..."
    sudo systemctl disable firewall-watchdog.service
fi

# Remove service file
if [[ -f "$SERVICE_FILE" ]]; then
    echo "Removing systemd service file..."
    sudo rm -f "$SERVICE_FILE"
fi

# Reload systemd
sudo systemctl daemon-reload

# Remove saved rules + hash
if [[ -f "$RULES_FILE" ]]; then
    echo "Removing saved rules..."
    sudo rm -f "$RULES_FILE"
fi

if [[ -f "$HASH_FILE" ]]; then
    echo "Removing saved hash..."
    sudo rm -f "$HASH_FILE"
fi

# Flush iptables completely
flush_rules

echo "[+] Firewall system reset complete."
echo "You can now configure a fresh ruleset."
}


# --------------------
# Menu
# --------------------
echo "What would you like to do?"
echo "1. Flush iptables rules"
echo "2. Disable firewalld"
echo "3. Configure Stateful firewall"
echo "4. Configure Stateless firewall"
echo "5. Reset Watchdog"
read -rp "Enter choice (1-4): " choice

case "$choice" in
    1)
        flush_rules
        ;;
    2)
        echo "Disabling firewalld..."
        systemctl disable --now firewalld
        echo "firewalld disabled."
        ;;
    3)
        configure_iptables_stateful
        ;;
    4)
        configure_iptables_stateless
        ;;
    5)
	reset_firewall_system
	;;
    *)
        echo "Invalid option."
        ;;
esac
