#!/bin/bash

read -p "Enter the path to your hardened sshd_config file: " CONFIG_FILE

# Check if file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "File not found: $CONFIG_FILE"
  exit 1
fi

# Backup current config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak && echo "Backup created at /etc/ssh/sshd_config.bak"

# Overwrite sshd_config
sudo cp "$CONFIG_FILE" /etc/ssh/sshd_config && echo "sshd_config has been overwritten with $CONFIG_FILE"

# Test SSH config syntax
sudo sshd -t
if [[ $? -ne 0 ]]; then
  echo "SSH config syntax error. Restoring backup."
  sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
  exit 1
fi

# Restart sshd safely
echo "Restarting sshd..."
sudo systemctl restart sshd && echo "sshd restarted successfully"
