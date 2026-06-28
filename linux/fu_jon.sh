#!/bin/bash
# Spam fake creds to skimmer server

# Server Killer Password: jonsuckz69

SERVER="192.168.0.100"  # Replace with skimmer server IP
PORT=9999

echo "[*] Sending 50 fake credentials to $SERVER:$PORT"
echo ""

for i in {1..50}; do
    echo "fuckjon:fuckjon:fuckjon" | nc "$SERVER" "$PORT" 2>/dev/null
    echo "[+] Sent fake cred #$i"
    sleep 0.1
done

echo ""
echo "[*] Done! Sent 50 fake credentials."