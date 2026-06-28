#!/bin/bash

### Mint
### This script must be run as root

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

# === Section 1: Initial Backup & Permissions Reset ===
initial_backup() {
    mkdir -p /opt/backups
    cp -r /etc/pam.d /opt/backups/pam.d
    cp -r /etc/apt /opt/backups/apt

    chattr = /etc/passwd
    chattr = /etc/shadow
    chattr = /etc/group
}

# === Section 2: Package Removal & Secure Tools Install ===
package_hardening() {
    for pkg in fcrackzip hydra john snort wireshark remmina enum4linux pvpgn hping3 p0f arp-scan hedgewars hedgewars-data xbill hashcat nmap ophcrack sucrack changeme unworkable; do
        dpkg -s "$pkg" &>/dev/null && sudo apt remove "$pkg" -y || echo "$pkg not installed, skipping."
    done

    apt-get update
    apt-get upgrade

    apt install -y rsyslog auditd unattended-upgrades libpam-pwquality git

    systemctl start rsyslog
    systemctl start auditd
}

# === Section 3: Sysctl Hardening ===
sysctl_hardening() {
    sed -i '/^[^#]/d' /etc/sysctl.conf

    sysctl kernel.unprivileged_userns_clone=0
    sysctl kernel.dmesg_restrict=1
    sysctl kernel.ctrl-alt-del=0
    sysctl vm.nr_hugepages=0
    sysctl net.ipv4.tcp_rfc1337=1
    sysctl net.ipv4.tcp_syncookies=1
    sysctl net.ipv4.ip_forward=0
    sysctl net.ipv4.conf.all.accept_source_route=0
    sysctl net.ipv4.conf.default.accept_source_route=0
    sysctl net.ipv4.conf.all.send_redirects=0
    sysctl net.ipv4.conf.default.send_redirects=0
    sysctl net.ipv4.conf.all.log_martians=1
    sysctl net.ipv4.conf.default.rp_filter=1
    sysctl net.ipv4.conf.all.rp_filter=1
    sysctl net.ipv4.conf.all.accept_redirects=0
    sysctl net.ipv4.conf.default.accept_redirects=0
    sysctl net.ipv6.conf.all.disable_ipv6=1
    sysctl net.ipv6.conf.default.disable_ipv6=1
    sysctl net.ipv4.conf.all.secure_redirects=0
    sysctl net.ipv4.icmp_ignore_bogus_error_responses=1
    sysctl fs.suid_dumpable=0
    sysctl fs.protected_symlinks=1
    sysctl kernel.randomize_va_space=2
    sysctl kernel.kexec_load_disabled=1
    sysctl kernel.perf_event_paranoid=3
    sysctl kernel.kptr_restrict=2
    sysctl kernel.sysrq=0

    sysctl -p
}

# === Section 4: PAM and Password Policy ===
pam_hardening() {
    if grep -q "^UMASK" /etc/login.defs; then
        sed -i 's/^UMASK.*/UMASK 077/' /etc/login.defs
    else
        echo "UMASK 077" >> /etc/login.defs
    fi

    if grep -q "^ENCRYPT_METHOD" /etc/login.defs; then
        sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/' /etc/login.defs
    else
        echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs
    fi

    secure_pwquality='password requisite pam_pwquality.so retry=3 minlen=12 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 dictcheck=1'
    pam_file="/etc/pam.d/common-password"

    if grep -q "pam_pwquality.so" "$pam_file"; then
        sudo sed -i "s|.*pam_pwquality\\.so.*|$secure_pwquality|" "$pam_file"
        echo "Replaced existing pam_pwquality.so line."
    else
        echo "$secure_pwquality" | sudo tee -a "$pam_file" > /dev/null
        echo "Appended pam_pwquality.so line."
    fi

    if grep -q "pam_unix.so" "$pam_file"; then
        if ! grep -q "pam_unix.so.*remember=" "$pam_file"; then
            sudo sed -i '/pam_unix\.so/ s/$/ remember=5/' "$pam_file"
            echo "Appended remember=5 to existing pam_unix.so line."
        else
            echo "pam_unix.so line already contains a remember option. No change made."
        fi
    else
        echo "No pam_unix.so line found in $pam_file."
    fi
}

# === Section 5: vsftpd Config Replacement ===
vsftpd_config() {
    if command -v vsftpd >/dev/null 2>&1; then
        echo "[*] vsftpd detected. Replacing config..."
        cp /etc/vsftpd.conf /opt/backups/vsftpd.conf.bak 2>/dev/null || true
        cp ./vsftpd.conf /etc/vsftpd.conf
        systemctl restart vsftpd
    else
        echo "[*] vsftpd not installed. Skipping config replacement."
    fi
}

# === Section 6: Permissions & Cron Cleanup ===
permissions_and_cleanup() {
    chmod 644 /etc/pam.d/*
    chmod 644 /lib/x86_64-linux-gnu/security/*
    chmod 640 /etc/shadow
    chmod 644 /etc/passwd /etc/group
    chmod 600 /etc/ssh/sshd_config
    chown root:shadow /etc/shadow
    chown root:root /etc/passwd
    chown root:root /etc/group
    chown root:root /home
    rm -f /var/spool/cron/crontabs/*
    setfacl -R -b /
}

# === Section 7: Config Copying ===
copy_configs() {
    rm /etc/apt/apt.conf.d/*
    cp apt.conf.d/* /etc/apt/apt.conf.d/
    cp grub /etc/default/grub
    cp bash.bashrc /etc/bash.bashrc
    cp sshd_config /etc/ssh/sshd_config
    cp environment /etc/environment
    cp shells /etc/shells
    rm -f /etc/sysctl.d/README.conf
    cp e2scrub_all /etc/cron.d/e2scrub_all
    cp lightdm.conf /etc/lightdm/lightdm.conf
    cp sudoers_readme /etc/sudoers.d/README
    cp sudo.conf /etc/sudo.conf
    cp resolved.conf /etc/systemd/resolved.conf
    cp 40_custom /etc/grub.d/40_custom
    cp /etc/skel/.bashrc /home/*/.bashrc
    grub-mkconfig -o /boot/grub/grub.cfg
}

# === Section 8: Remove Dangerous Capabilities ===
capability_strip() {
    getcap -r / 2>/dev/null | awk '/cap_setuid/ {print $1}' | xargs -r -I{} setcap -r {}
    find / -type f -perm -4000 2>/dev/null > setuid
    grep -q '^[*][[:space:]]\+hard[[:space:]]\+nproc[[:space:]]\+2500' /etc/security/limits.conf || echo '* hard nproc 2500' | sudo tee -a /etc/security/limits.conf
}

audit_users() {
    echo "[*] Starting full user audit (with UID/shell validation)..."

    VALID_SHELLS=$(grep -vE '^#' /etc/shells)

    while IFS=: read -r username _ uid gid _ home shell; do
        [[ "$shell" == "/usr/sbin/nologin" || "$shell" == "/bin/false" ]] && continue
        [[ "$uid" -lt 1000 && "$uid" -ne 0 ]] && continue

        echo ""
        echo "----------------------------------"
        echo "User: $username"
        echo "UID : $uid"
        echo "GID : $gid"
        echo "Home: $home"
        echo "Shell: $shell"
        id "$username" 2>/dev/null || echo "⚠️ Warning: 'id' command failed for user $username"

        [[ "$uid" -eq 0 && "$username" != "root" ]] && echo "❗ WARNING: $username has UID 0 (ROOT!)"
        ! echo "$VALID_SHELLS" | grep -Fxq "$shell" && echo "❗ WARNING: $shell is not a valid shell in /etc/shells"

        echo "----------------------------------"
        echo "Choose action:"
        echo "  [d] Delete user"
        echo "  [r] Remove from specific group(s)"
        echo "  [s] Skip"
        read -e -p "[d/r/s]: " action < /dev/tty

        case "$action" in
            d|D)
                read -e -p "Are you sure you want to delete user '$username'? [y/N]: " confirm < /dev/tty
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    userdel -r "$username" && echo "User '$username' deleted."
                else
                    echo "Skipped deletion of '$username'."
                fi
                ;;
            r|R)
                groups=$(id -nG "$username" 2>/dev/null)
                echo "Current groups: $groups"
                read -e -p "Enter groups to remove (space-separated): " groups_to_remove < /dev/tty
                for grp in $groups_to_remove; do
                    gpasswd -d "$username" "$grp" && echo "Removed '$username' from '$grp'."
                done
                ;;
            *)
                echo "Skipped user '$username'."
                ;;
        esac
    done < /etc/passwd
}

# === Section 9: Optional Hardening Placeholders ===
extras() {
    echo "# Optional: Enable and start AppArmor"
    echo "# Optional: Firefox HTTPS-only mode"
    echo "# Optional: Check /etc/apt/sources.list"
    echo "# Optional: passwd -l root"
    echo "# Optional: Check LD_PRELOAD"
    echo "# Secure hosts"
}

# === Dispatcher ===
run_all() {
    initial_backup
    package_hardening
    sysctl_hardening
    pam_hardening
    vsftpd_config
    permissions_and_cleanup
    copy_configs
    capability_strip
    audit_users
    extras
}

case "$1" in
    all) run_all ;;
    initial_backup) initial_backup ;;
    package_hardening) package_hardening ;;
    sysctl_hardening) sysctl_hardening ;;
    pam_hardening) pam_hardening ;;
    vsftpd_config) vsftpd_config ;;
    permissions_and_cleanup) permissions_and_cleanup ;;
    copy_configs) copy_configs ;;
    capability_strip) capability_strip ;;
    audit_users) audit_users ;;
    extras) extras ;;
    *)
        echo "Usage: $0 {all|initial_backup|package_hardening|sysctl_hardening|pam_hardening|vsftpd_config|permissions_and_cleanup|copy_configs|capability_strip|audit_users|extras}"
        exit 1
        ;;
esac
