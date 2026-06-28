#!/bin/bash

### Mint

### Exit if not root

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

mkdir /opt/backups
cp -r /etc/pam.d /opt/backups/pam.d

chattr = /etc/passwd
chattr = /etc/shadow
chattr = /etc/group

apt-get update
#apt-get install --reinstall libpam0g libpam-modules libpam-modules-bin libpam-runtime

# Reinstall services before editing their confs
# apt-get remove --purge <package>

# if vsftpd, check permissions of files being served and for anon access, and ssl

for pkg in fcrackzip hydra john snort wireshark remmina enum4linux pvpgn hping3 p0f arp-scan hedgewars hedgewars-data xbill hashcat nmap ophcrack sucrack changeme unworkable; do
    dpkg -s "$pkg" &>/dev/null && sudo apt remove "$pkg" -y || echo "$pkg not installed, skipping."
done

apt install rsyslog auditd unattended-upgrades libpam-pwquality -y

systemctl start rsyslog
systemctl start auditd

sed -i '/^[^#]/d' /etc/sysctl.conf

sysctl kernel.unprivileged_userns_clone=0
sysctl kernel.dmesg_restrict=1
sysctl kernel.ctrl-alt-del=0 # Kernel ignores Ctrl Alt Del
sysctl vm.nr_hugepages=0 # KVM hypervisor mitigation for non-executable page areas is enabled
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

# A secure UMASK has been configured
if grep -q "^UMASK" /etc/login.defs; then
    sed -i 's/^UMASK.*/UMASK 077/' /etc/login.defs
else
    echo "UMASK 077" >> /etc/login.defs
fi

# A secure ENCRYPT_METHOD has been configured
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
        # Insert remember=5 into the existing pam_unix.so line
        sudo sed -i '/pam_unix\.so/ s/$/ remember=5/' "$pam_file"
        echo "Appended remember=5 to existing pam_unix.so line."
    else
        echo "pam_unix.so line already contains a remember option. No change made."
    fi
else
    echo "No pam_unix.so line found in $pam_file."
fi

if command -v vsftpd >/dev/null 2>&1; then
    echo "[*] vsftpd detected. Replacing config..."
    cp /etc/vsftpd.conf /opt/backups/vsftpd.conf.bak 2>/dev/null || true
    cp ./vsftpd.conf /etc/vsftpd.conf
    systemctl restart vsftpd
else
    echo "[*] vsftpd not installed. Skipping config replacement."
fi

chmod 644 /etc/pam.d/* # Secured permissions for /etc/pam.d/common-auth
chmod 644 /lib/x86_64-linux-gnu/security/* # Secured permissionf or pam_exec.so
chmod 644 /etc/passwd /etc/group
chmod 640 /etc/shadow
chmod 600 /etc/ssh/sshd_config

chown root:shadow /etc/shadow
chown root:root /etc/passwd
chown root:root /etc/group

rm /var/spool/cron/crontabs/* # Removed unauthorized cron job

# Removed ACL on /
setfacl -R -b /

# Ubuntu automatically checks for updates daily
cp 20auto-upgrades /etc/apt/apt.conf.d/20auto-upgrades

# OpenSSH pkey auth is enabled, X11 forwarding is disabled
cp sshd_config /etc/ssh/sshd_config

# Path has been secured
cp environment /etc/environment
cp shells /etc/shells

rm /etc/sysctl.d/README.conf

cp e2scrub_all /etc/cron.d/e2scrub_all
cp lightdm.conf /etc/lightdm/lightdm.conf
cp sudoers_readme /etc/sudoers.d/README
cp sudo.conf /etc/sudo.conf
cp resolved.conf /etc/systemd/resolved.conf

# Grub bootloader password has been set
cp 40_custom /etc/grub.d/40_custom
grub-mkconfig -o /boot/grub/grub.cfg

# /usr/bin/perl no longer has CAP_SETUID
getcap -r / 2>/dev/null | awk '/cap_setuid/ {print $1}' | xargs -r -I{} setcap -r {}

find / -type f -perm -4000 2>/dev/null > setuid

# enable and start apparmor?
#firefox https only mode
# check apt sources

# passwd -l root