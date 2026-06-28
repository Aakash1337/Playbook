#!/bin/bash

### Ubuntu 22.04.5 LTS Jammy Jellyfish

### Exit if not root

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

### 

#!/bin/bash

# Define the sources.list content
NEW_SOURCES_LIST="#deb cdrom:[Ubuntu 22.04.4 LTS _Jammy Jellyfish_ - Release amd64 (20240220)]/ jammy main restricted

# See http://help.ubuntu.com/community/UpgradeNotes for how to upgrade to
# newer versions of the distribution.
deb http://us.archive.ubuntu.com/ubuntu/ jammy main restricted
# deb-src http://us.archive.ubuntu.com/ubuntu/ jammy main restricted

## Major bug fix updates produced after the final release of the
## distribution.
deb http://us.archive.ubuntu.com/ubuntu/ jammy-updates main restricted
# deb-src http://us.archive.ubuntu.com/ubuntu/ jammy-updates main restricted

## N.B. software from this repository is ENTIRELY UNSUPPORTED by the Ubuntu
## team. Also, please note that software in universe WILL NOT receive any
## review or updates from the Ubuntu security team.
deb http://us.archive.ubuntu.com/ubuntu/ jammy universe
# deb-src http://us.archive.ubuntu.com/ubuntu/ jammy universe
deb http://us.archive.ubuntu.com/ubuntu/ jammy-updates universe
# deb-src http://us.archive.ubuntu.com/ubuntu/ jammy-updates universe

## N.B. software from this repository is ENTIRELY UNSUPPORTED by the Ubuntu 
## team, and may not be under a free licence. Please satisfy yourself as to 
## your rights to use the software. Also, please note that software in 
## multiverse WILL NOT receive any review or updates from the Ubuntu
## security team.
deb http://us.archive.ubuntu.com/ubuntu/ jammy multiverse
# deb-src http://us.archive.ubuntu.com/ubuntu/ jammy multiverse
deb http://us.archive.ubuntu.com/ubuntu/ jammy-updates multiverse
# deb-src http://us.archive.ubuntu.com/ubuntu/ jammy-updates multiverse

## N.B. software from this repository may not have been tested as
## extensively as that contained in the main release, although it includes
## newer versions of some applications which may provide useful features.
## Also, please note that software in backports WILL NOT receive any review
## or updates from the Ubuntu security team.
deb http://us.archive.ubuntu.com/ubuntu/ jammy-backports main restricted universe multiverse
# deb-src http://us.archive.ubuntu.com/ubuntu/ jammy-backports main restricted universe multiverse

deb http://security.ubuntu.com/ubuntu jammy-security main restricted
# deb-src http://security.ubuntu.com/ubuntu jammy-security main restricted
deb http://security.ubuntu.com/ubuntu jammy-security universe
# deb-src http://security.ubuntu.com/ubuntu jammy-security universe
deb http://security.ubuntu.com/ubuntu jammy-security multiverse
# deb-src http://security.ubuntu.com/ubuntu jammy-security multiverse

# This system was installed using small removable media
# (e.g. netinst, live or single CD). The matching \"deb cdrom\"
# entries were disabled at the end of the installation process.
# For information about how to configure apt package sources,
# see the sources.list(5) manual."

# Backup existing sources.list
cp /etc/apt/sources.list /etc/apt/sources.list.bak

# Replace sources.list with new content
echo "$NEW_SOURCES_LIST" | sudo tee /etc/apt/sources.list > /dev/null

## Fix resolv.conf

sh -c 'echo "nameserver 8.8.8.8" > /etc/resolv.conf'

cp /etc/skel/.bashrc /home/*/.bashrc

source ~/.bashrc

unalias -a

apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 871920D1991BC93C

# Update package lists
apt update

apt install --reinstall e2fsprogs

chattr -R = /etc/*


echo "sources.list has been updated and a backup is saved as /etc/apt/sources.list.bak"

chmod 644 /etc/shadow /etc/passwd /etc/group

sed -i 's|/bin/Bash|/bin/bash|g' /etc/passwd

rm /bin/Bash

sysctl kernel.unprivileged_userns_clone=0
sysctl net.ipv4.conf.all.rp_filter=1
sysctl kernel.dmesg_restrict=1
sysctl kernel.ctrl-alt-del=0
sysctl vm.nr_hugepages=0

sysctl -p

## change umask 022 to 077 in /etc/login.defs
## Set min pass to be 1 and max pass to be 60 in /etc/login.defs

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games:/snap/bin

sed -i '/^[^#]/d' /etc/sudoers.d/README # delete anything that's not # in readme - can hide sudoers in here

rm /etc/sysctl.d/README.conf
