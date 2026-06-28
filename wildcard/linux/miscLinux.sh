#!/bin/bash

#The following is random Linux stuff that has gotten points on other boxes and might get points here

#Install, enable, and configure UFW logging to high
sudo apt install ufw
sudo ufw enable
sudo ufw logging high
echo "UFW did a thing"

#Cleans out control-alt-delete.conf file if present on the system
echo "# control-alt-delete - emergency keypress handling
#
# This task is run whenever the Control-Alt-Delete key combination is
# pressed, and performs a safe reboot of the machine.
description	\"emergency keypress handling\"
author		\"Scott James Remnant <scott@netsplit.com>\"
start on control-alt-delete
task
exec false" > /etc/init/control-alt-delete.conf
echo "Finished cleaning control-alt-delete"

#Ensure root's .bashrc file has adequately large history
sed -i -e 's/^HISTSIZE=.*/HISTSIZE=1000/' -e 's/^HISTFILESIZE=.*/HISTFILESIZE=2000/' /root/.bashrc
grep -q '^HISTSIZE=' /root/.bashrc || echo 'HISTSIZE=1000' >> /root/.bashrc
grep -q '^HISTFILESIZE=' /root/.bashrc || echo 'HISTFILESIZE=2000' >> /root/.bashrc
echo "History size for /root/.bashrc is now insane"

#Clear any funky monkey aliases
for i in $(echo $(alias | grep -vi -e "alias egrep='egrep --color=auto'" -e "alias fgrep='fgrep --color=auto'" -e "alias grep='grep --color=auto'" -e "alias l='ls -CF'" -e "alias la='ls -A'" -e "alias ll='ls -alF'" -e "alias ls='ls --color=auto'" | cut -f 1 -d=) | cut -f 2 -d ' ') ; do 
	echo $(alias | grep -e $i)  >> AliasesAndFunctions.txt;
	unalias $i;
done
echo "Finished unaliasing"

#Set PATH variable in /etc/environment to known good value
sudo sed -i '/^PATH=/c\PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"' /etc/environment

