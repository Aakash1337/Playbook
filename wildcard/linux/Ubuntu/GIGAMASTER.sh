# Make sure the script is executable
chmod +x *

# Run all scripts in the current directory
sudo ./initialScript.sh
sudo ./users.sh
sudo ./removeBadPackages.sh
sudo ./configFirefoxPolicies.sh
sudo ./sysctl_hardening.sh
sudo ./keyperm.sh
sudo ./ssh.sh