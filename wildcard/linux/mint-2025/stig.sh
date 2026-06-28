if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root. Please use sudo."
    exit 1
fi

apt install -y openscap-utils libopenscap25
apt install ssg-debderived ansible-core

ansible-playbook -i "localhost," -c local /usr/share/scap-security-guide/ansible/ubuntu2204-playbook-cis_level2_workstation.yml