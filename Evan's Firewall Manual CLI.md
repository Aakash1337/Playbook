🔍-
100%
🔍+
⚊
◧
🌙
🔍
✕
⚙️
📋 Document Outline
Firewall Fantastic FunPalo Alto & Cisco FTDv
SECTION 1: PALO ALTO NETWORKS – CCDC CLI REFERENCE
SECTION 2: CISCO FTDv (Firepower Threat Defense Virtual) – CCDC CLI REFERENCE
Firewall Fantastic Fun
Palo Alto & Cisco FTDv
SECTION 1: PALO ALTO NETWORKS – CCDC CLI REFERENCE

This section is a fully consolidated Palo Alto CLI operations reference designed specifically for
CCDC environments. All commands originate from your uploaded files and have been
expanded using Palo Alto engineering documentation and TAC playbooks.

==========================
BASIC SYSTEM & HEALTH
==========================
show system info
show system resources
show system software status
show system disk-space
show system logdb-quota
show counters all
show counter global | match drop
show jobs processed

==========================
INTERFACES & ZONES
==========================
show interface all
show interface management
show arp all
set network interface ethernet <int> layer3 ip <x.x.x.x/x>
set network interface ethernet <int> layer3 zone <zone>
set zone <zone> network layer3 <interface>

==========================
ROUTING / VIRTUAL ROUTER
==========================
show routing route
show routing fib
set network virtual-router default interface <ethernet.x>
set network virtual-router default routing-table ip static-route <name> destination <subnet> nexthop <ip>

==========================
SECURITY POLICY (CLI MODE)
==========================
show running security-policy
set rulebase security rules <name> from <zone> to <zone> source <src> destination <dst> application <app> service <service> action allow
set rulebase security rules <name> log-start yes
set rulebase security rules <name> log-end yes
delete rulebase security rules <name>

==========================
ANTI-LOCKOUT RULE
==========================
set rulebase security rules MGMT-ALLOW from <mgmt-zone> to <mgmt-zone> source <trusted-ip> destination <fw-mgmt-ip> application any service application-default action allow

==========================
NAT (CRITICAL FOR CCDC)
==========================
show running nat-policy
test nat-policy-match from <src> to <dst> destination-port <port>
set rulebase nat rules <name> source-translation dynamic-ip-and-port interface-address
set rulebase nat rules <name> destination-translation translated-address <ip>

==========================
LOGGING & MONITORING
==========================
tail follow yes mp-log authd.log
tail follow yes mp-log system.log
show session info
show session all filter source <ip>
clear session all filter source <ip>

==========================
VPN / IPSEC
==========================
show vpn ike-sa
show vpn ipsec-sa
show vpn gateway
show vpn tunnel

==========================
DISABLE/ENABLE SERVICES
==========================
Disable HTTP mgmt:
set deviceconfig system service disable-http yes

Disable HTTPS mgmt:
set deviceconfig system service disable-https yes

Disable SSH:
set deviceconfig system service disable-ssh yes

Disable API:
set deviceconfig system service disable-api yes

==========================
HARDENING FOR CCDC
==========================
set deviceconfig setting session-browser-inactivity-timeout 2
set deviceconfig system service disable-telnet yes
set deviceconfig system service disable-http yes
set system setting persistent-dipp enable yes
set system setting arp-cache-timeout 900

==========================
IMPORTANT TROUBLESHOOTING
==========================
debug dataplane packet-diag set log feature flow basic
debug dataplane packet-diag clear all
debug dataplane packet-diag set filter match source <ip>
debug dataplane packet-diag set capture on
debug dataplane show cp-log
debug software restart process management-server

SECTION 2: CISCO FTDv (Firepower Threat Defense Virtual) – CCDC CLI REFERENCE

This section is a consolidated Cisco FTDv CLI handbook for rapid CCDC defense.
Includes FMC-less CLI, appliance mode, expert mode, packet tracing, NAT verification,
service lockdown, and API/GUI disable procedures.

==========================
SYSTEM / CONFIGURATION
==========================
show running-config
show interfaces
show route
show nat
show logging
show access-control-config


==========================
When open CLI it will only be a >
==========================
Enter expert mode:
expert

Disable api here

Get into a Shell:
enable (!!!!! AFTER U RUN EXPERT!!!!)

Users and fun


Enter root:
sudo su -

Change admin password:
configure user password admin

Change root password:
sudo passwd


==========================
NETWORKING
==========================
show network
configure network ipv4 manual <ip> <mask> <gw>
configure network dns servers <ip>
configure network hostname <name>

==========================
DISABLE MANAGEMENT SERVICES (CRITICAL)
==========================
Disable HTTPS GUI:
configure firewall disable-http
configure firewall disable-https

Disable REST API:
configure api-agent disable

Disable SSH:
configure ssh-access disable

Disable FMC Registration:
configure manager delete
configure manager disable

==========================
ACCESS CONTROL POLICY (CLI OPERATIONS)
==========================
show access-control-config
> Show rule positions, logging, actions

Access rule creation via FlexConfig (advanced):
configure policy-map type inspect dns
configure policy-map <policy> class <class> inspect

==========================
NAT (FTD SECTION ORDER LOGIC)
==========================
Section 1: Manual NAT (before auto)
Section 2: Auto NAT (object NAT)
Section 3: After-auto NAT

Check NAT:
show nat detail
show nat | include <object>

Packet tracing (most important tool):
packet-tracer input <int> <tcp/udp> <src-ip> <src-port> <dst-ip> <dst-port>

==========================
PACKET CAPTURE (CCDC ESSENTIAL)
==========================
capture capin interface <int> match ip host <src> host <dst>
capture capin
show capture capin

Copy capture off-box:
copy capture:capin tftp:

==========================
ASP DROP ANALYSIS
==========================
show asp drop
Common drops:
- ACL drop
- Flow offload fail
- Invalid TCP flags
- Inspection failure

==========================
DISABLE UNUSED SERVICES
==========================
configure ssh-access disable
configure api-agent disable
configure firewall disable-telnet
configure firewall disable-http
configure firewall disable-https

==========================
IPS / SNORT ENGINE
==========================
show snort status
show snort statistics
show snort memory
expert: systemctl restart snort

==========================
HARDENING FOR CCDC
==========================
configure firewall disable-telnet
configure firewall disable-http
configure firewall disable-https
configure ssh-access disable
configure manager delete
configure api-agent disable
configure network ipv6 disable

==========================
REBOOT / SERVICE RESTART
==========================
system restart
expert: systemctl restart ftd
expert: systemctl restart snort