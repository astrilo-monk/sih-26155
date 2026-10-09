# MikroTik RouterOS security compliance fixture - Secure
# Representative test fixture, not a vendor-exported production configuration

/system identity set name="MT-EDGE-01"

/user group add name=auditors policy="read,winbox,ssh,ftp,reboot,policy,test,api,romon"
/user add name=netadmin group=full password=TEST-REDACTED

/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set www-ssl disabled=yes
set ssh disabled=no port=22
set api disabled=yes
set api-ssl disabled=yes

/ip ssh set strong-crypto=yes forwarding-enabled=no

/ip firewall address-list
add list=MGMT-SOURCES address=10.130.10.0/24
add list=LOG-SERVERS address=10.130.50.20
add list=NTP-SERVERS address=10.130.60.10
add list=NTP-SERVERS address=10.130.60.11

/ip firewall filter
add chain=input action=accept protocol=tcp dst-port=22 src-address-list=MGMT-SOURCES comment="Allow SSH from management"
add chain=input action=accept protocol=udp dst-port=161 src-address-list=LOG-SERVERS comment="Allow SNMP from monitoring"
add chain=input action=drop connection-state=invalid
add chain=input action=drop in-interface-list=WAN comment="Drop unsolicited WAN management"

/ip service set ssh address=10.130.10.0/24

/snmp set enabled=yes
/snmp community
add name=readonly addresses=10.130.50.20/32 read-access=yes write-access=no

/system logging action
add name=remote target=remote remote=10.130.50.20
/system logging
add topics=info action=remote
add topics=warning action=remote
add topics=error action=remote

/system ntp client set enabled=yes
/system ntp client servers
add address=10.130.60.10
add address=10.130.60.11

/system note set show-at-login=yes note="AUTHORIZED ACCESS ONLY. ACTIVITY MAY BE MONITORED."

/ip settings set ip-forward=no
/interface lldp set [find] disabled=yes

/interface ethernet
set [find default-name=ether1] comment="WAN-UPLINK"
set [find default-name=ether2] comment="SERVER-NETWORK"
