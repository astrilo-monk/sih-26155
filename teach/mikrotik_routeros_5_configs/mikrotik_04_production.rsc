# MikroTik RouterOS security compliance fixture - Production-style
# Representative test fixture, not a vendor-exported production configuration

/system identity set name="MT-DC-EDGE-01"

/user add name=automation group=full password=TEST-REDACTED
/user add name=noc group=full password=TEST-REDACTED

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
add list=OOB-MGMT address=172.16.10.0/24
add list=MONITORING address=172.16.50.10
add list=MONITORING address=172.16.50.11
add list=SYSLOG address=172.16.50.20
add list=NTP address=172.16.60.10
add list=NTP address=172.16.60.11

/ip firewall filter
add chain=input action=accept protocol=tcp dst-port=22 src-address-list=OOB-MGMT comment="OOB SSH"
add chain=input action=accept protocol=udp dst-port=161 src-address-list=MONITORING comment="SNMP"
add chain=input action=drop connection-state=invalid
add chain=input action=drop in-interface-list=WAN

/ip service set ssh address=172.16.10.0/24

/snmp set enabled=yes
/snmp community
add name=monitoring addresses=172.16.50.10/32 read-access=yes write-access=no
add name=monitoring2 addresses=172.16.50.11/32 read-access=yes write-access=no

/system logging action
add name=remote target=remote remote=172.16.50.20
/system logging
add topics=info action=remote
add topics=warning action=remote
add topics=error action=remote

/system ntp client set enabled=yes
/system ntp client servers
add address=172.16.60.10
add address=172.16.60.11

/system note set show-at-login=yes note="PRIVATE NETWORK. AUTHORIZED ADMINISTRATORS ONLY."

/ip settings set ip-forward=yes
/interface lldp set [find] disabled=yes

/interface ethernet
set [find default-name=ether1] comment="SPINE-LINK-1"
set [find default-name=ether2] comment="SPINE-LINK-2"
set [find default-name=ether3] comment="SERVER-FABRIC"
