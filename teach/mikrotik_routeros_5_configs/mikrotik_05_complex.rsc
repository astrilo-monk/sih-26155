# MikroTik RouterOS security compliance fixture - Complex
# Representative test fixture, not a vendor-exported production configuration

/system identity set name="MT-BORDER-COMPLEX"

/user add name=secops group=full password=TEST-REDACTED
/user add name=netops group=full password=TEST-REDACTED
/user add name=readonly group=read password=TEST-REDACTED

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
add list=OOB-MGMT address=10.150.10.0/24
add list=OOB-MGMT address=10.150.11.0/24
add list=MONITORING address=10.150.50.10
add list=MONITORING address=10.150.50.11
add list=SYSLOG address=10.150.60.10
add list=SYSLOG address=10.150.60.11
add list=NTP address=10.150.70.10
add list=NTP address=10.150.70.11

/ip firewall filter
add chain=input action=accept protocol=tcp dst-port=22 src-address-list=OOB-MGMT comment="OOB SSH"
add chain=input action=accept protocol=udp dst-port=161 src-address-list=MONITORING comment="Monitoring"
add chain=input action=drop connection-state=invalid
add chain=input action=drop src-address=10.150.0.0/16 in-interface-list=WAN
add chain=input action=drop in-interface-list=WAN comment="Default WAN drop"

/ip service set ssh address=10.150.10.0/24,10.150.11.0/24

/snmp set enabled=yes
/snmp community
add name=observe addresses=10.150.50.10/32 read-access=yes write-access=no
add name=observe2 addresses=10.150.50.11/32 read-access=yes write-access=no

/system logging action
add name=syslog1 target=remote remote=10.150.60.10
add name=syslog2 target=remote remote=10.150.60.11
/system logging
add topics=info action=syslog1
add topics=warning action=syslog1
add topics=error action=syslog2

/system ntp client set enabled=yes
/system ntp client servers
add address=10.150.70.10
add address=10.150.70.11

/system note set show-at-login=yes note="AUTHORIZED ACCESS ONLY. SECURITY EVENTS MAY BE RECORDED AND REVIEWED."

/ip settings set ip-forward=yes
/interface lldp set [find] disabled=yes

/interface ethernet
set [find default-name=ether1] comment="INTERNET-UPLINK"
set [find default-name=ether2] comment="INTERNAL-CORE"
set [find default-name=ether3] comment="SECURITY-SENSOR"
set [find default-name=ether4] comment="SERVER-FARM"
