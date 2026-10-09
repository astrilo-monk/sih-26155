# MikroTik RouterOS security compliance fixture - Mixed posture
# Representative test fixture, not a vendor-exported production configuration

/system identity set name="MT-DIST-MIXED"

/user add name=netops group=full password=TEST-REDACTED

/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=no
set www-ssl disabled=yes
set ssh disabled=no port=22
set api disabled=yes
set api-ssl disabled=yes

/ip ssh set strong-crypto=yes forwarding-enabled=no

/ip firewall address-list
add list=MGMT-SOURCES address=10.140.10.0/24
add list=SYSLOG address=10.140.50.20

/ip firewall filter
add chain=input action=accept protocol=tcp dst-port=22 src-address-list=MGMT-SOURCES
add chain=input action=drop in-interface-list=WAN
add chain=input action=drop connection-state=invalid

/ip service set ssh address=10.140.10.0/24

/snmp set enabled=yes
/snmp community
add name=nms addresses=10.140.50.20/32 read-access=yes write-access=no

/system logging action
add name=remote target=remote remote=10.140.50.20
/system logging
add topics=info action=remote
add topics=error action=remote

/system ntp client set enabled=yes
/system ntp client servers
add address=10.140.60.10

/system note set show-at-login=yes note="AUTHORIZED ADMINISTRATORS ONLY."

/ip settings set ip-forward=yes
/interface lldp set [find] disabled=no

/interface ethernet
set [find default-name=ether1] comment="CORE-UPLINK"
set [find default-name=ether10] comment="INTERNET-EDGE"
