# MikroTik RouterOS security compliance fixture - Intentionally insecure
# Representative test fixture, not a vendor-exported production configuration

/system identity set name="MT-LAB-INSECURE"

/user add name=admin group=full password=TEST-REDACTED

/ip service
set telnet disabled=no
set ftp disabled=no
set www disabled=no
set www-ssl disabled=no
set ssh disabled=no port=22
set api disabled=no
set api-ssl disabled=no

/ip firewall filter
add chain=input action=accept protocol=tcp dst-port=22
add chain=input action=accept protocol=tcp dst-port=8291
add chain=input action=accept

/snmp set enabled=yes
/snmp community
add name=public addresses=0.0.0.0/0 read-access=yes write-access=yes

# No remote logging configured.
# No NTP configuration configured.

/system note set show-at-login=yes note="LAB ROUTER"

/ip settings set ip-forward=yes
/interface lldp set [find] disabled=no

/interface ethernet
set [find default-name=ether1] comment="WAN"
