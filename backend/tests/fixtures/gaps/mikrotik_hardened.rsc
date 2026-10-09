# 2026-09-30 11:20:44 by RouterOS 7.14.3
# software id = TEST-0002
#
# model = RB5009UG+S+
/interface bridge
add admin-mac=48:A9:8A:00:00:02 auto-mac=no comment=defconf name=bridge
/interface list
add comment=defconf name=WAN
add comment=defconf name=LAN
/interface bridge port
add bridge=bridge comment=defconf interface=ether2
/interface list member
add comment=defconf interface=bridge list=LAN
add comment=defconf interface=ether1 list=WAN
/ip address
add address=192.168.88.1/24 comment=defconf interface=bridge network=192.168.88.0
/ip dhcp-client
add comment=defconf interface=ether1
/ip firewall filter
add action=accept chain=input comment="accept established" connection-state=established,related,untracked
add action=drop chain=input comment="drop invalid" connection-state=invalid
add action=accept chain=input comment="accept ICMP" protocol=icmp
add action=accept chain=input comment="accept from LAN" in-interface-list=LAN
add action=drop chain=input comment="drop all not coming from LAN"
add action=accept chain=forward connection-state=established,related
add action=drop chain=forward connection-state=invalid
/ip firewall nat
add action=masquerade chain=srcnat out-interface-list=WAN
/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set ssh address=192.168.88.0/24
set winbox address=192.168.88.0/24
set api disabled=yes
set api-ssl disabled=yes
/system identity
set name=MT-BRANCH-02
/system logging action
add name=remote1 remote=192.0.2.60 target=remote
/system logging
add action=remote1 topics=info
/system note
set note="Authorized access only. All activity is logged." show-at-login=yes
/system ntp client
set enabled=yes
/system ntp client servers
add address=192.0.2.123
