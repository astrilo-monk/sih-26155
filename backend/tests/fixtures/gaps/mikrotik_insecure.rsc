# 2026-09-30 11:02:17 by RouterOS 7.14.3
# software id = TEST-0001
#
# model = RB5009UG+S+
/interface bridge
add admin-mac=48:A9:8A:00:00:01 auto-mac=no comment=defconf name=bridge
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
add action=accept chain=input comment="allow everything to the router"
add action=accept chain=forward connection-state=established,related
add action=drop chain=forward connection-state=invalid
/ip firewall nat
add action=masquerade chain=srcnat out-interface-list=WAN
/ip service
set telnet disabled=no
set ftp disabled=yes
set www disabled=no
set api disabled=yes
set api-ssl disabled=yes
/system identity
set name=MT-BRANCH-01
/system logging action
set 0 memory-lines=2000
/user
set [ find name=admin ] password=""
