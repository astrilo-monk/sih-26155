/system identity
set name=ROUTEROS-SEED-01

/ip service
set telnet disabled=no
set www disabled=yes
set ssh disabled=no

/system ntp client
set enabled=yes
set primary-ntp=198.51.100.44

/interface bridge
add name=bridge-lan
