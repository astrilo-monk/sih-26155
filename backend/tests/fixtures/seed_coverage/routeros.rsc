# oct/06/2026 10:22:31 by RouterOS 7.12
/ip service
set telnet disabled=yes
set www disabled=yes
/ip ssh
set strong-crypto=yes
/ip firewall filter
add chain=input action=accept
/snmp community
set [ find default=yes ] name=public
/system logging action
add name=remote target=remote remote=192.0.2.50
/system ntp client
set primary-ntp=192.0.2.10
/system note
set show-at-login=yes note="Authorized access only."
/ip neighbor discovery-settings
/interface lldp
set [find] disabled=yes
/user
set admin password=Secret123 group=full
/ip settings
set send-redirects=no
/user aaa
set use-radius=yes
/user settings
set minimum-password-length=12
