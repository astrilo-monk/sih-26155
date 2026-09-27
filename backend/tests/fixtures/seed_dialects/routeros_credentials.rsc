# RouterOS export written for NetAuditAI tests: SNMP community and local users
/system identity set name=MT-CRED-01
/snmp set enabled=yes contact=noc
/snmp community set [ find default=yes ] name=public
/snmp community
add name=MtRoComm7 addresses=192.0.2.0/24
/user set admin password=MtAdminPw9 group=full
/user
add name=backup group=read password=MtBackupPw4
