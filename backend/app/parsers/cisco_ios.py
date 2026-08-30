import re
from typing import Optional
from app.parsers.base import BaseParser
from app.models.normalized import (
    NormalizedConfig, Vendor, Interface, VtyLine, ConsoleLine,
    LocalUser, SnmpCommunity, AclEntry, AccessList, IpsecProposal
)

class CiscoIOSParser(BaseParser):
    def parse(self, raw_config: str) -> NormalizedConfig:
        config = NormalizedConfig()
        config.raw_config = raw_config
        lines = self._index_lines(raw_config)
        config.raw_lines = lines
        
        config.device.vendor = Vendor.CISCO_IOS

        # State tracking for block parsing
        current_interface: Optional[Interface] = None
        current_vty: Optional[VtyLine] = None
        current_console: Optional[ConsoleLine] = None
        current_acl: Optional[AccessList] = None
        current_isakmp: Optional[IpsecProposal] = None
        
        in_banner_login = False
        in_banner_motd = False
        banner_login_char = ""
        banner_motd_char = ""
        banner_login_text = []
        banner_motd_text = []

        for i, original_line in enumerate(lines):
            line_num = i + 1
            line = original_line.strip()

            if not line:
                continue
            
            # --- Banners ---
            if in_banner_login:
                if banner_login_char and banner_login_char in line:
                    in_banner_login = False
                    banner_login_text.append(line.split(banner_login_char)[0])
                    config.banners.login_banner = "\n".join(banner_login_text)
                else:
                    banner_login_text.append(original_line)
                config.banners.source_lines.append(line_num)
                continue

            if in_banner_motd:
                if banner_motd_char and banner_motd_char in line:
                    in_banner_motd = False
                    banner_motd_text.append(line.split(banner_motd_char)[0])
                    config.banners.motd_banner = "\n".join(banner_motd_text)
                else:
                    banner_motd_text.append(original_line)
                config.banners.source_lines.append(line_num)
                continue
            
            if line.startswith('!'):
                # Reset context blocks
                current_interface = current_vty = current_console = current_acl = current_isakmp = None
                continue

            # --- Device Info ---
            m = re.match(r'^hostname\s+(\S+)', line)
            if m:
                config.device.hostname = m.group(1)
                config.device.source_lines.append(line_num)
                continue
            
            m = re.match(r'^version\s+([\w\.]+)', line)
            if m:
                config.device.os_version = m.group(1)
                config.device.source_lines.append(line_num)
                continue

            # --- Services (Global) ---
            if line == "ip source-route":
                config.services.ip_source_route = True
                config.services.source_lines.append(line_num)
                continue
            if line == "no ip source-route":
                config.services.ip_source_route = False
                config.services.source_lines.append(line_num)
                continue
            if line == "cdp run":
                config.services.cdp_globally_enabled = True
                config.services.source_lines.append(line_num)
                continue
            if line == "no cdp run":
                config.services.cdp_globally_enabled = False
                config.services.source_lines.append(line_num)
                continue
            if line == "service password-encryption":
                config.services.password_encryption = True
                config.services.source_lines.append(line_num)
                config.authentication.password_encryption_service = True
                config.authentication.source_lines.append(line_num)
                continue

            # --- Management Access & SSH/HTTP ---
            m = re.match(r'^ip ssh version\s+(\d)', line)
            if m:
                config.management.ssh_enabled = True
                config.management.ssh_version = int(m.group(1))
                config.management.source_lines.append(line_num)
                continue
            
            m = re.match(r'^ip ssh time-out\s+(\d+)', line)
            if m:
                config.management.ssh_timeout = int(m.group(1))
                config.management.source_lines.append(line_num)
                continue
            
            m = re.match(r'^ip ssh authentication-retries\s+(\d+)', line)
            if m:
                config.management.ssh_retries = int(m.group(1))
                config.management.source_lines.append(line_num)
                continue

            if line == "ip http server":
                config.management.http_enabled = True
                config.management.source_lines.append(line_num)
                continue
            if line == "no ip http server":
                config.management.http_enabled = False
                config.management.source_lines.append(line_num)
                continue
            if line == "ip http secure-server":
                config.management.https_enabled = True
                config.management.source_lines.append(line_num)
                continue

            # --- Authentication (Global) ---
            if line == "aaa new-model":
                config.authentication.aaa_enabled = True
                config.authentication.source_lines.append(line_num)
                continue
            
            m = re.match(r'^aaa authentication login\s+(.*)', line)
            if m:
                config.authentication.aaa_auth_methods.append(m.group(1))
                config.authentication.source_lines.append(line_num)
                continue

            m = re.match(r'^enable (secret|password)(?:\s+(\d))?\s+(\S+)', line)
            if m:
                pass_type = m.group(1) # secret or password
                level = m.group(2)
                
                type_str = pass_type
                if level == "0": type_str = "plaintext"
                elif level == "5": type_str = "type5_md5"
                elif level == "7": type_str = "type7"
                elif level == "8": type_str = "type8_sha256"
                elif level == "9": type_str = "type9_scrypt"
                
                config.authentication.enable_password_type = type_str
                config.authentication.source_lines.append(line_num)
                continue

            # Local Users
            m = re.match(r'^username\s+(\S+)(?:\s+privilege\s+(\d+))?\s+(secret|password)(?:\s+(\d))?\s+(\S+)', line)
            if m:
                usr = m.group(1)
                priv = int(m.group(2)) if m.group(2) else None
                sec_or_pass = m.group(3)
                level = m.group(4)
                
                type_str = sec_or_pass
                if level == "0": type_str = "plaintext"
                elif level == "5": type_str = "type5_md5"
                elif level == "7": type_str = "type7"
                elif level == "8": type_str = "type8_sha256"
                elif level == "9": type_str = "type9_scrypt"
                
                user = LocalUser(username=usr, privilege=priv, password_type=type_str)
                user.source_lines.append(line_num)
                config.authentication.local_users.append(user)
                continue
            
            # --- SNMP ---
            m = re.match(r'^snmp-server community\s+(\S+)\s+(RO|RW)(?:\s+(\S+))?', line)
            if m:
                config.snmp.enabled = True
                comm = SnmpCommunity(name=m.group(1), permission=m.group(2), acl=m.group(3))
                comm.source_lines.append(line_num)
                config.snmp.communities.append(comm)
                config.snmp.source_lines.append(line_num)
                continue

            if line.startswith("snmp-server group") and " v3 " in line:
                config.snmp.enabled = True
                config.snmp.v3_configured = True
                config.snmp.source_lines.append(line_num)
                continue

            # --- Logging ---
            m = re.match(r'^logging buffered(?:\s+(\d+))?', line)
            if m:
                config.logging.buffered = True
                if m.group(1):
                    config.logging.buffer_size = int(m.group(1))
                config.logging.source_lines.append(line_num)
                continue
            
            m = re.match(r'^logging host\s+(\S+)|logging\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
            if m:
                host = m.group(1) or m.group(2)
                if host:
                    config.logging.remote_hosts.append(host)
                config.logging.source_lines.append(line_num)
                continue

            m = re.match(r'^logging trap\s+(\S+)', line)
            if m:
                config.logging.trap_level = m.group(1)
                config.logging.source_lines.append(line_num)
                continue

            if "service timestamps log datetime msec" in line:
                config.logging.timestamps_enabled = True
                config.logging.timestamps_msec = True
                config.logging.source_lines.append(line_num)
                continue
            elif "service timestamps log" in line:
                config.logging.timestamps_enabled = True
                config.logging.source_lines.append(line_num)
                continue

            # --- NTP ---
            m = re.match(r'^ntp server\s+(\S+)', line)
            if m:
                config.ntp.servers.append(m.group(1))
                config.ntp.source_lines.append(line_num)
                continue
            if line.startswith("ntp authenticate"):
                config.ntp.authentication_enabled = True
                config.ntp.source_lines.append(line_num)
                continue

            # --- Old Style ACLs ---
            m = re.match(r'^access-list\s+(\d+)\s+(permit|deny)\s+(.*?)$', line)
            if m:
                acl_id = m.group(1)
                action = m.group(2)
                rest = m.group(3)
                
                # Check if it exists
                acl = next((a for a in config.access_lists if a.name == acl_id), None)
                if not acl:
                    acl_type = "extended" if (100 <= int(acl_id) <= 199) or (2000 <= int(acl_id) <= 2699) else "standard"
                    acl = AccessList(name=acl_id, acl_type=acl_type)
                    config.access_lists.append(acl)
                
                acl.source_lines.append(line_num)
                entry = AclEntry(action=action)
                entry.source_lines.append(line_num)
                if acl.acl_type == "standard":
                    entry.source = rest
                else:
                    protocol, source, destination = self._parse_extended_acl_rest(rest)
                    entry.protocol = protocol
                    entry.source = source
                    entry.destination = destination
                acl.entries.append(entry)
                continue

            # --- Block Entrances ---
            # Banner
            m = re.match(r'^banner (login|motd)\s+(.)$', line)
            if m:
                current_interface = current_vty = current_console = current_acl = current_isakmp = None
                if m.group(1) == "login":
                    in_banner_login = True
                    banner_login_char = m.group(2)
                    config.banners.source_lines.append(line_num)
                else:
                    in_banner_motd = True
                    banner_motd_char = m.group(2)
                    config.banners.source_lines.append(line_num)
                continue

            # Interfaces
            m = re.match(r'^interface\s+(.*)', line)
            if m:
                current_interface = Interface(name=m.group(1))
                current_interface.source_lines.append(line_num)
                config.interfaces.append(current_interface)
                current_vty = current_console = current_acl = current_isakmp = None
                continue
            
            # VTY
            m = re.match(r'^line vty\s+(.*)', line)
            if m:
                current_vty = VtyLine(line_range=m.group(1))
                current_vty.source_lines.append(line_num)
                config.management.vty_lines.append(current_vty)
                current_interface = current_console = current_acl = current_isakmp = None
                continue
            
            # Console
            m = re.match(r'^line con\s+0', line)
            if m:
                if not config.management.console:
                    config.management.console = ConsoleLine()
                current_console = config.management.console
                current_console.source_lines.append(line_num)
                current_interface = current_vty = current_acl = current_isakmp = None
                continue

            # Named ACL
            m = re.match(r'^ip access-list (standard|extended)\s+(.*)', line)
            if m:
                current_acl = AccessList(name=m.group(2), acl_type=m.group(1))
                current_acl.source_lines.append(line_num)
                config.access_lists.append(current_acl)
                current_interface = current_vty = current_console = current_isakmp = None
                continue

            # Crypto ISAKMP
            m = re.match(r'^crypto isakmp policy\s+(\d+)', line)
            if m:
                current_isakmp = IpsecProposal(name=f"isakmp-{m.group(1)}")
                current_isakmp.source_lines.append(line_num)
                config.vpn.ipsec_proposals.append(current_isakmp)
                current_interface = current_vty = current_console = current_acl = None
                continue
            
            # Crypto IPSEC Transform Set
            m = re.match(r'^crypto ipsec transform-set\s+(\S+)\s+(.*)', line)
            if m:
                current_interface = current_vty = current_console = current_acl = current_isakmp = None
                prop = IpsecProposal(name=m.group(1))
                prop.encryption = m.group(2)
                prop.source_lines.append(line_num)
                config.vpn.ipsec_proposals.append(prop)
                continue

            # --- Inside Blocks ---
            
            # Interface contents
            if current_interface and original_line.startswith((' ', '\t')):
                current_interface.source_lines.append(line_num)
                
                m_ip = re.match(r'^ip address\s+([0-9\.]+)\s+([0-9\.]+)', line)
                if m_ip:
                    current_interface.ip_address = m_ip.group(1)
                    current_interface.subnet_mask = m_ip.group(2)
                    continue
                
                if line.startswith("description"):
                    current_interface.description = line[12:].strip()
                    continue
                
                if line == "shutdown":
                    current_interface.shutdown = True
                    continue
                elif line == "no shutdown":
                    current_interface.shutdown = False
                    continue
                
                if line == "no cdp enable":
                    current_interface.cdp_enabled = False
                    continue
                elif line == "cdp enable":
                    current_interface.cdp_enabled = True
                    continue
                
                m_acl = re.match(r'^ip access-group\s+(\S+)\s+(in|out)', line)
                if m_acl:
                    if m_acl.group(2) == "in":
                        current_interface.acl_in = m_acl.group(1)
                    else:
                        current_interface.acl_out = m_acl.group(1)
                    continue
                continue

            # VTY contents
            if current_vty and original_line.startswith((' ', '\t')):
                current_vty.source_lines.append(line_num)
                
                m_acc = re.match(r'^access-class\s+(\S+)', line)
                if m_acc:
                    current_vty.access_class = m_acc.group(1)
                    continue
                
                m_trans = re.match(r'^transport input\s+(.*)', line)
                if m_trans:
                    current_vty.transport_input = m_trans.group(1).split()
                    if "telnet" in current_vty.transport_input or "all" in current_vty.transport_input:
                        config.management.telnet_enabled = True
                    continue
                
                m_exec = re.match(r'^exec-timeout\s+(\d+)(?:\s+(\d+))?', line)
                if m_exec:
                    current_vty.exec_timeout_minutes = int(m_exec.group(1))
                    current_vty.exec_timeout_seconds = int(m_exec.group(2)) if m_exec.group(2) else 0
                    continue
                
                m_login = re.match(r'^login\s+(.*)', line)
                if m_login:
                    current_vty.login_method = m_login.group(1)
                    continue
                elif line == "login":
                    current_vty.login_method = "login"
                    continue
                continue

            # Console contents
            if current_console and original_line.startswith((' ', '\t')):
                current_console.source_lines.append(line_num)
                
                m_exec = re.match(r'^exec-timeout\s+(\d+)(?:\s+(\d+))?', line)
                if m_exec:
                    current_console.exec_timeout_minutes = int(m_exec.group(1))
                    current_console.exec_timeout_seconds = int(m_exec.group(2)) if m_exec.group(2) else 0
                    continue
                
                m_login = re.match(r'^login\s+(.*)', line)
                if m_login:
                    current_console.login_method = m_login.group(1)
                    continue
                elif line == "login":
                    current_console.login_method = "login"
                    continue
                continue
            
            # ACL contents
            if current_acl and original_line.startswith((' ', '\t')):
                current_acl.source_lines.append(line_num)
                
                m_entry = re.match(r'^(permit|deny)\s+(.*?)$', line)
                if m_entry:
                    entry = AclEntry(action=m_entry.group(1))
                    entry.source_lines.append(line_num)
                    
                    rest = m_entry.group(2)
                    if " log" in rest:
                        entry.log = True
                    if current_acl.acl_type == "standard":
                        entry.source = rest.replace(" log", "").strip()
                    else:
                        protocol, source, destination = self._parse_extended_acl_rest(rest)
                        entry.protocol = protocol
                        entry.source = source
                        entry.destination = destination
                    current_acl.entries.append(entry)
                continue

            # ISAKMP contents
            if current_isakmp and original_line.startswith((' ', '\t')):
                current_isakmp.source_lines.append(line_num)
                
                m_encr = re.match(r'^encr\s+(\S+)', line)
                if m_encr:
                    current_isakmp.encryption = m_encr.group(1)
                    continue
                
                m_hash = re.match(r'^hash\s+(\S+)', line)
                if m_hash:
                    current_isakmp.hash_algorithm = m_hash.group(1)
                    continue
                
                m_group = re.match(r'^group\s+(\d+)', line)
                if m_group:
                    current_isakmp.dh_group = int(m_group.group(1))
                    continue
                continue

            # Unset context on any non-indented line that wasn't matched above
            if not original_line.startswith((' ', '\t')):
                current_interface = current_vty = current_console = current_acl = current_isakmp = None

        # Post-process interfaces for WAN heuristic
        for intf in config.interfaces:
            name_lower = intf.name.lower()
            desc_lower = (intf.description or "").lower()
            
            if "outside" in name_lower:
                intf.is_wan = True
            elif any(w in desc_lower for w in ["wan", "internet", "uplink"]):
                intf.is_wan = True
            elif intf.acl_in or intf.acl_out:
                intf.is_wan = True

        return config

    def _parse_extended_acl_rest(self, rest: str) -> tuple[str, str, str]:
        """
        Naive parser for Cisco extended ACL remainder.
        Format: protocol source destination [options]
        """
        parts = rest.split()
        if not parts:
            return "ip", "any", "any"
        
        protocol = parts[0]
        idx = 1
        
        def parse_ip_spec():
            nonlocal idx
            if idx >= len(parts):
                return ""
            if parts[idx] == "any":
                idx += 1
                return "any"
            elif parts[idx] == "host":
                val = f"host {parts[idx+1]}" if idx + 1 < len(parts) else "host"
                idx += 2
                return val
            else:
                # Assuming IP and wildcard
                val = f"{parts[idx]} {parts[idx+1]}" if idx + 1 < len(parts) else parts[idx]
                idx += 2
                return val

        source = parse_ip_spec()
        destination = parse_ip_spec()
        
        return protocol, source, destination
