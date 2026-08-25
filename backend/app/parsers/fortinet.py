import shlex
import collections
from typing import List, Tuple, Dict

from app.parsers.base import BaseParser
from app.models.normalized import (
    NormalizedConfig, DeviceInfo, Vendor, Interface, ManagementAccess,
    Authentication, LocalUser, SnmpConfig, SnmpCommunity, LoggingConfig,
    NtpConfig, FirewallPolicy, VpnConfig, IpsecProposal, BannerConfig, ServiceConfig
)

class FortinetParser(BaseParser):
    """
    Parser for Fortinet FortiOS configuration files.
    
    FortiOS uses a hierarchical configuration structure based on 
    `config`, `edit`, `set`, `next`, and `end` keywords.
    This parser builds a context stack to parse nested blocks accurately.
    """

    def parse(self, raw_config: str) -> NormalizedConfig:
        norm = NormalizedConfig(raw_config=raw_config, raw_lines=self._index_lines(raw_config))
        norm.device.vendor = Vendor.FORTINET
        
        commands = self._parse_blocks(norm.raw_lines)
        groups = collections.defaultdict(list)
        for ctx, line_num, cmd in commands:
            # Group commands by their precise configuration context
            groups[tuple(ctx)].append((line_num, cmd))
            
        self._parse_system_global(groups, norm)
        self._parse_interfaces(groups, norm)
        self._parse_admin_users(groups, norm)
        self._parse_password_policy(groups, norm)
        self._parse_snmp(groups, norm)
        self._parse_logging(groups, norm)
        self._parse_ntp(groups, norm)
        self._parse_firewall_policies(groups, norm)
        self._parse_vpn(groups, norm)
        self._parse_system_settings(groups, norm)

        return norm
        
    def _parse_blocks(self, lines: list[str]) -> list[tuple[list[str], int, str]]:
        """
        Convert flat lines into a list of contextualized commands.
        Maintains a stack of `config` and `edit` contexts.
        """
        context = []
        commands = []
        for i, line in enumerate(lines, 1):
            text = line.strip()
            if not text:
                continue
            
            parts = text.split()
            cmd = parts[0].lower()
            
            if cmd == "config":
                context.append(text)
            elif cmd == "edit":
                context.append(text)
            elif cmd == "next":
                # Exit the current `edit` block
                if context and context[-1].lower().startswith("edit"):
                    context.pop()
            elif cmd == "end":
                # Exit the innermost `config` block (and any unclosed `edit`)
                while context:
                    popped = context.pop()
                    if popped.lower().startswith("config"):
                        break
            elif cmd == "set":
                commands.append((list(context), i, text))
        return commands
        
    def _extract_values(self, set_command: str) -> list[str]:
        """Extract arguments from a `set` command, respecting quotes."""
        try:
            parts = shlex.split(set_command)
        except ValueError:
            # Fallback for mismatched quotes
            parts = set_command.split()
            
        if len(parts) >= 2 and parts[0].lower() == "set":
            return parts[2:]
        return []

    def _extract_name(self, text: str) -> str:
        """Extract the name/ID from an `edit <name>` block."""
        try:
            parts = shlex.split(text)
            if len(parts) >= 2:
                return parts[1]
        except ValueError:
            pass
        parts = text.split(maxsplit=1)
        if len(parts) > 1:
            return parts[1].strip('"\'')
        return ""

    def _parse_system_global(self, groups, norm: NormalizedConfig):
        ctx = ("config system global",)
        if ctx in groups:
            for line_num, cmd in groups[ctx]:
                vals = self._extract_values(cmd)
                if not vals:
                    continue
                k = cmd.split()[1].lower()
                
                if k == "hostname":
                    norm.device.hostname = vals[0]
                    norm.device.source_lines.append(line_num)
                elif k == "admintimeout":
                    if vals[0].isdigit():
                        norm.management.admin_timeout = int(vals[0])
                        norm.management.source_lines.append(line_num)
                elif k == "admin-ssh-v1":
                    norm.management.ssh_version = 1 if vals[0] == "enable" else 2
                    norm.management.source_lines.append(line_num)
                elif k == "pre-login-banner":
                    norm.banners.pre_login_banner_enabled = (vals[0] == "enable")
                    norm.banners.source_lines.append(line_num)

    def _parse_interfaces(self, groups, norm: NormalizedConfig):
        for ctx, cmds in groups.items():
            if len(ctx) >= 2 and ctx[0] == "config system interface" and ctx[1].startswith("edit"):
                name = self._extract_name(ctx[1])
                intf = Interface(name=name)
                
                for line_num, cmd in cmds:
                    vals = self._extract_values(cmd)
                    if not vals:
                        continue
                    k = cmd.split()[1].lower()
                    
                    if k == "ip" and len(vals) >= 2:
                        intf.ip_address = vals[0]
                        intf.subnet_mask = vals[1]
                        intf.source_lines.append(line_num)
                    elif k == "description":
                        intf.description = vals[0]
                        intf.source_lines.append(line_num)
                    elif k == "allowaccess":
                        intf.allowed_services = [v.lower() for v in vals]
                        intf.source_lines.append(line_num)
                        
                        # Update global management flags based on allowed services
                        if "ssh" in intf.allowed_services:
                            norm.management.ssh_enabled = True
                        if "telnet" in intf.allowed_services:
                            norm.management.telnet_enabled = True
                        if "http" in intf.allowed_services:
                            norm.management.http_enabled = True
                        if "https" in intf.allowed_services:
                            norm.management.https_enabled = True
                            
                    elif k == "role":
                        if vals[0].lower() == "wan":
                            intf.is_wan = True
                        intf.source_lines.append(line_num)
                    elif k == "lldp-transmission":
                        intf.lldp_enabled = (vals[0] == "enable")
                        intf.source_lines.append(line_num)
                
                if "wan" in name.lower():
                    intf.is_wan = True
                    
                norm.interfaces.append(intf)

    def _parse_admin_users(self, groups, norm: NormalizedConfig):
        for ctx, cmds in groups.items():
            if len(ctx) >= 2 and ctx[0] == "config system admin" and ctx[1].startswith("edit"):
                name = self._extract_name(ctx[1])
                user = LocalUser(username=name)
                has_password = False
                
                for line_num, cmd in cmds:
                    vals = self._extract_values(cmd)
                    if not vals:
                        continue
                    k = cmd.split()[1].lower()
                    
                    if k == "password":
                        has_password = True
                        user.password_type = "encrypted" if vals[0].startswith("ENC") else "plaintext"
                        user.source_lines.append(line_num)
                    elif k == "trusthost1":
                        user.source_lines.append(line_num)
                        
                if not has_password:
                    user.password_type = "empty"
                    
                norm.authentication.local_users.append(user)
                norm.authentication.source_lines.extend(user.source_lines)

    def _parse_password_policy(self, groups, norm: NormalizedConfig):
        ctx = ("config system password-policy",)
        if ctx in groups:
            for line_num, cmd in groups[ctx]:
                vals = self._extract_values(cmd)
                if not vals:
                    continue
                k = cmd.split()[1].lower()
                if k == "status" and vals[0] == "enable":
                    norm.authentication.source_lines.append(line_num)

    def _parse_snmp(self, groups, norm: NormalizedConfig):
        for ctx, cmds in groups.items():
            if len(ctx) >= 2 and ctx[0] == "config system snmp community" and ctx[1].startswith("edit"):
                name = self._extract_name(ctx[1])
                comm = SnmpCommunity(name=name)
                norm.snmp.enabled = True
                
                for line_num, cmd in cmds:
                    vals = self._extract_values(cmd)
                    if not vals:
                        continue
                    k = cmd.split()[1].lower()
                    
                    if k == "name":
                        comm.name = vals[0]
                        comm.source_lines.append(line_num)
                    elif k in ("query-v1-status", "query-v2c-status"):
                        comm.source_lines.append(line_num)
                        
                norm.snmp.communities.append(comm)
                norm.snmp.source_lines.extend(comm.source_lines)
                
    def _parse_logging(self, groups, norm: NormalizedConfig):
        for ctx, cmds in groups.items():
            if ctx == ("config log syslogd setting",):
                for line_num, cmd in cmds:
                    vals = self._extract_values(cmd)
                    if not vals:
                        continue
                    k = cmd.split()[1].lower()
                    if k == "status" and vals[0] == "enable":
                        norm.logging.source_lines.append(line_num)
                    elif k == "server":
                        norm.logging.remote_hosts.append(vals[0])
                        norm.logging.source_lines.append(line_num)
            elif ctx == ("config log disk setting",):
                for line_num, cmd in cmds:
                    vals = self._extract_values(cmd)
                    if not vals:
                        continue
                    k = cmd.split()[1].lower()
                    if k == "status" and vals[0] == "enable":
                        norm.logging.buffered = True
                        norm.logging.source_lines.append(line_num)

    def _parse_ntp(self, groups, norm: NormalizedConfig):
        for ctx, cmds in groups.items():
            if ctx == ("config system ntp",):
                for line_num, cmd in cmds:
                    vals = self._extract_values(cmd)
                    if not vals:
                        continue
                    k = cmd.split()[1].lower()
                    if k == "authentication" and vals[0] == "enable":
                        norm.ntp.authentication_enabled = True
                        norm.ntp.source_lines.append(line_num)
                        
            # Extract NTP servers from nested block
            if len(ctx) >= 3 and ctx[0] == "config system ntp" and ctx[1] == "config ntpserver" and ctx[2].startswith("edit"):
                for line_num, cmd in cmds:
                    vals = self._extract_values(cmd)
                    if not vals:
                        continue
                    k = cmd.split()[1].lower()
                    if k == "server":
                        norm.ntp.servers.append(vals[0])
                        norm.ntp.source_lines.append(line_num)

    def _parse_firewall_policies(self, groups, norm: NormalizedConfig):
        for ctx, cmds in groups.items():
            if len(ctx) >= 2 and ctx[0] == "config firewall policy" and ctx[1].startswith("edit"):
                pid = self._extract_name(ctx[1])
                pol = FirewallPolicy(policy_id=pid)
                
                for line_num, cmd in cmds:
                    vals = self._extract_values(cmd)
                    if not vals:
                        continue
                    k = cmd.split()[1].lower()
                    
                    if k == "name":
                        pol.name = vals[0]
                        pol.source_lines.append(line_num)
                    elif k == "srcintf":
                        pol.src_interface = vals[0]
                        pol.source_lines.append(line_num)
                    elif k == "dstintf":
                        pol.dst_interface = vals[0]
                        pol.source_lines.append(line_num)
                    elif k == "srcaddr":
                        pol.src_address = vals[0]
                        pol.source_lines.append(line_num)
                    elif k == "dstaddr":
                        pol.dst_address = vals[0]
                        pol.source_lines.append(line_num)
                    elif k == "service":
                        pol.service = vals
                        pol.source_lines.append(line_num)
                    elif k == "action":
                        pol.action = vals[0]
                        pol.source_lines.append(line_num)
                    elif k == "schedule":
                        pol.schedule = vals[0]
                        pol.source_lines.append(line_num)
                    elif k == "utm-status":
                        pol.utm_enabled = (vals[0] == "enable")
                        pol.source_lines.append(line_num)
                    elif k == "logtraffic":
                        pol.logging_enabled = (vals[0] != "disable")
                        pol.source_lines.append(line_num)
                    elif k == "nat":
                        pol.nat_enabled = (vals[0] == "enable")
                        pol.source_lines.append(line_num)
                        
                norm.firewall_policies.append(pol)

    def _parse_vpn(self, groups, norm: NormalizedConfig):
        for ctx, cmds in groups.items():
            if len(ctx) >= 2 and ctx[0] == "config vpn ipsec phase1-interface" and ctx[1].startswith("edit"):
                name = self._extract_name(ctx[1])
                prop = IpsecProposal(name=name)
                
                for line_num, cmd in cmds:
                    vals = self._extract_values(cmd)
                    if not vals:
                        continue
                    k = cmd.split()[1].lower()
                    
                    if k == "proposal":
                        prop.encryption = vals[0]
                        prop.hash_algorithm = vals[0]
                        prop.source_lines.append(line_num)
                    elif k == "dhgrp":
                        if vals[0].isdigit():
                            prop.dh_group = int(vals[0])
                        prop.source_lines.append(line_num)
                    elif k == "ike-version":
                        if vals[0].isdigit():
                            prop.ike_version = int(vals[0])
                        prop.source_lines.append(line_num)
                        
                norm.vpn.ipsec_proposals.append(prop)
                norm.vpn.source_lines.extend(prop.source_lines)
                
            elif ctx == ("config vpn ssl settings",):
                for line_num, cmd in cmds:
                    vals = self._extract_values(cmd)
                    if not vals:
                        continue
                    k = cmd.split()[1].lower()
                    if k == "ssl-min-proto-ver":
                        norm.vpn.ssl_min_tls_version = vals[0]
                        norm.vpn.source_lines.append(line_num)

    def _parse_system_settings(self, groups, norm: NormalizedConfig):
        ctx = ("config system settings",)
        if ctx in groups:
            for line_num, cmd in groups[ctx]:
                vals = self._extract_values(cmd)
                if not vals:
                    continue
                k = cmd.split()[1].lower()
                if k == "ip-src-routing":
                    norm.services.ip_source_route = (vals[0] == "enable")
                    norm.services.source_lines.append(line_num)
