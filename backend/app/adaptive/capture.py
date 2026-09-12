"""
Unrecognized Line Capture for Adaptive Parsing.

This module captures lines from the raw configuration that were not recognized
by the vendor parser, applies the security relevance filter, and adds them
to the NormalizedConfig as UnrecognizedLine objects.
"""

from app.models.normalized import NormalizedConfig, UnrecognizedLine, Vendor
from app.adaptive.relevance import is_security_relevant, get_context_lines
from app.adaptive.context import structural_paths


def _collect_recognized_line_numbers(config: NormalizedConfig) -> set[int]:
    """
    Collect all line numbers that were recognized/parsed by the vendor parser.
    
    Each parsed component in NormalizedConfig has source_lines tracking which
    raw config lines it came from.
    """
    recognized = set()
    
    # Device info
    recognized.update(config.device.source_lines)
    
    # Interfaces
    for intf in config.interfaces:
        recognized.update(intf.source_lines)
    
    # Management access
    recognized.update(config.management.source_lines)
    for vty in config.management.vty_lines:
        recognized.update(vty.source_lines)
    if config.management.console:
        recognized.update(config.management.console.source_lines)
    
    # Authentication
    recognized.update(config.authentication.source_lines)
    for user in config.authentication.local_users:
        recognized.update(user.source_lines)
    
    # SNMP
    recognized.update(config.snmp.source_lines)
    for comm in config.snmp.communities:
        recognized.update(comm.source_lines)
    
    # Logging
    recognized.update(config.logging.source_lines)
    
    # NTP
    recognized.update(config.ntp.source_lines)
    
    # Access lists
    for acl in config.access_lists:
        recognized.update(acl.source_lines)
        for entry in acl.entries:
            recognized.update(entry.source_lines)
    
    # Firewall policies
    for policy in config.firewall_policies:
        recognized.update(policy.source_lines)
    
    # VPN
    recognized.update(config.vpn.source_lines)
    for proposal in config.vpn.ipsec_proposals:
        recognized.update(proposal.source_lines)
    
    # Banners
    recognized.update(config.banners.source_lines)
    
    # Services
    recognized.update(config.services.source_lines)
    
    return recognized


def capture_unrecognized_lines(config: NormalizedConfig) -> None:
    """
    Capture unrecognized lines from the raw configuration.
    
    This function:
    1. Identifies line numbers not present in any parsed component's source_lines
    2. Applies the security relevance filter to those lines
    3. Creates UnrecognizedLine objects for relevant lines with context
    4. Adds them to config.unrecognized_lines
    
    This is called AFTER parsing, so it doesn't modify parser behavior.
    
    Args:
        config: The NormalizedConfig produced by a vendor parser
    """
    if not config.raw_lines:
        return
    
    # Get vendor string
    vendor_str = config.device.vendor.value if config.device.vendor else "unknown"
    
    # Collect all recognized line numbers
    recognized_lines = _collect_recognized_line_numbers(config)
    
    # Find unrecognized lines
    unrecognized = []
    paths = None
    for i, raw_line in enumerate(config.raw_lines):
        line_num = i + 1  # 1-indexed
        
        if line_num in recognized_lines:
            continue
        
        stripped = raw_line.strip()
        if not stripped:
            continue
        
        # Skip comment-only lines (Cisco ! and Fortinet #)
        if stripped.startswith("!") or stripped.startswith("#"):
            continue
        
        # Apply security relevance filter
        if not is_security_relevant(raw_line):
            continue
        
        # Get surrounding context
        context_before, context_after = get_context_lines(
            config.raw_lines, line_num, context_size=2
        )
        
        if paths is None:
            paths = structural_paths(config.raw_lines)

        # Create UnrecognizedLine
        unrecognized.append(UnrecognizedLine(
            raw_line=raw_line,
            line_number=line_num,
            vendor=vendor_str,
            context_before=context_before,
            context_after=context_after,
            structural_path=list(paths[i]),
        ))
    
    config.unrecognized_lines = unrecognized