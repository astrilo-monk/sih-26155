# Parser Design

Parsing raw network configs is the hardest part of this project. Here is how we are handling it.

## The Approach

We use custom, pattern-based parsers in Python for each vendor.
All parsers inherit from a `BaseParser` class (located in `backend/app/parsers/base.py`) which mandates a `parse()` method returning a `NormalizedConfig` object.

## Cisco IOS (Implemented for Common Patterns)

Cisco configs use a hierarchical indentation structure (though sometimes just spaces). 
* **Challenges:** Lots of legacy commands. Interfaces can span multiple lines. ACLs are extremely complex to parse.
* **Strategy:** The parser walks through the configuration line by line and tracks the current interface, VTY, console, ACL, banner, or crypto context. It records source line numbers along the way.

## FortiGate (Implemented for Common Patterns)

Fortinet configs use a block structure with `config system ...` followed by `edit ...` and ending with `end`.
* **Challenges:** Deeply nested contexts and vendor-specific settings. The current parser focuses on fields needed by the implemented rules and does not resolve every referenced FortiGate object.
* **Strategy:** The parser tracks a stack of `config` and `edit` contexts, stores `set` commands with their context, and then extracts interfaces, policies, users, logging, NTP, VPN, and system settings.

## Normalization Example

**Raw Cisco:**
```text
interface GigabitEthernet0/1
 ip address 192.168.1.1 255.255.255.0
 no shutdown
```

**Raw FortiGate:**
```text
config system interface
    edit "port1"
        set ip 192.168.1.1 255.255.255.0
        set status up
    next
end
```

**Normalized Result (Both map to the same model):**
```json
{
  "interfaces": [
    {
      "name": "GigabitEthernet0/1", // or "port1"
      "ip_address": "192.168.1.1",
      "subnet_mask": "255.255.255.0",
      "shutdown": false,
      "allowed_services": []
    }
  ]
}
```

## Known Limitations
The parsers are intentionally limited to common configuration patterns. They may miss unusual syntax, vendor version differences, or complex ACL options. This is acceptable for the current hackathon scope, but production use would need a more complete parser and larger fixture set.
