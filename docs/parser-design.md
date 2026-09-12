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

## Unknown Vendors and Unrecognized Lines

We do not write a parser per vendor beyond Cisco IOS and FortiGate. Two kinds of line go to the adaptive layer (`backend/app/adaptive/`) instead:
* lines a parser does not recognize
* every line of a config the detector cannot identify

`context.py` gives each captured line a generic **block path** in a single pass, with no vendor knowledge:
* **Braces:** `system {` … `}`
* **Keyword blocks:** `config` / `edit` opened, and `end` / `next` / `exit` closed
* **Indentation**

For example, `set admin-ssh enable` inside `config system global` gets the path `config system global`. The AI sees this path as context, so the same leaf command can be read correctly in different blocks.

The rest of the adaptive pipeline is described in [ai-design.md](ai-design.md). An AI result only reaches the normalized model after it passes these checks:
* the field is in the catalog
* the cited evidence appears in the line
* the value matches the line's on/off polarity

A HIGH-confidence result that passes is applied automatically. Anything less certain goes to the Training queue for an administrator.

## Known Limitations
The parsers are intentionally limited to common configuration patterns. They may miss unusual syntax, vendor version differences, or complex ACL options.

The adaptive layer only fills the fields in `field_catalog.py`, and most management rules are still vendor-specific. As a result, unknown-vendor configs are currently evaluated mainly by the vendor-neutral rules, and their scores are flagged provisional.
