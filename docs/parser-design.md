# Parser Design

Parsing raw network configs is the hardest part of this project. Here is how we are handling it.

## The Approach

We are building custom, regex-based parsers in Python for each vendor. 
All parsers inherit from a `BaseParser` class (located in `backend/app/parsers/base.py`) which mandates a `parse()` method returning a `NormalizedConfig` object.

## Target 1: Cisco IOS (In Progress)

Cisco configs use a hierarchical indentation structure (though sometimes just spaces). 
* **Challenges:** Lots of legacy commands. Interfaces can span multiple lines. ACLs are extremely complex to parse.
* **Strategy:** We are using regex blocks. First, we identify global configs, then we iterate through interfaces using `^interface (.*)` regex to grab blocks of text, then parse those blocks individually.

## Target 2: FortiGate (In Progress)

Fortinet configs use a block structure with `config system ...` followed by `edit ...` and ending with `end`.
* **Challenges:** Deeply nested contexts. Policies reference objects by name, so we have to parse objects first, then resolve them when parsing policies.
* **Strategy:** Building a state-machine parser that tracks the current `config` context to accurately extract key-value pairs.

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

**Normalized Result (Both map to this!):**
```json
{
  "interfaces": [
    {
      "name": "GigabitEthernet0/1", // or "port1"
      "ip_address": "192.168.1.1",
      "subnet_mask": "255.255.255.0",
      "is_up": true,
      "services_allowed": []
    }
  ]
}
```

## Known Limitations
Currently, we aren't using abstract syntax trees (ASTs) like Batfish does. Our regex approach is brittle and will likely fail on edge cases or deeply unusual configs. It is sufficient for the hackathon scope, however.
