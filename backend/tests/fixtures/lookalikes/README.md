# Look-alike configurations

Synthetic configs for vendor-identification tests (Phase 1b). Most of them
fingerprint as Cisco IOS or FortiGate (shared `hostname`, `!`, `interface`,
`config`/`edit`/`set` syntax) but are a different product or dialect, and must
come out **unverified**:

| File | Dialect |
|---|---|
| `arista_eos.cfg` | Arista EOS |
| `cisco_nxos.cfg` | Cisco NX-OS |
| `cisco_iosxr.cfg` | Cisco IOS-XR |
| `cisco_asa.cfg` | Cisco ASA |
| `dell_os10.cfg` | Dell OS10 |
| `brocade_icx.cfg` | Ruckus/Brocade ICX |
| `mixed_ios_foreign_block.cfg` | Valid IOS with a pasted foreign block |
| `fortiswitch.cfg` | FortiSwitchOS (FortiOS grammar, not a FortiGate) |

`cisco_iosxe_exec_banner.cfg` is the positive control: real IOS-XE syntax
(multi-line exec banner, `Virtual-PortGroup`, `iox`, `pnp`) that must stay
**confirmed**.

These files live in a subdirectory so the Phase 0 snapshot generator, which
reads `tests/fixtures/*.cfg` only, does not pick them up.
