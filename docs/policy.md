# Organisation policy

Frameworks set minimums. An organisation usually has its own, stricter baseline: a shorter idle timeout, fewer
login attempts, and a list of the NTP and syslog servers devices may use. A policy file states it, and the checks
use it on top of the frameworks.

```json
{
  "name": "Acme network baseline",
  "idle_timeout_minutes": 10,
  "login_attempts": 5,
  "password_min_length": 12,
  "ntp_servers": ["10.1.0.10", "10.1.0.11"],
  "syslog_servers": ["10.1.0.50"]
}
```

| Field | Default | Allowed | Check |
|---|---|---|---|
| `name` | required | up to 80 characters | named in every result the policy changed |
| `idle_timeout_minutes` | 15 | 1 – 15 | MGMT-006 |
| `login_attempts` | 10 | 1 – 10 | AUTH-001 |
| `password_min_length` | 8 | 8 – 128 | AUTH-002 |
| `ntp_servers` | any | up to 20 addresses or host names | LOG-002: a server not on the list is a FAIL |
| `syslog_servers` | any | up to 20 addresses or host names | LOG-001: a destination not on the list is a FAIL |

**A policy can only tighten.** A value looser than the default is refused (422 at upload, exit code 2 in the CLI):
a PASS must still mean the framework requirement is met. Unknown fields are refused too, so a typo is never
silently ignored.

**Where it applies.** Upload page (*Organisation policy*, optional), `POST /api/scan` (`policy` form field, the JSON
text), and the CLI (`--policy FILE`). Every later evaluation of that scan uses the same policy: teaching, and the
re-checks behind verified remediation. The scan response echoes it in `policy`; Results names it; a result it
changed ends its reason with *(organisation policy '…')*.

**Limit.** Automatic fixes write a 5-minute idle timeout. A policy under 5 minutes makes that fix fail its re-check,
so it is not offered as verified; set the timeout by hand.
