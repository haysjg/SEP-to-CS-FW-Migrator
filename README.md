# SEP → CrowdStrike Firewall Management Migrator

A PowerShell GUI tool to convert **Symantec Endpoint Protection 14** firewall policies (JSON export) into **CrowdStrike Firewall Management** rule groups and policies via the [PSFalcon](https://github.com/CrowdStrike/psfalcon) module.

---

## Features

- **3-step GUI workflow** — Setup → Analysis → Migration
- **Automatic rule classification** — flags each SEP rule as Direct, Adaptation Required, or Non-migratable before touching the tenant
- **Smart adaptations** applied automatically:
  - FQDN hosts forced to Outbound (CS FW stateful engine handles return traffic)
  - IP ranges converted to minimal CIDR blocks
  - Multi-protocol rules split into one CS rule per protocol
  - Host group members expanded inline from JSON or an optional CSV
  - VPN adapter rules mapped to a Network Location
  - Application paths normalised to glob patterns (`**\filename.exe`)
- **Hard blockers detected** (rules that cannot be migrated): EtherType, MAC address filters, IP fragment rules
- **Pre-flight port validation** before any API call
- Config save/load with **DPAPI-encrypted** client secret (current user + machine only)
- Full migration log exported to file

---

## Requirements

| Requirement | Details |
|---|---|
| PowerShell | 5.1+ (Windows PowerShell or PowerShell 7) |
| PSFalcon | Installed automatically on first run |
| CrowdStrike Falcon | Firewall Management module enabled in your tenant |
| Network | Outbound HTTPS to `api.crowdstrike.com` (or your cloud endpoint) |

### Required OAuth2 API Scopes

Create a **CrowdStrike API client** with the following scopes:

| Scope | Access |
|---|---|
| Firewall management | **Read + Write** |

> Used by: `New-FalconFirewallGroup`, `New-FalconFirewallPolicy`, `Edit-FalconFirewallSetting`

---

## Getting Started

### 1. Run the migrator


```powershell
.\SEP-CS-FW-Migrator.ps1
```

> First run: click **Install / Update PSFalcon** to pull the module from PSGallery.  
> If you get an execution policy error: `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`

### 2. Follow the 3-tab workflow

| Tab | Action |
|---|---|
| **1. Setup** | Enter API credentials → Test Connection → select SEP JSON |
| **2. Analysis** | Click **Analyze File** to preview every rule before migrating |
| **3. Migration** | Name the rule group & policy → **Start Migration** |

---

## Migration Rule Types

| Type | Meaning |
|---|---|
| ✅ Direct | Rule translates 1:1, no changes needed |
| ⚠️ Adaptation | Automatic adjustment applied (see below) |
| ❌ Non-migratable | Rule uses a feature not supported at L3/L4 |

### Adaptations applied automatically

- **FQDN host + direction Both/Inbound** → forced to Outbound (CS FW resolves FQDNs outbound-only; stateful WFP allows return traffic)
- **IP range notation** (`x.x.x.x-y.y.y.y`) → converted to minimal covering CIDR set
- **Multiple protocols** in one rule → split into N separate CS rules
- **Host groups** → members embedded in the JSON are expanded inline
- **Adapter = VPN** → mapped to a named Network Location (configured in tab 3)
- **Application path** with drive letter or filename-only → converted to `**\filename.exe` glob

### Hard blockers (cannot be migrated)

- **EtherType rules** — CS FW operates at L3/L4 only
- **MAC address filters** — not supported in CS FW
- **IP fragment rules** — CS FW is stateful (WFP), not packet-level

---

## Optional: Host Groups CSV

If your SEP policy references host groups whose member data is **not** embedded in the JSON export, you can provide a CSV:

```
GroupName,Entry
Bloomberg,10.0.1.0/24
Country B - VPN Gateway,vpn.example.com
Global - MCP Host Group,*.symantec.com
```

See `HostGroups-template.csv` for the format.

---

## Headless Testing

`Test-Migration.ps1` runs the full conversion pipeline without the GUI — useful for CI or pre-flight checks:

```powershell
# Local validation only (no API call):
.\Test-Migration.ps1 -SepJson "path\to\FW_policy.json"

# Full API schema validation (no rule group created):
.\Test-Migration.ps1 -SepJson "path\to\FW_policy.json" -ApiValidate -ClientId <id> -ClientSecret <secret>

# Inspect first 5 rules matching a name filter:
.\Test-Migration.ps1 -SepJson "path\to\FW_policy.json" -DumpRules 5 -Filter "VPN"
```

---

## Important Notes

- **CS FW and SEP FW cannot coexist** on the same endpoint. Plan for a cutover, not a parallel run.
- The policy is created **unassigned** and in **Monitor Mode** by default — all traffic is allowed, blocks are only logged. Validate in Monitor Mode before switching to Enforce.
- Disabling a policy via API means **no change events are recorded** during that window — document this gap for compliance.

---

## Files

| File | Description |
|---|---|
| `SEP-CS-FW-Migrator.ps1` | Main GUI tool |
| `Test-Migration.ps1` | Headless test / validation script |
| `HostGroups-template.csv` | Template for optional host group expansion |

> `*-Config.json`, `*.log`, and `SEP-CS-FW-Migration-*.csv` are excluded from the repo via `.gitignore` — they may contain tenant-specific or customer data.
