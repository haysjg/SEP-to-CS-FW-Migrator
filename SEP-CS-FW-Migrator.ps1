#Requires -Version 5.1
<#
.SYNOPSIS
    SEP to CrowdStrike Firewall Management Migration Tool
.DESCRIPTION
    GUI tool to convert Symantec Endpoint Protection 14 firewall rules (JSON export)
    into CrowdStrike Firewall Management rule groups and policies via PSFalcon.
    Handles: direct migration, FQDN/direction adaptation, host group expansion,
    VPN adapter -> Network Location mapping, protocol splitting, and hard blockers.
.NOTES
    Requires: PSFalcon module (installed automatically if missing)
    Input:    SEP native policy JSON (FW_*.json from SEP console export)
    Output:   CS FW Rule Group + Policy created in your Falcon tenant

    Required OAuth2 API scopes (Falcon API client):
      - Firewall management : Read + Write
        Used for: New-FalconFirewallGroup, New-FalconFirewallPolicy, Edit-FalconFirewallSetting
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ─────────────────────────────────────────────────────────────────────────────────
#region CONSTANTS & MAPPINGS
# ─────────────────────────────────────────────────────────────────────────────────

$script:LogFile = Join-Path $PSScriptRoot "SEP-CS-FW-Migrator-$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-FileLog {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  [$Level]  $Message"
    Add-Content -Path $script:LogFile -Value $line -Encoding UTF8
}

$script:MaxRuleNameLen = 64

$script:DirectionMap = @{ 0 = 'OUT'; 1 = 'IN'; 2 = 'BOTH' }
$script:DirectionLabel = @{ 0 = 'Outbound'; 1 = 'Inbound'; 2 = 'Both' }

$script:ProtocolMap = @{
    1  = 'ICMPv4'
    6  = 'TCP'
    17 = 'UDP'
    41 = '41'      # IPv6 Encapsulation
    50 = '50'      # ESP
    58 = 'ICMPv6'
}

$script:EtherTypeNames = @{
    34958 = '802.1X / EAPOL (0x888E)'
    34525 = 'IPv6 (0x86DD)'
}

$script:AnalysisResults = [System.Collections.Generic.List[hashtable]]::new()
$script:Connected       = $false
$script:AnalysisDone    = $false

#endregion

# ─────────────────────────────────────────────────────────────────────────────────
#region PSFALCON SETUP
# ─────────────────────────────────────────────────────────────────────────────────

function Initialize-PSFalcon {
    param([System.Windows.Forms.RichTextBox]$Log)

    Write-UILog $Log 'Checking PSFalcon installation...' Info

    # ── Diagnostics ──────────────────────────────────────────────────────────────
    Write-FileLog "--- Initialize-PSFalcon START ---" INFO
    Write-FileLog "PS version  : $($PSVersionTable.PSVersion)" INFO
    Write-FileLog "PS edition  : $($PSVersionTable.PSEdition)" INFO
    Write-FileLog "OS          : $([System.Environment]::OSVersion.VersionString)" INFO
    Write-FileLog "RunAs admin : $( ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) )" INFO
    Write-FileLog "Script root : $PSScriptRoot" INFO

    $execPolicy = Get-ExecutionPolicy -Scope CurrentUser
    $execPolicyProcess = Get-ExecutionPolicy -Scope Process
    Write-FileLog "ExecPolicy CurrentUser : $execPolicy" INFO
    Write-FileLog "ExecPolicy Process     : $execPolicyProcess" INFO
    Write-UILog $Log "Execution policy — CurrentUser: $execPolicy  /  Process: $execPolicyProcess" Info

    $psModulePaths = $env:PSModulePath -split ';'
    Write-FileLog "PSModulePath entries:" INFO
    foreach ($p in $psModulePaths) { Write-FileLog "  $p" INFO }

    # Check PSGallery reachability
    Write-UILog $Log 'Testing PSGallery connectivity...' Info
    try {
        $repo = Get-PSRepository -Name PSGallery -ErrorAction Stop
        Write-FileLog "PSGallery registered — InstallationPolicy: $($repo.InstallationPolicy)  SourceLocation: $($repo.SourceLocation)" INFO
        Write-UILog $Log "PSGallery registered — policy: $($repo.InstallationPolicy)" Info
    } catch {
        Write-FileLog "PSGallery NOT registered: $_" ERROR
        Write-UILog $Log "PSGallery not registered: $_" Error
    }

    try {
        $null = [System.Net.Dns]::GetHostEntry('www.powershellgallery.com')
        Write-FileLog "DNS resolution powershellgallery.com: OK" INFO
        Write-UILog $Log 'PSGallery DNS: OK' Info
    } catch {
        Write-FileLog "DNS resolution powershellgallery.com: FAILED — $_" ERROR
        Write-UILog $Log "PSGallery DNS resolution failed: $_" Error
    }

    # ── Module check ─────────────────────────────────────────────────────────────
    $installed = Get-Module -Name PSFalcon -ListAvailable |
        Sort-Object Version -Descending | Select-Object -First 1

    if ($installed) {
        Write-FileLog "PSFalcon already installed — version $($installed.Version) at $($installed.ModuleBase)" INFO
    } else {
        Write-FileLog "PSFalcon not found in any PSModulePath" INFO
    }

    if (-not $installed) {
        Write-UILog $Log 'PSFalcon not found. Installing from PSGallery...' Warning
        Write-FileLog "Calling Install-Module PSFalcon -Scope CurrentUser -Force" INFO
        try {
            Install-Module -Name PSFalcon -Repository PSGallery -Force -Scope CurrentUser -ErrorAction Stop
            Write-FileLog "Install-Module completed without exception" INFO
            Write-UILog $Log 'PSFalcon installed successfully.' Success
        } catch {
            Write-FileLog "Install-Module FAILED: $_" ERROR
            Write-FileLog "Exception type: $($_.Exception.GetType().FullName)" ERROR
            Write-FileLog "Stack trace: $($_.ScriptStackTrace)" ERROR
            Write-UILog $Log "Failed to install PSFalcon: $_" Error
            return $false
        }
    } else {
        Write-UILog $Log "PSFalcon v$($installed.Version) found. Checking for updates..." Info
        try {
            $latest = Find-Module -Name PSFalcon -Repository PSGallery -ErrorAction Stop
            Write-FileLog "Find-Module returned version $($latest.Version)" INFO
            if ([version]$latest.Version -gt [version]$installed.Version) {
                Write-UILog $Log "Updating PSFalcon -> v$($latest.Version)..." Info
                Write-FileLog "Calling Update-Module PSFalcon" INFO
                Update-Module -Name PSFalcon -Force -ErrorAction Stop
                Write-FileLog "Update-Module completed" INFO
                Write-UILog $Log "Updated to v$($latest.Version)." Success
            } else {
                Write-UILog $Log "PSFalcon v$($installed.Version) is up to date." Success
            }
        } catch {
            Write-FileLog "Find/Update-Module error: $_" WARNING
            Write-UILog $Log 'Could not check for updates (offline?). Using installed version.' Warning
        }
    }

    try {
        Write-FileLog "Calling Import-Module PSFalcon -Force" INFO
        Import-Module PSFalcon -Force -ErrorAction Stop
        $loaded = Get-Module -Name PSFalcon
        Write-FileLog "Import-Module OK — loaded version $($loaded.Version)" INFO
        Write-UILog $Log 'PSFalcon module loaded.' Success
        return $true
    } catch {
        Write-FileLog "Import-Module FAILED: $_" ERROR
        Write-UILog $Log "Failed to import PSFalcon: $_" Error
        return $false
    }
}

function Connect-FalconApi {
    param(
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$Cloud,
        [System.Windows.Forms.RichTextBox]$Log
    )
    try {
        Write-UILog $Log "Authenticating to CrowdStrike ($Cloud)..." Info
        Request-FalconToken -ClientId $ClientId -ClientSecret $ClientSecret -Cloud $Cloud -ErrorAction Stop
        Write-UILog $Log 'Authentication successful.' Success
        $script:Connected = $true
        return $true
    } catch {
        Write-UILog $Log "Authentication failed: $_" Error
        $script:Connected = $false
        return $false
    }
}

#endregion

# ─────────────────────────────────────────────────────────────────────────────────
#region CONFIG IMPORT / EXPORT
# ─────────────────────────────────────────────────────────────────────────────────

function Set-ComboValue {
    param($Combo, [string]$Value)
    $idx = $Combo.Items.IndexOf($Value)
    if ($idx -ge 0) { $Combo.SelectedIndex = $idx }
}

function Export-AppConfig {
    param([string]$Path)

    # Encrypt secret with Windows DPAPI (current user + machine only)
    $encryptedSecret = ''
    if ($tbSecret.Text -ne '') {
        $ss = ConvertTo-SecureString $tbSecret.Text -AsPlainText -Force
        $encryptedSecret = ConvertFrom-SecureString $ss
    }

    $cfg = [ordered]@{
        clientId        = $tbClientId.Text
        clientSecret    = $encryptedSecret
        cloud           = $cboCloud.SelectedItem.ToString()
        jsonPath        = $tbJson.Text
        csvPath         = $tbCsv.Text
        groupName       = $tbGroupName.Text
        policyName      = $tbPolicyName.Text
        platform        = $cboPlatform.SelectedItem.ToString()
        defaultInbound  = $cboInbound.SelectedItem.ToString()
        defaultOutbound = $cboOutbound.SelectedItem.ToString()
        monitorMode     = $chkMonitor.Checked
        vpnLocName      = $tbVpnName.Text
        vpnLocId        = $tbVpnId.Text
    }

    if ($Path -match '\.xml$') {
        [pscustomobject]$cfg | Export-Clixml -Path $Path -Encoding UTF8
    } else {
        $cfg | ConvertTo-Json | Set-Content -Path $Path -Encoding UTF8
    }
}

function Import-AppConfig {
    param([string]$Path)

    if ($Path -match '\.xml$') {
        $cfg = Import-Clixml -Path $Path
    } else {
        $cfg = Get-Content -Path $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    }

    if ($cfg.clientId)        { $tbClientId.Text = $cfg.clientId }
    # Decrypt secret with DPAPI (only works for same user + machine that exported)
    if ($cfg.clientSecret -and $cfg.clientSecret -ne '') {
        try {
            $ss  = ConvertTo-SecureString $cfg.clientSecret
            $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
            $tbSecret.Text = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ptr)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        } catch {
            Write-UILog $rtbSetup 'Could not decrypt client secret (different user or machine?).' Warning
        }
    }
    if ($cfg.cloud)           { Set-ComboValue $cboCloud    $cfg.cloud }
    if ($cfg.jsonPath)        { $tbJson.Text      = $cfg.jsonPath }
    if ($cfg.csvPath)         { $tbCsv.Text       = $cfg.csvPath }
    if ($cfg.groupName)       { $tbGroupName.Text  = $cfg.groupName }
    if ($cfg.policyName)      { $tbPolicyName.Text = $cfg.policyName }
    if ($cfg.platform)        { Set-ComboValue $cboPlatform   $cfg.platform }
    if ($cfg.defaultInbound)  { Set-ComboValue $cboInbound    $cfg.defaultInbound }
    if ($cfg.defaultOutbound) { Set-ComboValue $cboOutbound   $cfg.defaultOutbound }
    $chkMonitor.Checked = [bool]$cfg.monitorMode
    if ($cfg.vpnLocName)      { $tbVpnName.Text = $cfg.vpnLocName }
    if ($null -ne $cfg.vpnLocId) { $tbVpnId.Text = $cfg.vpnLocId }
}

#endregion

# ─────────────────────────────────────────────────────────────────────────────────
#region SEP JSON PARSER
# ─────────────────────────────────────────────────────────────────────────────────

function Import-SepJson {
    param([string]$Path)

    $raw = Get-Content -Path $Path -Raw -Encoding UTF8
    $obj = $raw | ConvertFrom-Json

    # Native SEP export wraps rules inside configuration
    if ($obj.configuration -and $obj.configuration.enforced_rules) {
        $rules = [System.Collections.Generic.List[object]]::new()
        foreach ($r in $obj.configuration.enforced_rules) { $rules.Add($r) }
        if ($obj.configuration.baseline_rules) {
            foreach ($r in $obj.configuration.baseline_rules) { $rules.Add($r) }
        }
        return $rules.ToArray()
    }

    # Flat array
    if ($obj -is [array]) { return $obj }

    return @($obj)
}

function Get-ConnectionProtocols {
    param($Connections)
    $protos = [System.Collections.Generic.List[int]]::new()
    foreach ($c in $Connections) {
        if ($c.protocol_ids) {
            foreach ($p in $c.protocol_ids) { if (-not $protos.Contains([int]$p)) { $protos.Add([int]$p) } }
        }
    }
    return $protos.ToArray()
}

function Get-ConnectionDirection {
    # Returns the most permissive direction across all connections.
    # If any connection is BOTH(2) or directions differ -> return 2.
    param($Connections)
    if (-not $Connections -or $Connections.Count -eq 0) { return 2 }
    $dirs = @($Connections | Where-Object { $null -ne $_.direction_id } | ForEach-Object { [int]$_.direction_id } | Sort-Object -Unique)
    if ($dirs.Count -eq 0) { return 2 }
    if ($dirs.Count -eq 1) { return $dirs[0] }
    return 2  # Mixed -> BOTH
}

function Merge-PortRanges {
    param([hashtable[]]$Ranges)
    if (-not $Ranges -or $Ranges.Count -eq 0) { return @() }
    if ($Ranges.Count -eq 1) { return ,$Ranges }
    $sorted = @($Ranges | Sort-Object { [int]$_.start })
    $merged = [System.Collections.Generic.List[hashtable]]::new()
    $cur = @{ start = [int]$sorted[0].start; end = [int]$sorted[0].end }
    for ($i = 1; $i -lt $sorted.Count; $i++) {
        $s = [int]$sorted[$i].start
        $e = [int]$sorted[$i].end
        if ($s -le ($cur.end + 1)) {
            if ($e -gt $cur.end) { $cur.end = $e }
        } else {
            $merged.Add($cur)
            $cur = @{ start = $s; end = $e }
        }
    }
    $merged.Add($cur)
    return $merged.ToArray()
}

function Test-RulePortsValid {
    param($Rule)
    foreach ($field in @('local_port', 'remote_port')) {
        $list = $Rule[$field]
        if (-not $list -or @($list).Count -le 1) { continue }
        $sorted = @($list | Sort-Object { [int]$_.start })
        for ($i = 0; $i -lt ($sorted.Count - 1); $i++) {
            if ([int]$sorted[$i + 1].start -le [int]$sorted[$i].end) {
                return @{
                    valid = $false
                    field = $field
                    issue = "overlap [$($sorted[$i].start)-$($sorted[$i].end)] vs [$($sorted[$i+1].start)-$($sorted[$i+1].end)]"
                }
            }
        }
    }
    return @{ valid = $true; field = ''; issue = '' }
}

function Get-ConnectionPorts {
    param([string]$RuleName = '', $Connections)
    $local  = [System.Collections.Generic.List[hashtable]]::new()
    $remote = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($c in $Connections) {
        foreach ($p in ($c.ports | Where-Object { $_ })) {
            $start = [int]$p.start
            if ($start -eq 0) { continue }  # SEP uses port 0 as "any port" — no constraint in CS
            $end   = if ($null -ne $p.end) { [int]$p.end } else { $start }
            if ($end -lt $start) { $end = $start }
            if ($p.location -eq 'LOCAL') { $local.Add(@{ start = $start; end = $end }) }
            else                         { $remote.Add(@{ start = $start; end = $end }) }
        }
    }

    $localArr  = Merge-PortRanges $local.ToArray()
    $remoteArr = Merge-PortRanges $remote.ToArray()

    if ($local.Count -gt 0 -or $remote.Count -gt 0) {
        $rawL = ($local  | ForEach-Object { "$($_.start)-$($_.end)" }) -join ','
        $rawR = ($remote | ForEach-Object { "$($_.start)-$($_.end)" }) -join ','
        $mL   = if ($localArr)  { ($localArr  | ForEach-Object { "$($_.start)-$($_.end)" }) -join ',' } else { '' }
        $mR   = if ($remoteArr) { ($remoteArr | ForEach-Object { "$($_.start)-$($_.end)" }) -join ',' } else { '' }
        Write-FileLog "  [$RuleName] ports raw   local=[$rawL] remote=[$rawR]" INFO
        Write-FileLog "  [$RuleName] ports merged local=[$mL]  remote=[$mR]" INFO
    }

    return @{ local = $localArr; remote = $remoteArr }
}

function Test-IsEtherTypeRule {
    param($Rule)
    foreach ($c in ($Rule.connections | Where-Object { $_ })) {
        if ($null -ne $c.ether_type_id) { return $true }
    }
    return $false
}

function Test-IsFragmentRule {
    param($Rule)
    foreach ($c in ($Rule.connections | Where-Object { $_ })) {
        if ($c.ip_fragmented_only -eq $true) { return $true }
    }
    return $false
}

function Get-EtherTypeName {
    param($Rule)
    foreach ($c in ($Rule.connections | Where-Object { $_ })) {
        if ($null -ne $c.ether_type_id) {
            $id = [int]$c.ether_type_id
            if ($script:EtherTypeNames.ContainsKey($id)) { return $script:EtherTypeNames[$id] }
            return "EtherType 0x$($id.ToString('X4'))"
        }
    }
    return 'Unknown EtherType'
}

function ConvertFrom-IpRange {
    # Converts an IP range "a.b.c.d-e.f.g.h" to the minimal covering set of CIDR objects.
    param([string]$Start, [string]$End)
    function IPToInt([string]$ip) {
        $p = $ip -split '\.'; [int64]([int64]$p[0]*16777216+[int64]$p[1]*65536+[int64]$p[2]*256+[int64]$p[3])
    }
    function IntToIP([int64]$n) {
        "$([int]($n -shr 24)-band 0xFF).$([int]($n -shr 16)-band 0xFF).$([int]($n -shr 8)-band 0xFF).$([int]$n-band 0xFF)"
    }
    $results = [System.Collections.Generic.List[hashtable]]::new()
    $curr = IPToInt $Start
    $last = IPToInt $End
    while ($curr -le $last) {
        $alignBits = 0; $tmp = $curr
        while ($alignBits -lt 32 -and ($tmp -band 1) -eq 0) { $alignBits++; $tmp = $tmp -shr 1 }
        $sizeBits  = [int][Math]::Floor([Math]::Log($last - $curr + 1, 2))
        $bits      = [Math]::Min($alignBits, $sizeBits)
        $results.Add(@{ address = IntToIP $curr; netmask = 32 - $bits })
        $curr += [int64][Math]::Pow(2, $bits)
    }
    return $results.ToArray()
}

function Resolve-HostEntry {
    # Returns a list of typed host objects from a SEP hosts[] entry.
    # A single entry may carry both a group tag AND the actual host data.
    param($Entry)

    $results = [System.Collections.Generic.List[hashtable]]::new()

    # MAC address -> hard blocker, return special type
    if ($Entry.mac -and $Entry.mac -ne '') {
        $results.Add(@{ type = 'mac'; value = $Entry.mac; groupName = '' })
        return $results.ToArray()
    }

    $groupName = if ($Entry.group_name) { $Entry.group_name } else { '' }

    # ip_range
    if ($Entry.ip_range -and $Entry.ip_range.ip_start) {
        $results.Add(@{
            type      = 'range'
            value     = "$($Entry.ip_range.ip_start)-$($Entry.ip_range.ip_end)"
            groupName = $groupName
        })
    }
    # subnet (CIDR)
    if ($Entry.subnet -and $Entry.subnet -ne '') {
        $results.Add(@{ type = 'cidr'; value = $Entry.subnet; groupName = $groupName })
    }
    # single IP
    if ($Entry.ip -and $Entry.ip -ne '') {
        $results.Add(@{ type = 'ip'; value = $Entry.ip; groupName = $groupName })
    }
    # dns_domain (FQDN / wildcard)
    if ($Entry.dns_domain -and $Entry.dns_domain -ne '') {
        # Strip URL path component — CS FW only supports hostname/wildcard, not paths
        $fqdnVal = ($Entry.dns_domain -split '/')[0].Trim().ToLower()
        if ($fqdnVal -ne '') { $results.Add(@{ type = 'fqdn'; value = $fqdnVal; groupName = $groupName }) }
    }
    # dns_host (single hostname -> treat as FQDN)
    if ($Entry.dns_host -and $Entry.dns_host -ne '') {
        $fqdnVal = ($Entry.dns_host -split '/')[0].Trim().ToLower()
        if ($fqdnVal -ne '') { $results.Add(@{ type = 'fqdn'; value = $fqdnVal; groupName = $groupName }) }
    }
    # group_only entry (group reference with no actual data)
    if ($results.Count -eq 0 -and $groupName -ne '') {
        $results.Add(@{ type = 'group_placeholder'; value = ''; groupName = $groupName })
    }

    return $results.ToArray()
}

function ConvertTo-CidrObject {
    param([string]$Value)
    # Returns @{ address = '...'; netmask = N }
    if ($Value -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
        return @{ address = $Matches[1]; netmask = [int]$Matches[2] }
    }
    if ($Value -match '^\d{1,3}(?:\.\d{1,3}){3}$') {
        return @{ address = $Value; netmask = 32 }
    }
    # Range notation is not a valid CS FW address — callers must use ConvertFrom-IpRange
    return $null
}

#endregion

# ─────────────────────────────────────────────────────────────────────────────────
#region RULE CLASSIFIER
# ─────────────────────────────────────────────────────────────────────────────────

function Get-RuleClassification {
    param($Rule, [string]$VpnLocName)

    $blockers     = [System.Collections.Generic.List[string]]::new()
    $adaptations  = [System.Collections.Generic.List[string]]::new()

    $conns     = @($Rule.connections | Where-Object { $_ })
    $hosts     = @($Rule.hosts      | Where-Object { $_ })
    $apps      = @($Rule.applications | Where-Object { $_ })
    $adapters  = @($Rule.adapters   | Where-Object { $_ })

    # ── Hard blockers ────────────────────────────────────────────────────────────
    if (Test-IsEtherTypeRule $Rule) {
        $name = Get-EtherTypeName $Rule
        $blockers.Add("EtherType rule ($name)  -  CS FW operates at L3/L4 only")
    }

    foreach ($h in $hosts) {
        if ($h.mac -and $h.mac -ne '') {
            $blockers.Add("MAC address filter ($($h.mac))  -  not supported in CS FW")
            break
        }
    }

    if (Test-IsFragmentRule $Rule) {
        $blockers.Add("ip_fragmented_only=true  -  CS FW is stateful (WFP), not packet-level; drop this rule")
    }

    if ($blockers.Count -gt 0) {
        return @{ status = 'Blocker'; blockers = $blockers.ToArray(); adaptations = @() }
    }

    # ── Adaptations needed ───────────────────────────────────────────────────────
    $direction = Get-ConnectionDirection $conns
    $protos    = Get-ConnectionProtocols $conns
    $hasFqdn   = $false
    $hasRange  = $false
    $groupNames = [System.Collections.Generic.List[string]]::new()

    foreach ($h in $hosts) {
        $resolved = Resolve-HostEntry $h
        foreach ($r in $resolved) {
            if ($r.type -eq 'fqdn')             { $hasFqdn = $true }
            if ($r.type -eq 'range')            { $hasRange = $true }
            if ($r.groupName -and -not $groupNames.Contains($r.groupName)) {
                $groupNames.Add($r.groupName)
            }
        }
    }

    if ($hasFqdn -and $direction -eq 2) {
        $adaptations.Add("FQDN host with direction=Both -> changed to Outbound (CS FW: FQDNs are outbound-only; stateful engine allows return traffic)")
    } elseif ($hasFqdn -and $direction -eq 1) {
        $adaptations.Add("FQDN host with direction=Inbound -> changed to Outbound (CS FW: FQDNs are outbound-only)")
    }

    if ($hasRange) {
        $adaptations.Add("IP range host(s) -> converted to minimal CIDR block(s) (CS FW does not support range notation)")
    }

    if ($groupNames.Count -gt 0) {
        $adaptations.Add("Host group(s): [$($groupNames -join ', ')]  -  group members embedded in JSON and will be expanded inline")
    }

    foreach ($a in $adapters) {
        if ($a.type -eq 'VPN') {
            $adaptations.Add("Adapter filter=VPN -> Network Location '$VpnLocName' will be referenced (must be pre-created in CS FW)")
            break
        }
    }

    foreach ($app in $apps) {
        if ($app.name -and $app.name -ne '*') {
            $path = $app.name
            if ($path -notmatch '[/\\]') {
                $adaptations.Add("Application path is filename-only ('$path') -> converted to glob pattern **\\$path")
            } elseif ($path -match '^[A-Za-z]:\\') {
                $adaptations.Add("Application path has drive letter ('$path') -> CS FW glob paths use ** prefix (no drive letter)")
            }
        }
    }

    foreach ($c in $conns) {
        if ($c.icmp_types -and @($c.icmp_types).Count -gt 0) {
            $adaptations.Add("ICMP type filtering not supported in CS FW user rules -> rule will allow all ICMPv4")
            break
        }
    }

    if ($protos.Count -gt 1) {
        $protoNames = $protos | ForEach-Object { if ($script:ProtocolMap.$_) { $script:ProtocolMap.$_ } else { "$_" } }
        $adaptations.Add("Multiple protocols ($($protoNames -join ', ')) -> split into $($protos.Count) separate CS FW rules")
    }

    $status = if ($adaptations.Count -gt 0) { 'Adaptation' } else { 'Direct' }
    return @{ status = $status; blockers = @(); adaptations = $adaptations.ToArray() }
}

#endregion

# ─────────────────────────────────────────────────────────────────────────────────
#region RULE CONVERTER
# ─────────────────────────────────────────────────────────────────────────────────

function Convert-SepRuleToCs {
    param(
        $SepRule,
        $Classification,
        [string]$VpnLocId,
        [string]$VpnLocName
    )

    $csRules = [System.Collections.Generic.List[hashtable]]::new()
    if ($Classification.status -eq 'Blocker') { return , $csRules.ToArray() }

    $conns    = @($SepRule.connections | Where-Object { $_ })
    $hosts    = @($SepRule.hosts       | Where-Object { $_ })
    $apps     = @($SepRule.applications | Where-Object { $_ })
    $adapters = @($SepRule.adapters     | Where-Object { $_ })

    $direction = Get-ConnectionDirection $conns
    $protos    = Get-ConnectionProtocols $conns
    $ports     = Get-ConnectionPorts -RuleName $SepRule.name -Connections $conns
    $csAction  = if ($SepRule.action -eq 'ALLOW') { 'ALLOW' } else { 'DENY' }

    # ── Collect addresses ────────────────────────────────────────────────────────
    $remoteIpAddrs  = [System.Collections.Generic.List[hashtable]]::new()
    $remoteFqdns    = [System.Collections.Generic.List[string]]::new()
    $localAddrs     = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($h in $hosts) {
        $resolved = Resolve-HostEntry $h
        foreach ($r in $resolved) {
            switch ($r.type) {
                'ip'    { $obj = ConvertTo-CidrObject $r.value; if ($obj) { $remoteIpAddrs.Add($obj) } }
                'cidr'  { $obj = ConvertTo-CidrObject $r.value; if ($obj) { $remoteIpAddrs.Add($obj) } }
                'range' {
                    $parts = $r.value -split '-', 2
                    foreach ($c in (ConvertFrom-IpRange $parts[0] $parts[1])) { $remoteIpAddrs.Add($c) }
                }
                'fqdn'  { if (-not $remoteFqdns.Contains($r.value)) { $remoteFqdns.Add($r.value) } }
                'group_placeholder' {
                    # Group with no resolvable host data  -  use wildcard with a comment
                    $remoteIpAddrs.Add(@{ address = '*'; netmask = 0 })
                }
            }
        }
    }

    # Default: any local
    $localAddrs.Add(@{ address = '*'; netmask = 0 })

    # ── Application path ─────────────────────────────────────────────────────────
    $imageName = ''
    foreach ($app in $apps) {
        if ($app.name -and $app.name -ne '*') {
            $p = $app.name
            # Remove drive letter for glob compatibility
            $p = $p -replace '^[A-Za-z]:\\', '**\'
            # Filename only -> prepend glob
            if ($p -notmatch '[/\\]') { $p = "**\$p" }
            $imageName = $p
            break
        }
    }

    # ── VPN Network Location ─────────────────────────────────────────────────────
    $netLocIds = @()
    $hasVpn    = $adapters | Where-Object { $_.type -eq 'VPN' }
    if ($hasVpn -and $VpnLocId -and $VpnLocId.Trim() -ne '') {
        $netLocIds = @($VpnLocId.Trim())
    }

    # ── FQDN direction fix ───────────────────────────────────────────────────────
    $effectiveDirection = $direction
    if ($remoteFqdns.Count -gt 0 -and $direction -eq 2) { $effectiveDirection = 0 }
    $csDir = $script:DirectionMap[$effectiveDirection]

    # ── Build description ────────────────────────────────────────────────────────
    $descParts = @()
    if ($SepRule.desc -and $SepRule.desc.Trim() -ne '') { $descParts += $SepRule.desc.Trim() }
    if ($Classification.adaptations.Count -gt 0) {
        $descParts += "[Migrated with adaptations: $($Classification.adaptations -join ' | ')]"
    }
    $description = ($descParts -join '  -  ')
    if ($description.Length -gt 500) { $description = $description.Substring(0, 497) + '...' }

    # ── Protocol list ─────────────────────────────────────────────────────────────
    if ($protos.Count -eq 0) { $protos = @(0) }  # 0 = ANY

    # ── Create one CS rule per protocol (and per FQDN if multiple) ───────────────
    foreach ($proto in $protos) {
        $csProto   = if ($proto -eq 0) { '' } elseif ($script:ProtocolMap.ContainsKey($proto)) { $script:ProtocolMap[$proto] } else { "$proto" }
        $protoSuffix = if ($protos.Count -gt 1) { " [$csProto]" } else { '' }

        # FQDN sub-rules (one per FQDN  -  CS FW supports one FQDN per rule)
        foreach ($fqdn in $remoteFqdns) {
            $fqdnSuffix = if ($remoteFqdns.Count -gt 1 -or $remoteIpAddrs.Count -gt 0) { " [FQDN:$fqdn]" } else { '' }
            $rule = Build-CsRule `
                -Name        (Limit-RuleName $SepRule.name "$protoSuffix$fqdnSuffix") `
                -Description $description `
                -Enabled     ([bool]$SepRule.rulestate.enabled) `
                -Action      $csAction `
                -Direction   'OUT'  `
                -Protocol    $csProto `
                -LocalAddr   $localAddrs.ToArray() `
                -RemoteAddr  @(@{ address = '*'; netmask = 0 }) `
                -Fqdn        $fqdn `
                -LocalPort   $ports.local `
                -RemotePort  $ports.remote `
                -ImageName   $imageName `
                -NetLocIds   $netLocIds
            $csRules.Add($rule)
        }

        # IP/CIDR sub-rules
        $remoteAddr = if ($remoteIpAddrs.Count -gt 0) {
            $remoteIpAddrs.ToArray()
        } elseif ($remoteFqdns.Count -eq 0) {
            @(@{ address = '*'; netmask = 0 })
        } else {
            $null
        }

        if ($remoteAddr) {
            $rule = Build-CsRule `
                -Name        (Limit-RuleName $SepRule.name $protoSuffix) `
                -Description $description `
                -Enabled     ([bool]$SepRule.rulestate.enabled) `
                -Action      $csAction `
                -Direction   $csDir `
                -Protocol    $csProto `
                -LocalAddr   $localAddrs.ToArray() `
                -RemoteAddr  $remoteAddr `
                -LocalPort   $ports.local `
                -RemotePort  $ports.remote `
                -ImageName   $imageName `
                -NetLocIds   $netLocIds
            $csRules.Add($rule)
        }
    }

    return , $csRules.ToArray()
}

function Limit-RuleName {
    param([string]$Base, [string]$Suffix = '')
    $full = "$Base$Suffix"
    if ($full.Length -le $script:MaxRuleNameLen) { return $full }
    $available = $script:MaxRuleNameLen - $Suffix.Length - 3
    if ($available -lt 1) { return $Suffix.Substring(0, [Math]::Min($script:MaxRuleNameLen, $Suffix.Length)) }
    return "$($Base.Substring(0, $available))...$Suffix"
}

function Build-CsRule {
    param(
        [string]   $Name,
        [string]   $Description,
        [bool]     $Enabled,
        [string]   $Action,
        [string]   $Direction,
        [string]   $Protocol,
        [object[]] $LocalAddr,
        [object[]] $RemoteAddr,
        [string]   $Fqdn        = '',
        [object[]] $LocalPort   = @(),
        [object[]] $RemotePort  = @(),
        [string]   $ImageName   = '',
        [object[]] $NetLocIds   = @()
    )

    # Derive address family from protocol: ICMPv6 (58) and IPv6 encap (41) are IP6, everything else IP4
    $addressFamily = if ($Protocol -eq 'ICMPv6' -or $Protocol -eq '58' -or $Protocol -eq '41') { 'IP6' } else { 'IP4' }

    # CS FW API requires '*' or a numeric string '0'-'255' — convert named protocols to their IANA numbers
    $apiProto = switch ($Protocol) {
        'ICMPv4' { '1'  }
        'TCP'    { '6'  }
        'UDP'    { '17' }
        'ICMPv6' { '58' }
        ''       { '*'  }
        default  { $Protocol }   # already numeric ('41', '50') or '*'
    }

    # Build fields array — network_location is always required; image_name goes here too (not top-level)
    # [string[]] cast prevents PowerShell's single-element array unwrapping in expression context:
    #   `if (...) { @('ANY') }` returns the string 'ANY', not the array @('ANY')
    $fields = [System.Collections.Generic.List[hashtable]]::new()
    [string[]]$netLocValues = if ($NetLocIds.Count -gt 0) { $NetLocIds } else { @('ANY') }
    $fields.Add(@{
        name   = 'network_location'
        type   = 'set'
        values = $netLocValues
    })
    if ($ImageName -ne '') {
        $fields.Add(@{ name = 'image_name'; type = 'windows_path'; value = $ImageName })
    }

    $r = [ordered]@{
        name           = $Name
        description    = $Description
        enabled        = $Enabled
        action         = $Action
        direction      = $Direction
        address_family = $addressFamily
        protocol       = $apiProto
        fqdn           = $Fqdn
        fqdn_enabled   = ($Fqdn -ne '')
        local_address  = $LocalAddr
        remote_address = $RemoteAddr
        fields         = $fields.ToArray()
    }
    # ICMP/ESP/IPv6-encap have no port concept — keep using human-readable $Protocol for these checks
    $supportsPort = $Protocol -eq '' -or $Protocol -eq 'TCP' -or $Protocol -eq 'UDP'
    # For outbound rules the source port is always ephemeral — never constrain it.
    # local_port is only meaningful for IN/BOTH (where it represents the destination port).
    $useLocalPort = $supportsPort -and $Direction -ne 'OUT' -and $LocalPort.Count -gt 0
    if ($useLocalPort)                                      { $r['local_port']  = $LocalPort }
    if ($supportsPort -and $RemotePort.Count -gt 0)         { $r['remote_port'] = $RemotePort }

    return $r
}

#endregion

# ─────────────────────────────────────────────────────────────────────────────────
#region MIGRATION
# ─────────────────────────────────────────────────────────────────────────────────

function Write-ExpansionSummary {
    param(
        [object]   $Log,
        [object[]] $AnalysisResults
    )

    $nonBlocked  = @($AnalysisResults | Where-Object { $_.classification.status -ne 'Blocker' })
    $blocked     = @($AnalysisResults | Where-Object { $_.classification.status -eq 'Blocker' })
    $sepTotal    = $AnalysisResults.Count
    $csTotal     = ($nonBlocked | ForEach-Object { $_.csRules.Count } | Measure-Object -Sum).Sum

    Write-UILog $Log '' Info
    Write-UILog $Log "── Expansion: $sepTotal SEP rules  ->  $csTotal CS rules" Info

    foreach ($r in $AnalysisResults) {
        $name    = $r.sepRule.name
        $display = if ($name.Length -gt 44) { $name.Substring(0, 41) + '...' } else { $name }

        if ($r.classification.status -eq 'Blocker') {
            $reason = $r.classification.blockers[0] -replace '\s*-+\s*.+$', ''
            Write-UILog $Log "  [Not Migrated] $display  ->  $reason" Error
            continue
        }

        $csCount   = $r.csRules.Count
        $fqdns     = @($r.csRules | Where-Object { $_.fqdn_enabled } | ForEach-Object { $_.fqdn } | Sort-Object -Unique)
        $protos    = @($r.csRules | ForEach-Object { $_.protocol } | Sort-Object -Unique)
        $ipRules   = @($r.csRules | Where-Object { -not $_.fqdn_enabled }).Count

        $parts = @()
        if ($fqdns.Count -gt 0)  { $parts += "$($fqdns.Count) FQDN(s)" }
        if ($ipRules -gt 0)      { $parts += "$ipRules IP/CIDR rule(s)" }
        if ($protos.Count -gt 1) { $parts += "$($protos.Count) protocols" }

        $reason = if ($parts) { " ($($parts -join ' + '))" } else { '' }
        $arrow  = "1 -> $csCount"
        $level  = if ($csCount -gt 1) { 'Warning' } else { 'Info' }
        Write-UILog $Log ("  {0,-46} {1,-8}{2}" -f $display, $arrow, $reason) $level
    }

    if ($blocked.Count -gt 0) {
        Write-UILog $Log '' Info
        Write-UILog $Log "  $($blocked.Count) rule(s) not migrated: $(($blocked | ForEach-Object { $_.sepRule.name }) -join ', ')" Error
    }
    Write-UILog $Log '──' Info
}

function Start-Migration {
    param(
        [object[]] $CsRules,
        [string]   $GroupName,
        [string]   $PolicyName,
        [string]   $Platform,
        [string]   $DefaultInbound,
        [string]   $DefaultOutbound,
        [bool]     $MonitorMode,
        [object[]] $AnalysisResults = @(),
        [System.Windows.Forms.RichTextBox] $Log,
        [System.Windows.Forms.ProgressBar] $ProgressBar
    )

    $step  = 0
    $total = 3

    function Step { param([string]$msg, [string]$level='Info')
        $script:step++
        Write-UILog $Log $msg $level
        $pct = [int](($script:step / $total) * 100)
        if ($pct -gt 100) { $pct = 100 }
        $ProgressBar.Value = $pct
        [System.Windows.Forms.Application]::DoEvents()
    }

    Write-UILog $Log "Preparing $($CsRules.Count) CS FW rules..." Info

    # ── Pre-flight port validation ────────────────────────────────────────────────
    Write-FileLog "--- Pre-flight port dump ($($CsRules.Count) rules) ---" INFO
    $goodRules = [System.Collections.Generic.List[hashtable]]::new()
    $skipCount = 0
    foreach ($r in $CsRules) {
        $lp = if ($r.local_port  -and @($r.local_port).Count  -gt 0) { ($r.local_port  | ForEach-Object { "$($_.start)-$($_.end)" }) -join ',' } else { 'any' }
        $rp = if ($r.remote_port -and @($r.remote_port).Count -gt 0) { ($r.remote_port | ForEach-Object { "$($_.start)-$($_.end)" }) -join ',' } else { 'any' }
        Write-FileLog "  '$($r.name)' proto=$($r.protocol) dir=$($r.direction) addr=$($r.address_family) local_port=[$lp] remote_port=[$rp]" INFO
        $check = Test-RulePortsValid $r
        if ($check.valid) {
            $goodRules.Add($r)
        } else {
            $msg = "Port conflict in '$($r.name)' ($($check.field)): $($check.issue)"
            Write-FileLog "  SKIP — $msg" ERROR
            Write-UILog $Log "  Skip: $msg" Warning
            $skipCount++
        }
    }
    if ($skipCount -gt 0) {
        Write-UILog $Log "  $skipCount rule(s) skipped (port conflicts). $($goodRules.Count) proceeding." Warning
        $CsRules = $goodRules.ToArray()
        if ($CsRules.Count -eq 0) {
            Write-UILog $Log 'No valid rules remaining after port validation.' Error
            return $null
        }
    } else {
        Write-UILog $Log '  Pre-flight OK — all port ranges valid.' Success
    }

    # ── Convert single-port ranges to API format ─────────────────────────────────
    # CS FW API convention: {start=N, end=0} for a single port; {start=N, end=M} for ranges.
    # {start=N, end=N} is rejected ("Duplicate ports listed in range").
    # Port 0 entries are already filtered in Get-ConnectionPorts so end=0 is safe here.
    Write-FileLog "--- Converting ports to API format ---" INFO
    foreach ($r in $CsRules) {
        foreach ($field in @('local_port', 'remote_port')) {
            if ($r[$field] -and @($r[$field]).Count -gt 0) {
                $r[$field] = @(@($r[$field]) | ForEach-Object {
                    $s = [int]$_.start; $e = [int]$_.end
                    if ($s -eq $e) { @{ start = $s; end = 0 } } else { @{ start = $s; end = $e } }
                })
            }
        }
    }
    # Log first rule JSON to verify format
    if ($CsRules.Count -gt 0) {
        try {
            $sample = $CsRules[0] | ConvertTo-Json -Depth 8 -Compress
            Write-FileLog "SAMPLE RULE JSON: $sample" INFO
        } catch {}
    }

    # Step 1  -  Create Rule Group
    Step "Creating rule group '$GroupName'..." Info
    try {
        $platformParam  = $Platform.ToLower()
        $effectiveName  = $GroupName
        $group = $null
        for ($attempt = 1; $attempt -le 2; $attempt++) {
            try {
                $group = New-FalconFirewallGroup -Name $effectiveName -Enabled $true `
                             -Platform $platformParam -Rule $CsRules -ErrorAction Stop
                break
            } catch {
                if ($attempt -eq 1 -and "$_" -match 'Duplicate rule group name') {
                    $effectiveName = "$GroupName ($(Get-Date -Format 'yyyyMMdd-HHmm'))"
                    Write-UILog $Log "  Name already exists — retrying as '$effectiveName'" Warning
                } else {
                    throw
                }
            }
        }
        # PSFalcon returns the rule group ID as a plain string (resources: ["id"]),
        # but some versions return an object — handle both
        $groupId = if ($group -is [string]) { $group } elseif ($group.id) { $group.id } else { [string]$group }
        if ($groupId -notmatch '^[a-fA-F0-9]{32}$') {
            throw "Unexpected rule group response (could not extract 32-char hex ID). Raw: $($group | ConvertTo-Json -Compress -Depth 3)"
        }
        Write-UILog $Log "  Rule group created  ->  ID: $groupId" Success
    } catch {
        Write-UILog $Log "Failed to create rule group: $_" Error
        return $null
    }

    # Step 2  -  Create Policy
    Step "Creating firewall policy '$PolicyName'..." Info
    try {
        $effectivePolicyName = $PolicyName
        $policy = $null
        for ($attempt = 1; $attempt -le 2; $attempt++) {
            try {
                $policy = New-FalconFirewallPolicy -Name $effectivePolicyName -PlatformName $Platform `
                              -Description "Migrated from SEP  -  $(Get-Date -Format 'yyyy-MM-dd')" `
                              -ErrorAction Stop
                break
            } catch {
                if ($attempt -eq 1 -and "$_" -match 'Duplicate') {
                    $effectivePolicyName = "$PolicyName ($(Get-Date -Format 'yyyyMMdd-HHmm'))"
                    Write-UILog $Log "  Policy name already exists — retrying as '$effectivePolicyName'" Warning
                } else {
                    throw
                }
            }
        }
        $policyId = if ($policy -is [string]) { $policy } elseif ($policy.id) { $policy.id } else { [string]$policy }
        Write-UILog $Log "  Policy created  ->  ID: $policyId" Success
    } catch {
        Write-UILog $Log "Failed to create policy: $_" Error
        return $null
    }

    # Step 3  -  Configure settings (link rule group + defaults)
    Step "Configuring policy settings..." Info
    try {
        $platformId = if ($Platform -eq 'Windows') { '0' } else { '1' }
        Edit-FalconFirewallSetting -Id $policyId `
            -PlatformId $platformId `
            -Enforce    $false `
            -DefaultInbound  $DefaultInbound `
            -DefaultOutbound $DefaultOutbound `
            -MonitorMode     $MonitorMode `
            -RuleGroupId     @($groupId) `
            -ErrorAction Stop
        Write-UILog $Log "  Policy settings configured." Success
    } catch {
        Write-UILog $Log "Failed to configure policy settings: $_" Error
        Write-UILog $Log "  Rule group was created ($groupId)  -  link manually in Falcon console." Warning
    }

    $ProgressBar.Value = 100
    if ($AnalysisResults.Count -gt 0) {
        Write-ExpansionSummary -Log $Log -AnalysisResults $AnalysisResults
    }
    Write-UILog $Log '─────────────────────────────────────────────' Info
    Write-UILog $Log 'Migration complete!' Success
    Write-UILog $Log "  Rule Group ID : $groupId" Info
    Write-UILog $Log "  Policy ID     : $policyId" Info
    Write-UILog $Log "  CS rules created : $($CsRules.Count)" Info
    Write-UILog $Log '' Info
    Write-UILog $Log 'NEXT STEPS:' Warning
    Write-UILog $Log '  1. In Falcon console -> Endpoint security -> Firewall -> Policies' Info
    Write-UILog $Log '  2. Assign the new policy to your target Host Groups.' Info
    Write-UILog $Log '  3. Validate in Monitor Mode before switching to Enforce.' Info
    if ($MonitorMode) {
        Write-UILog $Log '  4. The policy is in MONITOR MODE  -  all traffic is allowed, blocks are logged.' Warning
    }

    return @{ groupId = $groupId; policyId = $policyId }
}

#endregion

# ─────────────────────────────────────────────────────────────────────────────────
#region REPORT EXPORT
# ─────────────────────────────────────────────────────────────────────────────────

function Export-MigrationReport {
    param([string]$Path)

    $rows = foreach ($r in $script:AnalysisResults) {
        [PSCustomObject]@{
            RuleName        = $r.sepRule.name
            Action          = $r.sepRule.action
            Direction       = $r.directionLabel
            Protocols       = $r.protocolStr
            Status          = $r.classification.status
            CsRulesCreated  = $r.csRules.Count
            Blockers        = ($r.classification.blockers    -join ' | ')
            Adaptations     = ($r.classification.adaptations -join ' | ')
        }
    }
    $rows | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
}

#endregion

# ─────────────────────────────────────────────────────────────────────────────────
#region GUI HELPERS
# ─────────────────────────────────────────────────────────────────────────────────

function Write-UILog {
    param(
        [System.Windows.Forms.RichTextBox]$Box,
        [string]$Message,
        [ValidateSet('Info','Success','Warning','Error')]
        [string]$Level = 'Info'
    )
    if (-not $Box) { return }
    $color = switch ($Level) {
        'Success' { [System.Drawing.Color]::FromArgb(0,  200, 90) }
        'Warning' { [System.Drawing.Color]::FromArgb(230,160,  0) }
        'Error'   { [System.Drawing.Color]::FromArgb(220, 60, 60) }
        default   { [System.Drawing.Color]::FromArgb(210,210,210) }
    }
    $prefix = switch ($Level) {
        'Success' { '+ ' }
        'Warning' { '! ' }
        'Error'   { 'x ' }
        default   { '  ' }
    }
    $Box.SelectionStart  = $Box.TextLength
    $Box.SelectionLength = 0
    $Box.SelectionColor  = $color
    $Box.AppendText("$prefix$Message`r`n")
    $Box.ScrollToCaret()
    Write-FileLog $Message $Level
}

function New-Btn {
    param([string]$Text,[int]$X,[int]$Y,[int]$W=130,[int]$H=30,[bool]$Primary=$false)
    $b = New-Object System.Windows.Forms.Button
    $b.Text=$Text; $b.Location=New-Object System.Drawing.Point($X,$Y)
    $b.Size=New-Object System.Drawing.Size($W,$H)
    $b.Font=New-Object System.Drawing.Font('Segoe UI',9,[System.Drawing.FontStyle]::Bold)
    $b.FlatStyle=[System.Windows.Forms.FlatStyle]::Flat
    $b.FlatAppearance.BorderSize=1
    if ($Primary){$b.BackColor=[System.Drawing.Color]::FromArgb(204,0,0);$b.ForeColor=[System.Drawing.Color]::White;$b.FlatAppearance.BorderColor=[System.Drawing.Color]::FromArgb(204,0,0)}
    else{$b.BackColor=[System.Drawing.Color]::FromArgb(50,50,50);$b.ForeColor=[System.Drawing.Color]::FromArgb(220,220,220);$b.FlatAppearance.BorderColor=[System.Drawing.Color]::FromArgb(75,75,75)}
    $b.Cursor=[System.Windows.Forms.Cursors]::Hand
    return $b
}
function New-Lbl { param([string]$T,[int]$X,[int]$Y,[int]$W=150,[bool]$Bold=$false)
    $l=New-Object System.Windows.Forms.Label;$l.Text=$T;$l.Location=New-Object System.Drawing.Point($X,$Y)
    $l.Size=New-Object System.Drawing.Size($W,20);$l.ForeColor=[System.Drawing.Color]::FromArgb(210,210,210)
    $l.Font=if($Bold){New-Object System.Drawing.Font('Segoe UI',9,[System.Drawing.FontStyle]::Bold)}else{New-Object System.Drawing.Font('Segoe UI',9)}
    $l.BackColor=[System.Drawing.Color]::Transparent;return $l
}
function New-Tbx { param([int]$X,[int]$Y,[int]$W=260,[bool]$Pw=$false)
    $t=New-Object System.Windows.Forms.TextBox;$t.Location=New-Object System.Drawing.Point($X,$Y)
    $t.Size=New-Object System.Drawing.Size($W,22);$t.Font=New-Object System.Drawing.Font('Segoe UI',9)
    $t.BackColor=[System.Drawing.Color]::FromArgb(55,55,55);$t.ForeColor=[System.Drawing.Color]::FromArgb(220,220,220)
    $t.BorderStyle=[System.Windows.Forms.BorderStyle]::FixedSingle
    if($Pw){$t.PasswordChar=[char]0x25CF};return $t
}
function New-Combo { param([int]$X,[int]$Y,[int]$W=140,[string[]]$Items)
    $c=New-Object System.Windows.Forms.ComboBox;$c.Location=New-Object System.Drawing.Point($X,$Y)
    $c.Size=New-Object System.Drawing.Size($W,22);$c.Font=New-Object System.Drawing.Font('Segoe UI',9)
    $c.BackColor=[System.Drawing.Color]::FromArgb(55,55,55);$c.ForeColor=[System.Drawing.Color]::FromArgb(220,220,220)
    $c.FlatStyle=[System.Windows.Forms.FlatStyle]::Flat
    $c.DropDownStyle=[System.Windows.Forms.ComboBoxStyle]::DropDownList
    foreach($i in $Items){$c.Items.Add($i)|Out-Null}
    $c.SelectedIndex=0;return $c
}
function New-Grp { param([string]$T,[int]$X,[int]$Y,[int]$W,[int]$H)
    $g=New-Object System.Windows.Forms.GroupBox;$g.Text=$T;$g.Location=New-Object System.Drawing.Point($X,$Y)
    $g.Size=New-Object System.Drawing.Size($W,$H);$g.ForeColor=[System.Drawing.Color]::FromArgb(200,200,200)
    $g.Font=New-Object System.Drawing.Font('Segoe UI',9,[System.Drawing.FontStyle]::Bold)
    $g.BackColor=[System.Drawing.Color]::FromArgb(42,42,42);return $g
}

#endregion

# ─────────────────────────────────────────────────────────────────────────────────
#region MAIN FORM
# ─────────────────────────────────────────────────────────────────────────────────

$clrBg     = [System.Drawing.Color]::FromArgb(30,30,30)
$clrPanel  = [System.Drawing.Color]::FromArgb(42,42,42)
$clrAccent = [System.Drawing.Color]::FromArgb(204,0,0)
$clrText   = [System.Drawing.Color]::FromArgb(220,220,220)
$clrMuted  = [System.Drawing.Color]::FromArgb(130,130,130)
$clrOk     = [System.Drawing.Color]::FromArgb(0,200,90)
$clrWarn   = [System.Drawing.Color]::FromArgb(230,160,0)
$clrErr    = [System.Drawing.Color]::FromArgb(220,60,60)
$fntMono   = New-Object System.Drawing.Font('Consolas',8.5)
$fntBold   = New-Object System.Drawing.Font('Segoe UI',9,[System.Drawing.FontStyle]::Bold)

$form = New-Object System.Windows.Forms.Form
$form.Text            = 'SEP  ->  CrowdStrike Firewall Management Migrator  v1.0'
$form.Size            = New-Object System.Drawing.Size(960,760)
$form.MinimumSize     = New-Object System.Drawing.Size(960,700)
$form.BackColor       = $clrBg
$form.ForeColor       = $clrText
$form.Font            = New-Object System.Drawing.Font('Segoe UI',9)
$form.StartPosition   = [System.Windows.Forms.FormStartPosition]::CenterScreen

# ── Header ───────────────────────────────────────────────────────────────────────
$hdr = New-Object System.Windows.Forms.Panel
$hdr.Dock=$([System.Windows.Forms.DockStyle]::Top);$hdr.Height=52;$hdr.BackColor=$clrAccent
$form.Controls.Add($hdr)

$hdrLbl = New-Object System.Windows.Forms.Label
$hdrLbl.Text='  SEP  ->  CrowdStrike Firewall Management Migrator'
$hdrLbl.Font=New-Object System.Drawing.Font('Segoe UI',12,[System.Drawing.FontStyle]::Bold)
$hdrLbl.ForeColor=[System.Drawing.Color]::White;$hdrLbl.Dock=[System.Windows.Forms.DockStyle]::Fill
$hdrLbl.TextAlign=[System.Drawing.ContentAlignment]::MiddleLeft
$hdr.Controls.Add($hdrLbl)

# ── TabControl ───────────────────────────────────────────────────────────────────
$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Location=New-Object System.Drawing.Point(8,60);$tabs.Size=New-Object System.Drawing.Size(936,662)
$tabs.Font=New-Object System.Drawing.Font('Segoe UI',10,[System.Drawing.FontStyle]::Bold)
$tabs.Padding=New-Object System.Drawing.Point(16,4)
$form.Controls.Add($tabs)

# ─────────────────────────────────────────────────────────────────────────────────
# TAB 1  -  SETUP
# ─────────────────────────────────────────────────────────────────────────────────
$t1 = New-Object System.Windows.Forms.TabPage
$t1.Text='  1. Setup  ';$t1.BackColor=$clrPanel;$t1.ForeColor=$clrText
$tabs.TabPages.Add($t1)

# Auth group
$grpAuth = New-Grp 'CrowdStrike Authentication' 12 12 912 145
$t1.Controls.Add($grpAuth)

$grpAuth.Controls.Add((New-Lbl 'Client ID:' 12 28 100))
$tbClientId = New-Tbx 120 26 300;$grpAuth.Controls.Add($tbClientId)

$grpAuth.Controls.Add((New-Lbl 'Client Secret:' 12 60 100))
$tbSecret = New-Tbx 120 58 300 $true;$grpAuth.Controls.Add($tbSecret)

$grpAuth.Controls.Add((New-Lbl 'Cloud Region:' 12 92 100))
$cboCloud = New-Combo 120 90 130 @('us-1','us-2','eu-1','us-gov-1')
$grpAuth.Controls.Add($cboCloud)

$btnInstall = New-Btn 'Install / Update PSFalcon' 440 24 200 28
$grpAuth.Controls.Add($btnInstall)

$btnConnect = New-Btn 'Test Connection' 440 62 160 28 $true
$grpAuth.Controls.Add($btnConnect)

$lblConnStatus = New-Lbl '' 614 66 260
$lblConnStatus.Font=$fntBold;$grpAuth.Controls.Add($lblConnStatus)

$grpAuth.Controls.Add((New-Lbl 'OAuth2 scopes required — Firewall management: Read + Write' 12 116 560))
($grpAuth.Controls | Where-Object {$_ -is [System.Windows.Forms.Label] -and $_.Text -match 'OAuth'})[0].ForeColor=$clrMuted
($grpAuth.Controls | Where-Object {$_ -is [System.Windows.Forms.Label] -and $_.Text -match 'OAuth'})[0].Font=New-Object System.Drawing.Font('Segoe UI',8)

# Input files group
$grpFiles = New-Grp 'Input Files' 12 166 912 110
$t1.Controls.Add($grpFiles)

$grpFiles.Controls.Add((New-Lbl 'SEP JSON file *:' 12 28 130))
$tbJson = New-Tbx 150 26 630;$grpFiles.Controls.Add($tbJson)
$btnBrowseJson = New-Btn 'Browse...' 790 24 110 24
$grpFiles.Controls.Add($btnBrowseJson)

$grpFiles.Controls.Add((New-Lbl 'Host Groups CSV:' 12 64 130))
$tbCsv = New-Tbx 150 62 630;$grpFiles.Controls.Add($tbCsv)
$btnBrowseCsv = New-Btn 'Browse...' 790 60 110 24
$grpFiles.Controls.Add($btnBrowseCsv)

$grpFiles.Controls.Add((New-Lbl '(optional  -  only needed if groups in JSON have no inline host data)' 150 85 600))
($grpFiles.Controls | Where-Object {$_ -is [System.Windows.Forms.Label] -and $_.Text -match 'optional'})[0].ForeColor=$clrMuted
($grpFiles.Controls | Where-Object {$_ -is [System.Windows.Forms.Label] -and $_.Text -match 'optional'})[0].Font=New-Object System.Drawing.Font('Segoe UI',8)

# Config import/export group
$grpConfig = New-Grp 'Configuration' 12 284 912 56
$t1.Controls.Add($grpConfig)

$btnExportConfig = New-Btn 'Export Config' 12 18 130 28
$grpConfig.Controls.Add($btnExportConfig)

$btnImportConfig = New-Btn 'Import Config' 152 18 130 28
$grpConfig.Controls.Add($btnImportConfig)

$lblConfigFile = New-Lbl 'No config loaded.' 300 22 590
$lblConfigFile.ForeColor = $clrMuted
$grpConfig.Controls.Add($lblConfigFile)

# Setup log
$rtbSetup = New-Object System.Windows.Forms.RichTextBox
$rtbSetup.Location=New-Object System.Drawing.Point(12,348);$rtbSetup.Size=New-Object System.Drawing.Size(912,276)
$rtbSetup.BackColor=[System.Drawing.Color]::FromArgb(20,20,20);$rtbSetup.ForeColor=$clrText
$rtbSetup.Font=$fntMono;$rtbSetup.ReadOnly=$true;$rtbSetup.BorderStyle=[System.Windows.Forms.BorderStyle]::FixedSingle
$rtbSetup.ScrollBars=[System.Windows.Forms.RichTextBoxScrollBars]::Vertical
$t1.Controls.Add($rtbSetup)

# ─────────────────────────────────────────────────────────────────────────────────
# TAB 2  -  ANALYSIS
# ─────────────────────────────────────────────────────────────────────────────────
$t2 = New-Object System.Windows.Forms.TabPage
$t2.Text='  2. Analysis  ';$t2.BackColor=$clrPanel;$t2.ForeColor=$clrText
$tabs.TabPages.Add($t2)

# Summary strip
$pnlSum = New-Object System.Windows.Forms.Panel
$pnlSum.Location=New-Object System.Drawing.Point(12,12);$pnlSum.Size=New-Object System.Drawing.Size(912,46)
$pnlSum.BackColor=[System.Drawing.Color]::FromArgb(35,35,35);$t2.Controls.Add($pnlSum)

$lblDirect  = New-Lbl '* 0  Direct'            16  8 220 $true
$lblAdapt   = New-Lbl '⚠ 0  Adaptation Required' 250 8 240 $true
$lblBlock   = New-Lbl '✗ 0  Non-migratable'    510  8 220 $true
$lblTotal   = New-Lbl '= 0  Total'             750  8 150 $true
$lblDirect.ForeColor=$clrOk;$lblAdapt.ForeColor=$clrWarn;$lblBlock.ForeColor=$clrErr;$lblTotal.ForeColor=$clrText
foreach($l in @($lblDirect,$lblAdapt,$lblBlock,$lblTotal)){$pnlSum.Controls.Add($l)}

# Toolbar row
$pnlBar = New-Object System.Windows.Forms.Panel
$pnlBar.Location=New-Object System.Drawing.Point(12,66);$pnlBar.Size=New-Object System.Drawing.Size(912,34)
$pnlBar.BackColor=[System.Drawing.Color]::Transparent;$t2.Controls.Add($pnlBar)

$btnAll     = New-Btn 'All'              0  2  80 28
$btnFilt1   = New-Btn 'Direct'          88  2  80 28
$btnFilt2   = New-Btn 'Adaptation'     176  2 100 28
$btnFilt3   = New-Btn 'Non-migratable' 284  2 130 28
$btnAnalyze = New-Btn 'Analyze File'   600  2 130 28 $true
$btnReport  = New-Btn 'Export CSV'     740  2 110 28
foreach($b in @($btnAll,$btnFilt1,$btnFilt2,$btnFilt3,$btnAnalyze,$btnReport)){$pnlBar.Controls.Add($b)}

# DataGridView
$dgv = New-Object System.Windows.Forms.DataGridView
$dgv.Location=New-Object System.Drawing.Point(12,108);$dgv.Size=New-Object System.Drawing.Size(912,460)
$dgv.BackgroundColor=[System.Drawing.Color]::FromArgb(25,25,25)
$dgv.GridColor=[System.Drawing.Color]::FromArgb(55,55,55)
$dgv.ForeColor=$clrText;$dgv.Font=New-Object System.Drawing.Font('Segoe UI',8.5)
$dgv.DefaultCellStyle.BackColor=[System.Drawing.Color]::FromArgb(32,32,32)
$dgv.DefaultCellStyle.ForeColor=$clrText
$dgv.DefaultCellStyle.SelectionBackColor=[System.Drawing.Color]::FromArgb(65,65,100)
$dgv.AlternatingRowsDefaultCellStyle.BackColor=[System.Drawing.Color]::FromArgb(38,38,38)
$dgv.ColumnHeadersDefaultCellStyle.BackColor=[System.Drawing.Color]::FromArgb(50,50,50)
$dgv.ColumnHeadersDefaultCellStyle.ForeColor=$clrText
$dgv.ColumnHeadersDefaultCellStyle.Font=$fntBold
$dgv.ColumnHeadersHeight=28;$dgv.ColumnHeadersHeightSizeMode=[System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode]::DisableResizing
$dgv.RowHeadersVisible=$false;$dgv.AllowUserToAddRows=$false;$dgv.ReadOnly=$true
$dgv.SelectionMode=[System.Windows.Forms.DataGridViewSelectionMode]::FullRowSelect
$dgv.AutoSizeColumnsMode=[System.Windows.Forms.DataGridViewAutoSizeColumnsMode]::None
$dgv.EnableHeadersVisualStyles=$false

@(
    @{H='#';         W=36 }
    @{H='Rule Name'; W=240}
    @{H='Action';    W=58 }
    @{H='Direction'; W=78 }
    @{H='Protocol';  W=78 }
    @{H='Status';    W=100}
    @{H='CS Rules';  W=68 }
    @{H='Notes';     W=240}
) | ForEach-Object {
    $c=New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $c.HeaderText=$_.H;$c.Width=$_.W
    $c.SortMode=[System.Windows.Forms.DataGridViewColumnSortMode]::NotSortable
    $dgv.Columns.Add($c)|Out-Null
}
$t2.Controls.Add($dgv)

# Detail tooltip strip at bottom
$lblDetail = New-Lbl 'Select a rule to see adaptation/blocker details.' 12 576 900
$lblDetail.Size      = New-Object System.Drawing.Size(912, 50)
$lblDetail.AutoSize  = $false
$lblDetail.ForeColor = $clrMuted
$t2.Controls.Add($lblDetail)

# ─────────────────────────────────────────────────────────────────────────────────
# TAB 3  -  MIGRATION
# ─────────────────────────────────────────────────────────────────────────────────
$t3 = New-Object System.Windows.Forms.TabPage
$t3.Text='  3. Migration  ';$t3.BackColor=$clrPanel;$t3.ForeColor=$clrText
$tabs.TabPages.Add($t3)

$grpMig = New-Grp 'Migration Settings' 12 12 912 210
$t3.Controls.Add($grpMig)

$grpMig.Controls.Add((New-Lbl 'Rule Group Name:' 12 30 140))
$tbGroupName=New-Tbx 160 28 420;$tbGroupName.Text='SEP Migration  -  Workstation VPN';$grpMig.Controls.Add($tbGroupName)

$grpMig.Controls.Add((New-Lbl 'Policy Name:' 12 62 140))
$tbPolicyName=New-Tbx 160 60 420;$tbPolicyName.Text='SEP Migration Policy';$grpMig.Controls.Add($tbPolicyName)

$grpMig.Controls.Add((New-Lbl 'Platform:' 12 94 100))
$cboPlatform=New-Combo 160 92 100 @('Windows','Mac');$grpMig.Controls.Add($cboPlatform)

$grpMig.Controls.Add((New-Lbl 'Default Inbound:' 12 126 120))
$cboInbound=New-Combo 160 124 100 @('DENY','ALLOW');$grpMig.Controls.Add($cboInbound)

$grpMig.Controls.Add((New-Lbl 'Default Outbound:' 280 126 130))
$cboOutbound=New-Combo 420 124 100 @('DENY','ALLOW')
$cboOutbound.SelectedIndex=1   # ALLOW for outbound by default
$grpMig.Controls.Add($cboOutbound)

$chkMonitor=New-Object System.Windows.Forms.CheckBox
$chkMonitor.Text='Start in Monitor Mode (recommended  -  all traffic allowed; blocks are logged only)'
$chkMonitor.Location=New-Object System.Drawing.Point(12,158);$chkMonitor.Size=New-Object System.Drawing.Size(800,22)
$chkMonitor.Font=New-Object System.Drawing.Font('Segoe UI',9);$chkMonitor.ForeColor=$clrText
$chkMonitor.Checked=$true;$chkMonitor.FlatStyle=[System.Windows.Forms.FlatStyle]::Flat
$grpMig.Controls.Add($chkMonitor)

$grpMig.Controls.Add((New-Lbl '⚠ CS FW cannot coexist with SEP FW. Plan for cutover, not coexistence.' 12 182 800))
($grpMig.Controls|Where-Object{$_ -is [System.Windows.Forms.Label] -and $_.Text -match 'coexist'})[0].ForeColor=$clrWarn
($grpMig.Controls|Where-Object{$_ -is [System.Windows.Forms.Label] -and $_.Text -match 'coexist'})[0].Font=New-Object System.Drawing.Font('Segoe UI',8.5)

# VPN network location
$grpVpn = New-Grp 'VPN Network Location (for adapter=VPN rules)' 12 232 912 70
$t3.Controls.Add($grpVpn)

$grpVpn.Controls.Add((New-Lbl 'Location Name:' 12 28 120))
$tbVpnName=New-Tbx 140 26 200;$tbVpnName.Text='VPN Connected';$grpVpn.Controls.Add($tbVpnName)

$grpVpn.Controls.Add((New-Lbl 'Location ID (if already created):' 360 28 200))
$tbVpnId=New-Tbx 570 26 250;$grpVpn.Controls.Add($tbVpnId)

$grpVpn.Controls.Add((New-Lbl 'Leave ID blank if not yet created. VPN-scoped rules will have the name noted in the description.' 12 50 800))
($grpVpn.Controls|Where-Object{$_ -is [System.Windows.Forms.Label] -and $_.Text -match 'Leave'})[0].ForeColor=$clrMuted
($grpVpn.Controls|Where-Object{$_ -is [System.Windows.Forms.Label] -and $_.Text -match 'Leave'})[0].Font=New-Object System.Drawing.Font('Segoe UI',8)

# Migrate button + prerequisite label
$btnMigrate = New-Btn 'Start Migration' 12 316 180 36 $true
$btnMigrate.Font=New-Object System.Drawing.Font('Segoe UI',10,[System.Drawing.FontStyle]::Bold)
$t3.Controls.Add($btnMigrate)

$lblPrereq=New-Lbl '' 206 322 700;$lblPrereq.ForeColor=$clrWarn;$t3.Controls.Add($lblPrereq)

# Progress bar
$progBar=New-Object System.Windows.Forms.ProgressBar
$progBar.Location=New-Object System.Drawing.Point(12,362);$progBar.Size=New-Object System.Drawing.Size(912,16)
$progBar.Style=[System.Windows.Forms.ProgressBarStyle]::Continuous
$t3.Controls.Add($progBar)

# Migration log
$rtbMig=New-Object System.Windows.Forms.RichTextBox
$rtbMig.Location=New-Object System.Drawing.Point(12,386);$rtbMig.Size=New-Object System.Drawing.Size(912,242)
$rtbMig.BackColor=[System.Drawing.Color]::FromArgb(20,20,20);$rtbMig.ForeColor=$clrText
$rtbMig.Font=$fntMono;$rtbMig.ReadOnly=$true;$rtbMig.BorderStyle=[System.Windows.Forms.BorderStyle]::FixedSingle
$rtbMig.ScrollBars=[System.Windows.Forms.RichTextBoxScrollBars]::Vertical
$t3.Controls.Add($rtbMig)

#endregion

# ─────────────────────────────────────────────────────────────────────────────────
#region EVENT HANDLERS
# ─────────────────────────────────────────────────────────────────────────────────

# ── Tab 1  -  Setup ────────────────────────────────────────────────────────────────
$btnInstall.Add_Click({
    $btnInstall.Enabled=$false
    Initialize-PSFalcon -Log $rtbSetup
    $btnInstall.Enabled=$true
})

$btnConnect.Add_Click({
    $btnConnect.Enabled=$false
    $lblConnStatus.Text='Connecting...';$lblConnStatus.ForeColor=$clrMuted
    if (-not (Get-Command 'Request-FalconToken' -ErrorAction SilentlyContinue)) {
        Write-UILog $rtbSetup 'PSFalcon not loaded  -  installing first...' Warning
        Initialize-PSFalcon -Log $rtbSetup
    }
    $ok = Connect-FalconApi -ClientId $tbClientId.Text -ClientSecret $tbSecret.Text `
                             -Cloud $cboCloud.SelectedItem -Log $rtbSetup
    if ($ok) {$lblConnStatus.Text='* Connected';$lblConnStatus.ForeColor=$clrOk}
    else     {$lblConnStatus.Text='* Failed';$lblConnStatus.ForeColor=$clrErr}
    $btnConnect.Enabled=$true
})

$btnBrowseJson.Add_Click({
    $d=New-Object System.Windows.Forms.OpenFileDialog
    $d.Title='Select SEP Firewall Policy JSON';$d.Filter='JSON files (*.json)|*.json|All files|*.*'
    if($d.ShowDialog() -eq 'OK'){$tbJson.Text=$d.FileName}
})
$btnBrowseCsv.Add_Click({
    $d=New-Object System.Windows.Forms.OpenFileDialog
    $d.Title='Select Host Groups CSV (optional)';$d.Filter='CSV files (*.csv)|*.csv|All files|*.*'
    if($d.ShowDialog() -eq 'OK'){$tbCsv.Text=$d.FileName}
})

$btnExportConfig.Add_Click({
    $d = New-Object System.Windows.Forms.SaveFileDialog
    $d.Title    = 'Export Configuration'
    $d.Filter   = 'JSON (*.json)|*.json|XML (*.xml)|*.xml'
    $d.FileName = 'SEP-CS-FW-Config'
    if ($d.ShowDialog() -eq 'OK') {
        try {
            Export-AppConfig -Path $d.FileName
            $lblConfigFile.Text = "Saved: $($d.FileName)"
            Write-UILog $rtbSetup "Config exported -> $($d.FileName)" Success
            Write-UILog $rtbSetup '  Client secret encrypted with Windows DPAPI (current user/machine only).' Info
        } catch {
            Write-UILog $rtbSetup "Export failed: $_" Error
        }
    }
})

$btnImportConfig.Add_Click({
    $d = New-Object System.Windows.Forms.OpenFileDialog
    $d.Title  = 'Import Configuration'
    $d.Filter = 'Config files (*.json;*.xml)|*.json;*.xml|JSON (*.json)|*.json|XML (*.xml)|*.xml'
    if ($d.ShowDialog() -eq 'OK') {
        try {
            Import-AppConfig -Path $d.FileName
            $lblConfigFile.Text = "Loaded: $($d.FileName)"
            Write-UILog $rtbSetup "Config imported <- $($d.FileName)" Success
        } catch {
            Write-UILog $rtbSetup "Import failed: $_" Error
        }
    }
})

# ── Tab 2  -  Analyze ──────────────────────────────────────────────────────────────
$btnAnalyze.Add_Click({
    $jsonPath = $tbJson.Text
    if (-not $jsonPath -or -not (Test-Path $jsonPath)) {
        [System.Windows.Forms.MessageBox]::Show("SEP JSON file not found.`nPlease select a file on the Setup tab.", 'Error', 0, 16) | Out-Null
        return
    }

    $dgv.Rows.Clear()
    $script:AnalysisResults.Clear()

    Write-UILog $rtbSetup "Analyzing: $jsonPath" Info

    $sepRules = $null
    try {
        $sepRules = Import-SepJson -Path $jsonPath
        Write-UILog $rtbSetup "Loaded $($sepRules.Count) rules." Success
    } catch {
        Write-UILog $rtbSetup "JSON parse error: $_" Error
        return
    }

    $vpnName     = if ($tbVpnName.Text) { $tbVpnName.Text } else { 'VPN Connected' }
    $vpnId       = if ($tbVpnId.Text)   { $tbVpnId.Text   } else { '' }
    $nDirect=0; $nAdapt=0; $nBlock=0; $rowIdx=0

    foreach ($rule in $sepRules) {
        $rowIdx++
        $classification = Get-RuleClassification -Rule $rule -VpnLocName $vpnName

        $csRules = @()
        if ($classification.status -ne 'Blocker') {
            $csRules = Convert-SepRuleToCs -SepRule $rule -Classification $classification `
                                           -VpnLocId $vpnId -VpnLocName $vpnName
        }

        $conns      = @($rule.connections | Where-Object { $_ })
        $direction  = Get-ConnectionDirection $conns
        $protos     = Get-ConnectionProtocols $conns
        $dirLabel   = $script:DirectionLabel[$direction]
        $protoStr   = if ($protos.Count -eq 0) { 'ANY' }
                      elseif ($protos.Count -gt 3) { "$($protos.Count) protocols" }
                      else { ($protos | ForEach-Object { if ($script:ProtocolMap.$_){$script:ProtocolMap.$_}else{$_} }) -join '+' }

        switch ($classification.status) {
            'Direct'     { $nDirect++ }
            'Adaptation' { $nAdapt++ }
            'Blocker'    { $nBlock++ }
        }

        $notes = switch ($classification.status) {
            'Blocker'    { $classification.blockers    -join '; ' }
            'Adaptation' { $classification.adaptations -join '; ' }
            default      { '' }
        }

        $entry = @{
            sepRule        = $rule
            classification = $classification
            csRules        = $csRules
            directionLabel = $dirLabel
            protocolStr    = $protoStr
        }
        $script:AnalysisResults.Add($entry)

        $rowNum = $dgv.Rows.Add($rowIdx, $rule.name, $rule.action, $dirLabel, $protoStr,
                                 $classification.status, $csRules.Count, $notes)

        $statusCell = $dgv.Rows[$rowNum].Cells[5]
        $statusCell.Style.Font = $fntBold
        $statusCell.Style.ForeColor = switch ($classification.status) {
            'Direct'     { $clrOk }
            'Adaptation' { $clrWarn }
            default      { $clrErr }
        }
    }

    $lblDirect.Text = "* $nDirect  Direct"
    $lblAdapt.Text  = "⚠ $nAdapt  Adaptation Required"
    $lblBlock.Text  = "✗ $nBlock  Non-migratable"
    $lblTotal.Text  = "= $($sepRules.Count)  Total"

    $script:AnalysisDone = $true
    Write-UILog $rtbSetup "Analysis complete  -  $nDirect direct, $nAdapt adapted, $nBlock not migrated." Success
    $tabs.SelectedIndex = 1
})

# Filter buttons
function Apply-DgvFilter {
    param([string]$F)
    foreach ($row in $dgv.Rows) {
        $s = $row.Cells[5].Value
        $row.Visible = ($F -eq 'All') -or ($row.Cells[5].Value -eq $F) -or
                       ($F -eq 'Adaptation' -and $s -eq 'Adaptation') -or
                       ($F -eq 'Non-migratable' -and $s -eq 'Blocker')
    }
}
$btnAll.Add_Click({   Apply-DgvFilter 'All' })
$btnFilt1.Add_Click({ Apply-DgvFilter 'Direct' })
$btnFilt2.Add_Click({ Apply-DgvFilter 'Adaptation' })
$btnFilt3.Add_Click({ Apply-DgvFilter 'Non-migratable' })

$dgv.Add_SelectionChanged({
    if ($dgv.SelectedRows.Count -eq 0) { return }
    $idx = $dgv.SelectedRows[0].Index
    if ($idx -lt 0 -or $idx -ge $script:AnalysisResults.Count) { return }
    $r = $script:AnalysisResults[$idx]
    $parts = @()
    if ($r.classification.blockers.Count -gt 0)    { $parts += "NOT MIGRATED: $($r.classification.blockers -join ' | ')" }
    if ($r.classification.adaptations.Count -gt 0) { $parts += "ADAPTED: $($r.classification.adaptations -join ' | ')" }
    $lblDetail.Text = if ($parts) { $parts -join '  ▸  ' } else { 'Direct migration  -  no changes required.' }
    $lblDetail.ForeColor = switch ($r.classification.status) {
        'Blocker'    { $clrErr }
        'Adaptation' { $clrWarn }
        default      { $clrMuted }
    }
})

$btnReport.Add_Click({
    if ($script:AnalysisResults.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('Run analysis first.','No data',0,48)|Out-Null
        return
    }
    $d=New-Object System.Windows.Forms.SaveFileDialog
    $d.Title='Export Migration Report'
    $d.Filter='CSV files (*.csv)|*.csv'
    $d.FileName="SEP-CS-FW-Migration-$(Get-Date -Format 'yyyyMMdd').csv"
    if ($d.ShowDialog() -eq 'OK') {
        Export-MigrationReport -Path $d.FileName
        [System.Windows.Forms.MessageBox]::Show("Report saved:`n$($d.FileName)",'Exported',0,64)|Out-Null
    }
})

# ── Tab 3  -  Migrate ──────────────────────────────────────────────────────────────
$btnMigrate.Add_Click({
    if (-not $script:Connected) {
        $lblPrereq.Text='⚠ Not connected to CrowdStrike  -  go to Setup tab.'
        return
    }
    if (-not $script:AnalysisDone) {
        $lblPrereq.Text='⚠ Run Analysis first (tab 2).'
        return
    }
    $lblPrereq.Text=''

    $allCsRules = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($r in $script:AnalysisResults) {
        if ($r.classification.status -ne 'Blocker') {
            foreach ($cr in $r.csRules) { $allCsRules.Add($cr) }
        }
    }

    if ($allCsRules.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('No migratable rules found.','Warning',0,48)|Out-Null
        return
    }

    $blockerCount = ($script:AnalysisResults | Where-Object {$_.classification.status -eq 'Blocker'}).Count
    $confirm = [System.Windows.Forms.MessageBox]::Show(
        "About to create in CrowdStrike Falcon:`n`n" +
        "  Rule Group : '$($tbGroupName.Text)'`n" +
        "  Policy     : '$($tbPolicyName.Text)'`n" +
        "  Platform   : $($cboPlatform.SelectedItem)`n" +
        "  CS rules   : $($allCsRules.Count)`n" +
        "  Skipped    : $blockerCount non-migratable rules`n" +
        "  Monitor Mode: $($chkMonitor.Checked)`n`n" +
        "Proceed?",
        'Confirm Migration', 4, 32)

    if ($confirm -ne 6) { return }

    $btnMigrate.Enabled=$false
    $rtbMig.Clear();$progBar.Value=0

    Start-Migration `
        -CsRules         $allCsRules.ToArray() `
        -GroupName       $tbGroupName.Text `
        -PolicyName      $tbPolicyName.Text `
        -Platform        $cboPlatform.SelectedItem `
        -DefaultInbound  $cboInbound.SelectedItem `
        -DefaultOutbound $cboOutbound.SelectedItem `
        -MonitorMode     $chkMonitor.Checked `
        -AnalysisResults $script:AnalysisResults.ToArray() `
        -Log             $rtbMig `
        -ProgressBar     $progBar

    $btnMigrate.Enabled=$true
})

#endregion

# ─────────────────────────────────────────────────────────────────────────────────
#region STARTUP
# ─────────────────────────────────────────────────────────────────────────────────

Write-FileLog "=== SEP-CS-FW-Migrator started ===" INFO
Write-FileLog "Log path: $($script:LogFile)" INFO

Write-UILog $rtbSetup 'SEP -> CrowdStrike FW Migrator ready.' Success
Write-UILog $rtbSetup '' Info
Write-UILog $rtbSetup "Log file: $($script:LogFile)" Info
Write-UILog $rtbSetup '' Info
Write-UILog $rtbSetup 'WORKFLOW:' Info
Write-UILog $rtbSetup '  1. Click "Install / Update PSFalcon" (first run or after updates).' Info
Write-UILog $rtbSetup '  2. Enter CrowdStrike API credentials and click "Test Connection".' Info
Write-UILog $rtbSetup '  3. Select your SEP JSON policy export (FW_*.json).' Info
Write-UILog $rtbSetup '  4. Go to tab 2 -> click "Analyze File" to preview the migration.' Info
Write-UILog $rtbSetup '  5. Go to tab 3 -> configure settings and click "Start Migration".' Info
Write-UILog $rtbSetup '' Info
Write-UILog $rtbSetup 'MIGRATION RULES:' Info
Write-UILog $rtbSetup '  Direct       -  rule translates 1:1, no changes needed.' Info
Write-UILog $rtbSetup '  Adaptation   -  automatic adjustment applied (FQDN->Outbound, group expansion, path fix...).' Warning
Write-UILog $rtbSetup '  Blocker      -  EtherType / MAC filter / IP fragment rules cannot be migrated.' Error
Write-UILog $rtbSetup '' Info
Write-UILog $rtbSetup 'NOTE: PSFalcon requires PowerShell Gallery access (Set-ExecutionPolicy RemoteSigned).' Warning

#endregion

[System.Windows.Forms.Application]::Run($form)
