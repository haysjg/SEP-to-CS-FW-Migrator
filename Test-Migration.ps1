#Requires -Version 5.1
<#
.SYNOPSIS
    Headless test for SEP-CS-FW-Migrator: validates rule conversion without the GUI.
.DESCRIPTION
    Loads all conversion functions from the main script, runs the full pipeline, and
    validates the output locally. Optionally validates the payload against the CS API
    schema using New-FalconFirewallGroup -Validate (no rule group is created).

    Usage examples:
        # Local validation only:
        .\Test-Migration.ps1 -SepJson "path\to\policy.json"

        # Load credentials from saved config + API schema validation:
        .\Test-Migration.ps1 -Config .\SEP-CS-FW-Config.json -ApiValidate

        # Show full JSON of the first 3 rules matching a name filter:
        .\Test-Migration.ps1 -SepJson "path\to\policy.json" -DumpRules 3 -Filter "CISCO"
#>
param(
    # Path to the SEP policy JSON file (overrides config file)
    [string]$SepJson,

    # Path to the saved app config JSON (reads jsonPath + credentials)
    [string]$Config = '.\SEP-CS-FW-Config.json',

    # Call New-FalconFirewallGroup -Validate (requires API credentials)
    [switch]$ApiValidate,

    # Explicit API credentials (override config)
    [string]$ClientId,
    [string]$ClientSecret,  # plain text
    [string]$CloudRegion,

    # Print JSON of the first N converted rules (0 = none)
    [int]$DumpRules = 3,

    # Only process rules whose name matches this regex
    [string]$Filter = ''
)

Set-StrictMode -Off
$ErrorActionPreference = 'Continue'
$host.UI.RawUI.WindowTitle = 'SEP-CS-FW-Migrator Test'

# ── 0. Load config file ───────────────────────────────────────────────────────
$cfg = $null
if (Test-Path $Config) {
    $cfg = Get-Content $Config -Raw | ConvertFrom-Json
    Write-Host "Config loaded: $Config" -ForegroundColor DarkGray
}

if (-not $SepJson -and $cfg.jsonPath) { $SepJson = $cfg.jsonPath }
if (-not $SepJson) { Write-Error "-SepJson is required (or set jsonPath in config)"; exit 1 }

# Credentials: explicit params > config file
if (-not $CloudRegion -and $cfg.cloud) { $CloudRegion = $cfg.cloud }
if (-not $ClientId    -and $cfg.clientId) { $ClientId = $cfg.clientId }
if (-not $ClientSecret -and $cfg.clientSecret -and $cfg.clientSecret -ne '') {
    # Decrypt DPAPI-encrypted secret from config
    try {
        $ss  = ConvertTo-SecureString $cfg.clientSecret
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
        $ClientSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        Write-Host "  Client secret decrypted OK." -ForegroundColor DarkGray
    } catch {
        Write-Warning "Could not decrypt client secret (different user/machine?): $_"
    }
}

# ── 1. Load functions from main script ───────────────────────────────────────
Write-Host "`n=== Loading functions from main script ===" -ForegroundColor Cyan

$mainScript = Join-Path $PSScriptRoot 'SEP-CS-FW-Migrator.ps1'
if (-not (Test-Path $mainScript)) { Write-Error "Main script not found: $mainScript"; exit 1 }

$src = Get-Content $mainScript -Raw -Encoding UTF8

# Stop before GUI code (keeps only data/logic functions)
$guiStart = $src.IndexOf('#region GUI HELPERS')
if ($guiStart -gt 0) { $src = $src.Substring(0, $guiStart) }

# Replace WinForms type annotations with [object] so param blocks stay valid
$src = $src -replace '\[System\.Windows\.Forms\.[A-Za-z]+\]', '[object]'
$src = $src -replace 'Add-Type\s+-AssemblyName[^\n]+', ''
# Remove top-level WinForms static method calls (e.g. [object]::EnableVisualStyles())
$src = $src -replace '\[object\]::\w+\(\)', ''

# Prepend PSScriptRoot and stubs so:
#  - Join-Path $PSScriptRoot "..." on line 24 of main script gets a valid path
#  - Write-UILog/Write-FileLog/Step are no-ops before the main script redefines Write-FileLog
# The stubs are also appended AFTER to override the real Write-FileLog defined in the main script
$scriptRoot = $PSScriptRoot
$stubs = @"
`$PSScriptRoot = '$scriptRoot'
`$script:LogFile = [System.IO.Path]::GetTempFileName()
function Write-UILog  { param(`$Log, `$Msg, `$Level) }
function Write-FileLog { param(`$Msg, `$Level) Write-Verbose "[LOG] `$Msg" }
function Step { param(`$Msg, `$Color) Write-Host "  `$Msg" -ForegroundColor DarkGray }
"@

# Redefine stubs after main script to override real Write-FileLog
$trailStubs = @'

function Write-UILog  { param($Log, $Msg, $Level) }
function Write-FileLog { param($Msg, $Level) Write-Verbose "[LOG] $Msg" }
function Step { param($Msg, $Color) Write-Host "  $Msg" -ForegroundColor DarkGray }

'@

try {
    Invoke-Expression ($stubs + "`n" + $src + "`n" + $trailStubs)
    Write-Host "  Functions loaded." -ForegroundColor Green
} catch {
    Write-Warning "Load warning: $_"
}

# Verify key functions are available
$needed = @('Import-SepJson','Get-RuleClassification','Convert-SepRuleToCs',
            'Test-RulePortsValid','Merge-PortRanges','Build-CsRule')
$missing = $needed | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) }
if ($missing) {
    Write-Error "Missing functions after load: $($missing -join ', ')"
    exit 1
}

# ── 2. Parse SEP JSON ─────────────────────────────────────────────────────────
Write-Host "`n=== Parsing SEP policy ===" -ForegroundColor Cyan
Write-Host "  $SepJson"

try {
    $rules = Import-SepJson -Path $SepJson
} catch {
    Write-Error "Failed to parse SEP JSON: $_"; exit 1
}

if ($Filter) {
    $rules = @($rules | Where-Object { $_.name -match $Filter })
    Write-Host "  Filter '$Filter' -> $($rules.Count) rules" -ForegroundColor Yellow
} else {
    Write-Host "  Found $($rules.Count) SEP rules." -ForegroundColor Green
}

# VPN location ID from config (optional)
$vpnLocId = if ($cfg.vpnLocId) { $cfg.vpnLocId } else { '' }

# ── 3. Classify and convert ──────────────────────────────────────────────────
Write-Host "`n=== Converting rules ===" -ForegroundColor Cyan

$csRules  = [System.Collections.Generic.List[hashtable]]::new()
$nBlocker = 0; $nAdapted = 0; $nErrors = 0

foreach ($r in $rules) {
    try {
        $cls = Get-RuleClassification $r
        if ($cls.status -eq 'Blocker') { $nBlocker++; continue }
        if ($cls.status -eq 'Adaptation') { $nAdapted++ }
        $converted = Convert-SepRuleToCs -SepRule $r -Classification $cls `
                         -VpnLocId $vpnLocId -VpnLocName ''
        foreach ($cr in $converted) { $csRules.Add($cr) }
    } catch {
        $nErrors++
        Write-Host "  ERROR '$($r.name)': $_" -ForegroundColor Red
    }
}

Write-Host "  CS rules built   : $($csRules.Count)" -ForegroundColor Green
Write-Host "  Blockers skipped : $nBlocker" -ForegroundColor $(if ($nBlocker) { 'Yellow' } else { 'DarkGray' })
Write-Host "  Adapted          : $nAdapted"
if ($nErrors) { Write-Host "  Conversion errors: $nErrors" -ForegroundColor Red }

# ── 4. Pre-flight port validation ─────────────────────────────────────────────
Write-Host "`n=== Pre-flight port validation ===" -ForegroundColor Cyan
$portErrors = 0
foreach ($r in $csRules) {
    $chk = Test-RulePortsValid $r
    if (-not $chk.valid) {
        $portErrors++
        Write-Host "  PORT CONFLICT '$($r.name)' [$($chk.field)]: $($chk.issue)" -ForegroundColor Red
    }
}
Write-Host "  $(if ($portErrors) { "$portErrors error(s)" } else { 'All OK' })" `
    -ForegroundColor $(if ($portErrors) { 'Red' } else { 'Green' })

# ── 5. Convert ports to API format (end=0 for single ports) ──────────────────
foreach ($r in $csRules) {
    foreach ($field in @('local_port', 'remote_port')) {
        if ($r[$field] -and @($r[$field]).Count -gt 0) {
            $r[$field] = @(@($r[$field]) | ForEach-Object {
                $s = [int]$_.start; $e = [int]$_.end
                if ($s -eq $e) { @{ start = $s; end = 0 } } else { @{ start = $s; end = $e } }
            })
        }
    }
}

# ── 6. Local format checks ────────────────────────────────────────────────────
Write-Host "`n=== Local format checks ===" -ForegroundColor Cyan
$fmtErrors = 0

foreach ($r in $csRules) {
    $issues = @()

    # Required fields
    foreach ($f in @('name','action','direction','address_family','protocol','enabled',
                     'fqdn','fqdn_enabled','local_address','remote_address','fields')) {
        if ($null -eq $r[$f]) { $issues += "missing '$f'" }
    }

    # Protocol must be '*' or numeric string '0'-'255'
    $proto = $r['protocol']
    if ($proto -and $proto -ne '*') {
        $protoInt = 0
        if (-not [int]::TryParse($proto, [ref]$protoInt) -or $protoInt -lt 0 -or $protoInt -gt 255) {
            $issues += "protocol '$proto' is not '*' or integer 0-255"
        }
    }

    # Address must be '*' or valid IP/CIDR, not 0.0.0.0/0 or range notation
    foreach ($addrField in @('local_address', 'remote_address')) {
        foreach ($a in @($r[$addrField])) {
            if ($a -and $a.address -eq '0.0.0.0' -and [int]$a.netmask -eq 0) {
                $issues += "${addrField}: 0.0.0.0/0 should be '*'"
            }
            if ($a -and $a.address -match '-') {
                $issues += "${addrField}: range notation '$($a.address)' not accepted by API"
            }
        }
    }

    # fields must have network_location with array values
    # Force @() so result is always an array (Where-Object returns scalar for single matches)
    # Use ['key'] not .key on hashtables to avoid IDictionary property collisions (e.g. .Values)
    $nlList = @($r['fields'] | Where-Object { $_ -and $_['name'] -eq 'network_location' })
    if ($nlList.Count -eq 0) {
        $issues += "fields missing network_location"
    } else {
        $vals = $nlList[0]['values']
        if ($null -eq $vals) {
            $issues += "network_location.values is null"
        } elseif ($vals -isnot [array] -and $vals -isnot [string[]] -and $vals -isnot [System.Collections.ICollection]) {
            $issues += "network_location.values is '$($vals.GetType().Name)' not array"
        }
    }

    # No end=start for ports after conversion (should be end=0)
    foreach ($portField in @('local_port', 'remote_port')) {
        foreach ($p in @($r[$portField])) {
            if ($p -and [int]$p.start -ne 0 -and [int]$p.start -eq [int]$p.end) {
                $issues += "$portField {start=$($p.start),end=$($p.end)} should have end=0"
            }
        }
    }

    if ($issues.Count -gt 0) {
        $fmtErrors++
        Write-Host "  '$($r.name)': $($issues -join ' | ')" -ForegroundColor Red
    }
}
Write-Host "  $(if ($fmtErrors) { "$fmtErrors error(s)" } else { "All $($csRules.Count) rules OK" })" `
    -ForegroundColor $(if ($fmtErrors) { 'Red' } else { 'Green' })

# ── 7. Dump first N rules as JSON ─────────────────────────────────────────────
if ($DumpRules -gt 0 -and $csRules.Count -gt 0) {
    Write-Host "`n=== First $([Math]::Min($DumpRules,$csRules.Count)) rule(s) JSON ===" -ForegroundColor Cyan
    for ($i = 0; $i -lt [Math]::Min($DumpRules, $csRules.Count); $i++) {
        Write-Host "`n--- Rule $($i+1): '$($csRules[$i].name)' ---" -ForegroundColor White
        $csRules[$i] | ConvertTo-Json -Depth 8 | Write-Host
    }
}

# ── 8. API schema validation ──────────────────────────────────────────────────
if ($ApiValidate) {
    Write-Host "`n=== API schema validation ===" -ForegroundColor Cyan

    if (-not $ClientId -or -not $ClientSecret) {
        Write-Warning "ApiValidate requires ClientId and ClientSecret."
    } elseif ($fmtErrors -gt 0 -or $portErrors -gt 0) {
        Write-Warning "Skipping API validation: fix local errors first."
    } else {
        if (-not (Get-Command 'Request-FalconToken' -ErrorAction SilentlyContinue)) {
            Import-Module PSFalcon -Force -ErrorAction Stop
        }

        # Pre-validation: replicate PSFalcon's Select-Object step and check for invalid addresses
        Write-Host "  Pre-check: simulating PSFalcon Select-Object + JSON serialization..." -ForegroundColor Yellow
        $fmtFile = [System.IO.Path]::Combine(
            (Get-Module PSFalcon -ListAvailable | Sort-Object Version -Desc | Select-Object -First 1).ModuleBase,
            'format', 'format.json')
        $fmtJson = Get-Content $fmtFile -Raw | ConvertFrom-Json
        $rulesProps = $fmtJson.'/fwmgr/entities/rule-groups/v1:post'.Body.rules
        $psRules = @($csRules | ForEach-Object { [PSCustomObject]$_ | Select-Object $rulesProps })
        $validIp = '^(\d{1,3}\.){3}\d{1,3}(/\d+)?$'
        $preCheckErrors = 0
        foreach ($pr in $psRules) {
            foreach ($addrField in @('local_address', 'remote_address')) {
                foreach ($a in @($pr.$addrField)) {
                    if ($a -and $a.address -ne $null -and $a.address -notmatch '^\*$' -and $a.address -notmatch $validIp) {
                        Write-Host "  BAD ADDRESS in '$($pr.name)' [$addrField]: '$($a.address)'" -ForegroundColor Red
                        $preCheckErrors++
                    }
                }
            }
        }
        if ($preCheckErrors -eq 0) {
            Write-Host "  Pre-check OK - all addresses valid." -ForegroundColor Green
        }

        try {
            Request-FalconToken -ClientId $ClientId -ClientSecret $ClientSecret `
                -Cloud $CloudRegion -ErrorAction Stop
            Write-Host "  Token OK." -ForegroundColor Green
        } catch { Write-Error "Auth failed: $_"; exit 1 }

        Write-Host "  Validating $($csRules.Count) rules against API schema..." -ForegroundColor Yellow
        try {
            $result = New-FalconFirewallGroup -Name 'TEST-VALIDATE' `
                -Enabled $true -Platform windows -Rule $csRules -Validate -ErrorAction Stop
            Write-Host "  VALIDATION PASSED" -ForegroundColor Green
        } catch {
            Write-Host "  VALIDATION FAILED: $_" -ForegroundColor Red
        }
    }
}

# ── Summary ───────────────────────────────────────────────────────────────────
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SEP rules: $($rules.Count)  |  CS rules: $($csRules.Count)  |  Port errors: $portErrors  |  Format errors: $fmtErrors"
if ($portErrors -eq 0 -and $fmtErrors -eq 0 -and $nErrors -eq 0) {
    Write-Host "READY TO MIGRATE" -ForegroundColor Green
} else {
    Write-Host "FIX ERRORS BEFORE MIGRATING" -ForegroundColor Red
    exit 1
}
