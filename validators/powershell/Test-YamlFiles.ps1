<#
.SYNOPSIS
    Parses YAML files with "Get-Content -Raw | ConvertFrom-Yaml" and reports the
    outcome of each file as JSON for the Sentinel Detection Linter.

.DESCRIPTION
    ConvertFrom-Yaml is provided by the third-party "powershell-yaml" module
    (a YamlDotNet wrapper); it is NOT a built-in cmdlet:

        Install-Module powershell-yaml -Scope CurrentUser

    The linter (validators/powershell_yaml_validator.py) launches this script with
    an argument LIST (no shell), so file names are never interpolated into a
    command string. Paths are handed over in a JSON file (-ListFile) rather than on
    the command line so that batches of any size, and paths containing commas,
    spaces, quotes or non-ASCII characters, are handled safely.

    Output contract: a marker line, then ONE line of compact JSON on stdout.
    Anything printed before the marker (profile noise, module banners) is ignored by
    the caller. The script exits 0 whenever it was able to emit the JSON, including
    when individual files fail to parse - parse failures are DATA, not script errors.

.PARAMETER ListFile
    Path to a UTF-8 JSON file containing an array of YAML file paths.

.PARAMETER Probe
    Only report the PowerShell version and whether powershell-yaml is installed.
#>
[CmdletBinding()]
param(
    [string]$ListFile,
    [switch]$Probe
)

# Any error becomes a terminating error so that try/catch sees it. Deliberately set
# globally instead of passing -ErrorAction to ConvertFrom-Yaml, which is a
# third-party function that is not guaranteed to expose common parameters.
$ErrorActionPreference = 'Stop'

$Marker = '@@SENTINEL-LINTER-JSON@@'

function Write-Payload {
    param($Payload)
    try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false) } catch { }
    [Console]::Out.WriteLine($Marker)
    [Console]::Out.WriteLine(($Payload | ConvertTo-Json -Depth 8 -Compress))
}

function Get-YamlFileReport {
    param([string]$Path)

    $report = [ordered]@{
        path         = $Path
        ok           = $false
        category     = $null   # read-error | parse-error | $null
        isMapping    = $false
        rootType     = $null
        topLevelKeys = @()
        line         = $null
        column       = $null
        message      = $null
        errorChain   = @()
    }

    # Step 1: read. -Raw yields ONE string (one document) instead of an array of
    # lines; -LiteralPath stops [ ] * ? in file names being treated as wildcards;
    # -Encoding UTF8 matches the Python loader (Windows PowerShell 5.1 would
    # otherwise default to the ANSI code page).
    $raw = $null
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    }
    catch {
        $report.category = 'read-error'
        $report.message  = [string]$_.Exception.Message
        return $report
    }

    # Step 2: parse - the equivalent of: Get-Content -Raw <path> | ConvertFrom-Yaml
    try {
        $parsed = $null
        if (-not [string]::IsNullOrWhiteSpace($raw)) {
            $parsed = $raw | ConvertFrom-Yaml
        }

        $report.ok = $true
        if ($null -ne $parsed) {
            $report.rootType = $parsed.GetType().FullName
            if ($parsed -is [System.Collections.IDictionary]) {
                $report.isMapping    = $true
                $report.topLevelKeys = @($parsed.Keys | ForEach-Object { [string]$_ })
            }
        }
    }
    catch {
        $report.ok       = $false
        $report.category = 'parse-error'

        # powershell-yaml has no try/catch of its own: YamlDotNet exceptions
        # propagate, wrapped by PowerShell in a MethodInvocationException whose
        # outer message is generic. Walk the whole InnerException chain and keep
        # every level; the innermost message is the useful one.
        $chain = New-Object System.Collections.Generic.List[object]
        $ex = $_.Exception
        while ($null -ne $ex) {
            $chain.Add([ordered]@{
                type    = $ex.GetType().FullName
                message = [string]$ex.Message
            })

            # YamlDotNet.Core.YamlException exposes 1-based Start/End marks.
            if ($null -eq $report.line) {
                $startProp = $ex.PSObject.Properties['Start']
                if ($null -ne $startProp -and $null -ne $startProp.Value) {
                    $lineProp = $startProp.Value.PSObject.Properties['Line']
                    $colProp  = $startProp.Value.PSObject.Properties['Column']
                    if ($null -ne $lineProp -and $null -ne $colProp) {
                        $report.line   = [int]$lineProp.Value
                        $report.column = [int]$colProp.Value
                    }
                }
            }
            $ex = $ex.InnerException
        }

        $report.errorChain = $chain.ToArray()
        if ($chain.Count -gt 0) {
            $report.message = [string]$chain[$chain.Count - 1].message
        }
        else {
            $report.message = [string]$_
        }
    }

    return $report
}

# --- main -------------------------------------------------------------------

$moduleInfo = Get-Module -ListAvailable -Name 'powershell-yaml' |
    Sort-Object -Property Version -Descending |
    Select-Object -First 1

$payload = [ordered]@{
    psVersion     = $PSVersionTable.PSVersion.ToString()
    psEdition     = [string]$PSVersionTable.PSEdition
    moduleFound   = [bool]$moduleInfo
    moduleVersion = $(if ($moduleInfo) { $moduleInfo.Version.ToString() } else { $null })
    fatal         = $null
    results       = @()
}

if ($Probe -or -not $moduleInfo) {
    Write-Payload $payload
    exit 0
}

try {
    Import-Module -Name 'powershell-yaml' -ErrorAction Stop

    if ([string]::IsNullOrEmpty($ListFile)) {
        throw 'Either -ListFile or -Probe must be supplied.'
    }

    # @() keeps a one-element JSON array an array on Windows PowerShell 5.1.
    $paths = @(Get-Content -LiteralPath $ListFile -Raw -Encoding UTF8 | ConvertFrom-Json)

    $results = New-Object System.Collections.Generic.List[object]
    foreach ($p in $paths) {
        $results.Add((Get-YamlFileReport -Path ([string]$p)))
    }
    $payload.results = $results.ToArray()
}
catch {
    $payload.fatal = [string]$_.Exception.Message
}

Write-Payload $payload
exit 0
