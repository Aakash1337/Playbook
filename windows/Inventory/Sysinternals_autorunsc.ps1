<#  Get-Autoruns.ps1
    Purpose: Dump Windows autoruns using Sysinternals Autorunsc (if present).
    Output:  CSV + TXT in a timestamped folder.
#>

[CmdletBinding()]
param(
    [string]$OutDir = "$env:ProgramData\CCDC\Autoruns",
    [string]$AutorunscPath = ""   # Optional: full path to autorunsc64.exe/autorunsc.exe
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Find-Autorunsc {
    param([string]$ExplicitPath)

    if ($ExplicitPath) {
        if (Test-Path -LiteralPath $ExplicitPath) { return (Resolve-Path -LiteralPath $ExplicitPath).Path }
        throw "AutorunscPath was provided but not found: $ExplicitPath"
    }

    # 1) Prefer PATH
    $cmd = Get-Command autorunsc64.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Path }
    $cmd = Get-Command autorunsc.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Path }

    # 2) Common extraction locations (lightweight checks; no expensive full-disk recursion)
    $candidates = @(
        "C:\SysinternalsSuite\autorunsc64.exe",
        "C:\SysinternalsSuite\autorunsc.exe",
        "C:\Tools\SysinternalsSuite\autorunsc64.exe",
        "C:\Tools\SysinternalsSuite\autorunsc.exe",
        "$env:ProgramData\SysinternalsSuite\autorunsc64.exe",
        "$env:ProgramData\SysinternalsSuite\autorunsc.exe",
        "$env:USERPROFILE\Downloads\SysinternalsSuite\autorunsc64.exe",
        "$env:USERPROFILE\Downloads\SysinternalsSuite\autorunsc.exe",
        "$env:USERPROFILE\Desktop\SysinternalsSuite\autorunsc64.exe",
        "$env:USERPROFILE\Desktop\SysinternalsSuite\autorunsc.exe"
    )

    foreach ($p in $candidates) {
        if (Test-Path -LiteralPath $p) { return (Resolve-Path -LiteralPath $p).Path }
    }

    return $null
}

function Run-Autorunsc {
    param(
        [Parameter(Mandatory=$true)][string]$Exe,
        [Parameter(Mandatory=$true)][string[]]$Args,
        [Parameter(Mandatory=$true)][string]$StdoutPath,
        [Parameter(Mandatory=$true)][string]$StderrPath
    )

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = ($Args -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError  = $true
    $psi.CreateNoWindow = $true

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi

    [void]$p.Start()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()

    # Preserve raw text as-written
    Set-Content -LiteralPath $StdoutPath -Value $stdout -Encoding UTF8
    Set-Content -LiteralPath $StderrPath -Value $stderr -Encoding UTF8

    return $p.ExitCode
}

# --- Main ---
$exe = Find-Autorunsc -ExplicitPath $AutorunscPath
if (-not $exe) {
    throw "autorunsc.exe/autorunsc64.exe not found. Place SysinternalsSuite on disk or provide -AutorunscPath."
}

# Timestamped run directory
$ts = (Get-Date).ToString("yyyyMMdd-HHmmss")
$runDir = Join-Path $OutDir $ts
New-Item -ItemType Directory -Path $runDir -Force | Out-Null

# Documented switches (per Microsoft Learn): -a, -c, -h, -m, -s, -t; user '*' scans all profiles :contentReference[oaicite:1]{index=1}
# We do two passes:
#  (1) ALL entries
#  (2) Hide Microsoft entries (-m) to focus on third-party persistence :contentReference[oaicite:2]{index=2}

$argsAll   = @('-a','*','-c','-h','-s','-t','*')
$argsNonMs = @('-a','*','-c','-h','-s','-t','-m','*')

$allCsv   = Join-Path $runDir "autoruns_all.csv"
$allErr   = Join-Path $runDir "autoruns_all.stderr.txt"
$nonMsCsv = Join-Path $runDir "autoruns_nonms.csv"
$nonMsErr = Join-Path $runDir "autoruns_nonms.stderr.txt"

$exit1 = Run-Autorunsc -Exe $exe -Args $argsAll   -StdoutPath $allCsv   -StderrPath $allErr
$exit2 = Run-Autorunsc -Exe $exe -Args $argsNonMs -StdoutPath $nonMsCsv -StderrPath $nonMsErr

# Also emit a plain-text view for quick terminal review
$allTxt   = Join-Path $runDir "autoruns_all.txt"
$nonMsTxt = Join-Path $runDir "autoruns_nonms.txt"
Get-Content -LiteralPath $allCsv   | Out-File -FilePath $allTxt   -Encoding UTF8
Get-Content -LiteralPath $nonMsCsv | Out-File -FilePath $nonMsTxt -Encoding UTF8

# Minimal run summary
$summary = @()
$summary += "Autorunsc: $exe"
$summary += "RunDir:   $runDir"
$summary += "ExitCode(all):   $exit1"
$summary += "ExitCode(nonms): $exit2"
$summary += ""
$summary += "Outputs:"
$summary += "  autoruns_all.csv"
$summary += "  autoruns_nonms.csv"
$summary += "  autoruns_all.txt"
$summary += "  autoruns_nonms.txt"
$summaryPath = Join-Path $runDir "SUMMARY.txt"
Set-Content -LiteralPath $summaryPath -Value ($summary -join "`r`n") -Encoding UTF8

Write-Host ("[OK] Autoruns exported to: " + $runDir)
Write-Host ("     - All entries:        " + $allCsv)
Write-Host ("     - Non-Microsoft focus:" + $nonMsCsv)
