[CmdletBinding()]
param(
    [string[]]$RootPaths = @($env:USERPROFILE),

    [string]$PackageListFile = "",

    # Max size (in MB) of individual text/code files to content-scan.
    [int]$MaxFileSizeMB = 20
)

$ErrorActionPreference = "SilentlyContinue"

Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Sha1-Hulud Deep Scanner (System + Node Projects)" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host "Start time: $(Get-Date)"
Write-Host ""

# ------------------------------
# Helper: Collect findings
# ------------------------------
$global:Findings = @()

function Add-Finding {
    param(
        [string]$Severity,
        [string]$Category,
        [string]$Indicator,
        [string]$Path,
        [string]$Details
    )
    $global:Findings += [PSCustomObject]@{
        Severity  = $Severity
        Category  = $Category
        Indicator = $Indicator
        Path      = $Path
        Details   = $Details
    }
}

# ------------------------------
# Normalize root paths
# ------------------------------
Write-Host "[*] Normalizing scan roots..." -ForegroundColor Cyan
$existingRoots = @()
foreach ($p in $RootPaths) {
    if ([string]::IsNullOrWhiteSpace($p)) { continue }
    if (Test-Path $p) {
        try {
            $resolved = (Resolve-Path $p).Path
            if (-not ($existingRoots -contains $resolved)) {
                $existingRoots += $resolved
            }
        } catch {}
    } else {
        Write-Host "  WARNING: Path not found: $p" -ForegroundColor Yellow
    }
}

if (-not $existingRoots) {
    Write-Host "No valid root paths to scan. Exiting." -ForegroundColor Red
    exit 1
}

$existingRoots | ForEach-Object { Write-Host "  Root: $_" }

Write-Host ""

# ------------------------------
# Load compromised package list
# ------------------------------
$CompromisedPackages = @()

if ($PackageListFile -and (Test-Path $PackageListFile)) {
    Write-Host "[*] Loading compromised package list from: $PackageListFile" -ForegroundColor Cyan
    try {
        $lines = Get-Content $PackageListFile
        foreach ($line in $lines) {
            $trim = $line.Trim()
            if (-not $trim) { continue }
            if ($trim.StartsWith("#")) { continue }
            $CompromisedPackages += $trim
        }
        Write-Host "  Loaded $($CompromisedPackages.Count) package names." -ForegroundColor Green
    } catch {
        Write-Host "  ERROR: Failed to read package list: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "[*] No package list file supplied or file not found. Node project scans will skip known-package checks." -ForegroundColor Yellow
}

Write-Host ""

# ------------------------------
# Quick environment info (Node / npm / bun)
# ------------------------------
Write-Host "[*] Checking Node/npm/bun availability..." -ForegroundColor Cyan
$tools = @("node","npm","yarn","pnpm","bun")

foreach ($t in $tools) {
    try {
        $cmd = Get-Command $t -ErrorAction SilentlyContinue
        if ($cmd) {
            $version = & $t --version 2>$null
            Write-Host "  $t found: $($cmd.Source) (version: $version)"
        } else {
            Write-Host "  $t not found on PATH."
        }
    } catch {
        Write-Host "  $t check failed: $($_.Exception.Message)"
    }
}
Write-Host ""

# ------------------------------
# 1) Process + runner checks
# ------------------------------
Write-Host "[*] Step 1: Process and runner checks..." -ForegroundColor Cyan
try {
    $suspiciousProcs = Get-Process | Where-Object {
        $_.ProcessName -like "*actions-runner*" -or
        $_.ProcessName -like "*sha1hulud*" -or
        $_.ProcessName -like "*shaihulud*"
    }

    foreach ($p in $suspiciousProcs) {
        Add-Finding -Severity "High" -Category "Process" -Indicator "SuspiciousProcess" `
            -Path $p.ProcessName `
            -Details "Suspicious process name (possible malicious GitHub Actions runner or Sha1-Hulud variant)."
    }
} catch {}

try {
    $runnerDir = Join-Path $env:USERPROFILE ".dev-env"
    if (Test-Path $runnerDir) {
        Add-Finding -Severity "High" -Category "Persistence" -Indicator "RunnerDirectory" `
            -Path $runnerDir `
            -Details "Directory name matches pattern used by malicious GitHub Actions runner (Sha1-Hulud variants)."
    }
} catch {}

Write-Host ""

# ------------------------------
# 2) System-level IoC scanning
# ------------------------------
Write-Host "[*] Step 2: System-level IoC scanning..." -ForegroundColor Cyan

# File name indicators
$HighRiskFileNames = @(
    "setup_bun.js",
    "bun_environment.js"
)

$RelatedFileNames = @(
    "actionsSecrets.json",
    "cloud.json",
    "contents.json",
    "environment.json",
    "truffleSecrets.json"
)

# Content indicators (strings)
$IndicatorStrings = @(
    "SHA1HULUD",
    "Sha1-Hulud",
    "Shai-Hulud",
    '"preinstall": "node setup_bun.js"',
    "setup_bun.js",
    "bun_environment.js",
    "Sha1-Hulud: The Second Coming",
    "webhook.site",
    "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7"
)

# Text/code file extensions to content-scan
$TextExtensions = @(
    "*.js","*.ts","*.mjs","*.cjs",
    "*.json","*.yml","*.yaml",
    "package.json","package-lock.json","yarn.lock","pnpm-lock.yaml","bun.lock",
    "*.txt","*.md"
)

$MaxBytes = $MaxFileSizeMB * 1MB

# 2a) Suspicious filenames + workflow files
Write-Host "  [2a] Searching for suspicious file names and workflows..." -ForegroundColor DarkCyan

foreach ($root in $existingRoots) {
    try {
        $files = Get-ChildItem -Path $root -Recurse -Force -ErrorAction SilentlyContinue

        foreach ($f in $files) {
            if (-not $f.PSIsContainer) {
                # High-risk exact names
                if ($HighRiskFileNames -contains $f.Name) {
                    Add-Finding -Severity "High" -Category "FileName" -Indicator "HighRiskFileName" `
                        -Path $f.FullName `
                        -Details "File name is a HIGH confidence Sha1-Hulud indicator: $($f.Name)"
                }
                elseif ($RelatedFileNames -contains $f.Name) {
                    Add-Finding -Severity "Medium" -Category "FileName" -Indicator "RelatedFileName" `
                        -Path $f.FullName `
                        -Details "File name matches a known Sha1-Hulud-related artifact: $($f.Name). Inspect contents."
                }

                # Workflow pattern: .github/workflows/formatter_*.yml
                if ($f.FullName -match "\\\.github\\workflows\\formatter_.*\.yml$") {
                    Add-Finding -Severity "Medium" -Category "Workflow" -Indicator "SuspiciousWorkflow" `
                        -Path $f.FullName `
                        -Details "Workflow path matches known Sha1-Hulud pattern: .github/workflows/formatter_*.yml"
                }
            }
        }
    } catch {}
}

Write-Host "  [2b] Content scanning for indicator strings (this can take a while)..." -ForegroundColor DarkCyan

foreach ($root in $existingRoots) {
    try {
        $textFiles = Get-ChildItem -Path $root -Recurse -Force -ErrorAction SilentlyContinue -File -Include $TextExtensions |
            Where-Object { $_.Length -le $MaxBytes }

        if (-not $textFiles) { continue }

        $paths = $textFiles.FullName
        $matches = Select-String -Path $paths -Pattern $IndicatorStrings -SimpleMatch -ErrorAction SilentlyContinue

        foreach ($m in $matches) {
            $pattern = $m.Pattern
            $severity = "Medium"
            if ($pattern -in @("SHA1HULUD","Sha1-Hulud","Shai-Hulud","setup_bun.js","bun_environment.js",'"preinstall": "node setup_bun.js"')) {
                $severity = "High"
            }

            Add-Finding -Severity $severity -Category "Content" -Indicator ("ContentMatch:" + $pattern) `
                -Path $m.Path `
                -Details ("Indicator '{0}' found at line {1}. Line (trimmed): {2}" -f $pattern, $m.LineNumber, $m.Line.Trim())
        }
    } catch {}
}

Write-Host ""

# ------------------------------
# 3) Node project scanning
# ------------------------------
Write-Host "[*] Step 3: Node.js project scanning..." -ForegroundColor Cyan

function Scan-NodeProject {
    param(
        [string]$ProjectDir,
        [string[]]$CompromisedPackages
    )

    $pkgJsonPath = Join-Path $ProjectDir "package.json"
    if (-not (Test-Path $pkgJsonPath)) { return }

    Write-Host "  - Scanning project: $ProjectDir"

    $pkgJsonContent = ""
    try {
        $pkgJsonContent = Get-Content $pkgJsonPath -Raw -ErrorAction SilentlyContinue
    } catch {}

    # 3a) Direct dependencies in package.json
    if ($CompromisedPackages.Count -gt 0 -and $pkgJsonContent) {
        foreach ($pkg in $CompromisedPackages) {
            if ($pkgJsonContent -like "*""$pkg""*") {
                Add-Finding -Severity "High" -Category "NodeProject" -Indicator "CompromisedPackage:Direct" `
                    -Path $pkgJsonPath `
                    -Details "Direct dependency on compromised package: $pkg"
            }
        }
    }

    # 3b) Lockfiles
    $lockfiles = @(
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock"
    )

    foreach ($lfName in $lockfiles) {
        $lfPath = Join-Path $ProjectDir $lfName
        if (-not (Test-Path $lfPath)) { continue }

        $lfContent = ""
        try {
            if ($lfName -eq "bun.lock") {
                # bun.lock may be binary; use strings-like approach
                $lfContent = (Get-Content $lfPath -Raw -ErrorAction SilentlyContinue)
            } else {
                $lfContent = Get-Content $lfPath -Raw -ErrorAction SilentlyContinue
            }
        } catch {}

        if ($CompromisedPackages.Count -gt 0 -and $lfContent) {
            foreach ($pkg in $CompromisedPackages) {
                if ($lfContent -like "*$pkg*") {
                    Add-Finding -Severity "High" -Category "NodeProject" -Indicator "CompromisedPackage:Lockfile" `
                        -Path $lfPath `
                        -Details "Compromised package appears in lockfile: $pkg"
                }
            }
        }

        # Additional high-signal indicators in lockfiles (no need to scan generic 'sha1*')
        if ($lfContent -like "*SHA1HULUD*" -or $lfContent -like "*Sha1-Hulud*" -or $lfContent -like "*Shai-Hulud*") {
            Add-Finding -Severity "High" -Category "NodeProject" -Indicator "Sha1HuludMarker:Lockfile" `
                -Path $lfPath `
                -Details "Lockfile contains direct 'Sha1-Hulud' marker text."
        }
    }

    # 3c) node_modules presence of compromised packages
    $nodeModules = Join-Path $ProjectDir "node_modules"
    if ((Test-Path $nodeModules) -and $CompromisedPackages.Count -gt 0) {
        foreach ($pkg in $CompromisedPackages) {
            $pkgPath = $null

            if ($pkg.StartsWith("@")) {
                # Scoped package, e.g. @postman/cli
                $pkgPath = Join-Path $nodeModules ($pkg.Replace("/", [IO.Path]::DirectorySeparatorChar))
            } else {
                $pkgPath = Join-Path $nodeModules $pkg
            }

            if ($pkgPath -and (Test-Path $pkgPath)) {
                Add-Finding -Severity "High" -Category "NodeProject" -Indicator "CompromisedPackage:Installed" `
                    -Path $pkgPath `
                    -Details "Compromised package appears installed in node_modules: $pkg"
            }
        }
    }
}

# Find all package.json files under the roots and scan each project
foreach ($root in $existingRoots) {
    Write-Host "  Searching for Node projects under: $root"
    try {
        $pkgFiles = Get-ChildItem -Path $root -Recurse -Force -File -Filter "package.json" -ErrorAction SilentlyContinue
        foreach ($pkg in $pkgFiles) {
            $projDir = Split-Path $pkg.FullName -Parent
            Scan-NodeProject -ProjectDir $projDir -CompromisedPackages $CompromisedPackages
        }
    } catch {}
}

Write-Host ""

# ------------------------------
# 4) Summary & report
# ------------------------------
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host " Scan complete" -ForegroundColor Cyan
Write-Host "End time: $(Get-Date)" -ForegroundColor Cyan
Write-Host "=====================================================" -ForegroundColor Cyan
Write-Host ""

if (-not $Findings -or $Findings.Count -eq 0) {
    Write-Host "Result: No known Sha1-Hulud indicators were found in the scanned paths." -ForegroundColor Green
    Write-Host "Note: This is a strong signal, but not a mathematical guarantee of cleanliness."
} else {
    Write-Host "Result: One or more indicators were found." -ForegroundColor Yellow
    Write-Host ""
    $Findings | Sort-Object Severity, Category | Format-Table -AutoSize

    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $outFile = Join-Path $PWD ("Sha1Hulud-DeepScan-Results-{0}.json" -f $timestamp)

    try {
        $Findings | ConvertTo-Json -Depth 6 | Out-File -FilePath $outFile -Encoding UTF8
        Write-Host ""
        Write-Host "Detailed JSON report saved to: $outFile" -ForegroundColor Cyan
    } catch {
        Write-Host "Failed to save JSON report: $($_.Exception.Message)" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Done."
