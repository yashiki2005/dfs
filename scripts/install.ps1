$ErrorActionPreference = "Stop"

# One-line installer for dfscli & dfssvc on Windows (PowerShell).
# Usage:
#   irm https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/install.ps1 | iex

$RepoUrl = if ($env:DFS_REPO_URL) { $env:DFS_REPO_URL } else { "https://github.com/yashiki2005/dfs.git" }
$ZipUrl = if ($env:DFS_ZIP_URL) { $env:DFS_ZIP_URL } else { "https://github.com/yashiki2005/dfs/archive/refs/heads/main.zip" }
$InstallDir = if ($env:DFS_INSTALL_DIR) { $env:DFS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "dfs" }
$BinDir = Join-Path $env:USERPROFILE ".local\bin"
$CargoBin = Join-Path $env:USERPROFILE ".cargo\bin"

if ($env:PATH -notlike "*$BinDir*") { $env:PATH = "$BinDir;$env:PATH" }
if ($env:PATH -notlike "*$CargoBin*") { $env:PATH = "$CargoBin;$env:PATH" }

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    irm https://astral.sh/uv/install.ps1 | iex
    if ($env:PATH -notlike "*$BinDir*") { $env:PATH = "$BinDir;$env:PATH" }
    if ($env:PATH -notlike "*$CargoBin*") { $env:PATH = "$CargoBin;$env:PATH" }
}

if (Get-Command git -ErrorAction SilentlyContinue) {
    if (Test-Path (Join-Path $InstallDir ".git")) {
        git -C $InstallDir pull --ff-only
    } else {
        if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
        $ParentDir = Split-Path -Parent $InstallDir
        if (-not (Test-Path $ParentDir)) { New-Item -ItemType Directory -Force -Path $ParentDir | Out-Null }
        git clone --depth 1 $RepoUrl $InstallDir
    }
} else {
    $TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("dfs_install_" + [System.Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null
    try {
        $ZipPath = Join-Path $TmpDir "dfs.zip"
        Invoke-WebRequest -Uri $ZipUrl -OutFile $ZipPath
        Expand-Archive -Path $ZipPath -DestinationPath $TmpDir -Force
        $Extracted = Get-ChildItem -Path $TmpDir -Directory | Select-Object -First 1
        if (-not $Extracted) { throw "Failed to extract dfs archive." }
        if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
        $ParentDir = Split-Path -Parent $InstallDir
        if (-not (Test-Path $ParentDir)) { New-Item -ItemType Directory -Force -Path $ParentDir | Out-Null }
        Move-Item -Path $Extracted.FullName -Destination $InstallDir
    } finally {
        Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
    }
}

$Synced = $false
try {
    uv sync --project $InstallDir --extra libp2p
    if ($LASTEXITCODE -eq 0) { $Synced = $true }
} catch {
    $Synced = $false
}
if (-not $Synced) {
    Write-Warning "[dfs] libp2p extra failed on this environment; installing core dependencies..."
    uv sync --project $InstallDir
    if ($LASTEXITCODE -ne 0) { throw "uv sync failed with exit code $LASTEXITCODE" }
}

if (-not (Test-Path $BinDir)) { New-Item -ItemType Directory -Force -Path $BinDir | Out-Null }
$VenvScripts = Join-Path $InstallDir ".venv\Scripts"
foreach ($cmd in @("dfs", "dfscli", "dfssvc")) {
    $Target = Join-Path $VenvScripts "$cmd.exe"
    $Shim = Join-Path $BinDir "$cmd.cmd"
    Set-Content -Path $Shim -Value "@echo off`r`n`"$Target`" %*`r`n" -Encoding Ascii
}

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not $UserPath) { $UserPath = "" }
if ($UserPath -notlike "*$BinDir*") {
    $NewUserPath = if ($UserPath) { "$BinDir;$UserPath" } else { $BinDir }
    [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
}

Write-Host ""
Write-Host "Installed dfs, dfscli, and dfssvc to $BinDir"
Write-Host "Run:"
Write-Host "  dfs start"
Write-Host "  dfs push .\my-folder"
