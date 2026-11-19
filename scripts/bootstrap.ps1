param(
    [string]$Token = $env:DFS_INVITE_TOKEN
)

$ErrorActionPreference = "Stop"

# Windows PowerShell bootstrap for dfs.
# Usage:
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/bootstrap.ps1))) <TOKEN>
#   $env:DFS_INVITE_TOKEN="<TOKEN>"; irm https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/bootstrap.ps1 | iex

if (-not $Token) {
    Write-Error "Usage: `$env:DFS_INVITE_TOKEN='<TOKEN>'; irm https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/bootstrap.ps1 | iex"
    exit 2
}

$DestDir = if ($env:DFS_DEST) { $env:DFS_DEST } else { ".\dfs-sync" }
$BinDir = Join-Path $env:USERPROFILE ".local\bin"
$CargoBin = Join-Path $env:USERPROFILE ".cargo\bin"
if ($env:PATH -notlike "*$BinDir*") { $env:PATH = "$BinDir;$env:PATH" }
if ($env:PATH -notlike "*$CargoBin*") { $env:PATH = "$CargoBin;$env:PATH" }

if (-not (Get-Command dfscli -ErrorAction SilentlyContinue)) {
    $InstallUrl = if ($env:DFS_INSTALL_PS1_URL) { $env:DFS_INSTALL_PS1_URL } else { "https://raw.githubusercontent.com/yashiki2005/dfs/main/scripts/install.ps1" }
    irm $InstallUrl | iex
    if ($env:PATH -notlike "*$BinDir*") { $env:PATH = "$BinDir;$env:PATH" }
}

if ($env:DFS_SYNC_ONLY -eq "1") {
    & dfscli invite join $Token --dest $DestDir --sync
} else {
    & dfscli invite join $Token --dest $DestDir --watch
}
exit $LASTEXITCODE
