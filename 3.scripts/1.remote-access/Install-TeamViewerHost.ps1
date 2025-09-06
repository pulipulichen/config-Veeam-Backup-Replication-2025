<# 
.SYNOPSIS
  Download and silently install TeamViewer Host on Windows Server 2022.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\Install-TeamViewerHost.ps1
#>

[CmdletBinding()]
param(
  [string]$DownloadDir = $env:TEMP,
  [switch]$Force
)

function Write-Info($msg){ Write-Host "[INFO]  $msg" -ForegroundColor Cyan }
function Write-Warn($msg){ Write-Host "[WARN]  $msg" -ForegroundColor Yellow }
function Write-Err ($msg){ Write-Host "[ERROR] $msg" -ForegroundColor Red }

# 1) Admin check
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Err "Please run this script as Administrator."
  exit 1
}

# 2) Enable TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# 3) TeamViewer Host download URL
$tvUrl = "https://download.teamviewer.com/download/TeamViewer_Host_Setup.exe"

# 4) Prepare download path
if (-not (Test-Path -LiteralPath $DownloadDir)) {
  Write-Info "Creating download directory: $DownloadDir"
  New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null
}
$installerPath = Join-Path $DownloadDir "TeamViewer_Host_Setup.exe"

# 5) Download
if ((Test-Path -LiteralPath $installerPath) -and -not $Force) {
  Write-Warn "Installer already exists at: $installerPath (use -Force to overwrite)"
} else {
  Write-Info "Downloading TeamViewer Host..."
  Invoke-WebRequest -Uri $tvUrl -OutFile $installerPath -UseBasicParsing
  Write-Info "Download completed: $installerPath"
}

# 6) Silent install
Write-Info "Starting silent installation..."
$proc = Start-Process -FilePath $installerPath -ArgumentList "/S" -PassThru -Wait
Write-Info "Installer exited with code: $($proc.ExitCode)"

# 7) Check registry for installation
$installed = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                           'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall' `
  -ErrorAction SilentlyContinue |
  ForEach-Object { try { Get-ItemProperty $_.PsPath } catch { $null } } |
  Where-Object { $_.DisplayName -like "TeamViewer*" } |
  Sort-Object DisplayVersion -Descending |
  Select-Object -First 1

if ($installed) {
  Write-Info ("TeamViewer Host installed. Version: {0}" -f $installed.DisplayVersion)
} else {
  Write-Warn "Unable to confirm installation via registry."
}

# 8) Ensure service running
$svc = Get-Service -Name "TeamViewer" -ErrorAction SilentlyContinue
if ($svc) {
  if ($svc.Status -ne "Running") {
    Start-Service -Name "TeamViewer"
    Write-Info "TeamViewer service started."
  }
  Set-Service -Name "TeamViewer" -StartupType Automatic
  Write-Info "Service status: $((Get-Service -Name 'TeamViewer').Status)"
} else {
  Write-Warn "TeamViewer service not found."
}

Write-Host ""
Write-Host "=== Installation Completed ===" -ForegroundColor Green
Write-Host "TeamViewer Host has been installed and service is configured."
