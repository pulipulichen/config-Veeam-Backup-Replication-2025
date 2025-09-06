param(
  [switch]$Enable,
  [switch]$Disable,
  [int]$Port = 3389,
  [string[]]$AddUser,        # Example: -AddUser 'Administrator','DOMAIN\user1'
  [switch]$NoNLA             # Use this to disable NLA (default is enabled)
)

function Assert-Admin {
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $p  = New-Object Security.Principal.WindowsPrincipal($id)
  if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run PowerShell as Administrator."
  }
}

function Enable-Rdp {
  Write-Host "=== Enabling Remote Desktop ===" -ForegroundColor Cyan

  # 1) Enable RDP
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0

  # 2) Configure NLA
  $nla = if ($NoNLA) { 0 } else { 1 }
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value $nla

  # 3) Change RDP port if needed
  if ($Port -ne 3389) {
    Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'PortNumber' -Value $Port
  }

  # 4) Enable firewall rules
  Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | Out-Null
  if ($Port -ne 3389) {
    $ruleName = "RDP-Custom-$Port"
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
      New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port | Out-Null
    } else {
      Set-NetFirewallRule -DisplayName $ruleName -Enabled True | Out-Null
    }
  }

  # 5) Ensure service is running
  Set-Service -Name "TermService" -StartupType Automatic
  if ((Get-Service TermService).Status -ne 'Running') { Start-Service TermService }
  if ($Port -ne 3389) { Restart-Service -Name TermService -Force }

  # 6) Add users if specified
  if ($AddUser) {
    foreach ($u in $AddUser) {
      try {
        if (Get-Command Add-LocalGroupMember -ErrorAction SilentlyContinue) {
          Add-LocalGroupMember -Group "Remote Desktop Users" -Member $u -ErrorAction Stop
        } else {
          & net localgroup "Remote Desktop Users" $u /add | Out-Null
        }
        Write-Host "Added user to Remote Desktop Users: $u"
      } catch {
        Write-Warning "Failed to add $u: $($_.Exception.Message)"
      }
    }
  }

  # 7) Show status
  $curPort = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name PortNumber).PortNumber
  $nlaNow  = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication).UserAuthentication
  Write-Host "`nRemote Desktop enabled. Port: $curPort ; NLA: " -NoNewline
  Write-Host ($(if($nlaNow -eq 1) {'Enabled'} else {'Disabled'})) -ForegroundColor Green
}

function Disable-Rdp {
  Write-Host "=== Disabling Remote Desktop ===" -ForegroundColor Yellow
  Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1
  Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | Out-Null
  Get-NetFirewallRule -DisplayName "RDP-Custom-*" -ErrorAction SilentlyContinue | ForEach-Object {
    Disable-NetFirewallRule -Name $_.Name | Out-Null
  }
  Write-Host "Remote Desktop disabled and firewall rules removed." -ForegroundColor Green
}

try {
  Assert-Admin
  if ($Enable -and $Disable) { throw "Choose only one: -Enable or -Disable" }
  elseif ($Enable) { Enable-Rdp }
  elseif ($Disable) { Disable-Rdp }
  else {
@"
Usage:
  Enable RDP (default port 3389, NLA enabled):
    .\Enable-RDP.ps1 -Enable

  Enable with custom port, add users, disable NLA:
    .\Enable-RDP.ps1 -Enable -Port 3390 -AddUser 'Administrator','DOMAIN\user1' -NoNLA

  Disable RDP:
    .\Enable-RDP.ps1 -Disable
"@ | Write-Host
  }
}
catch {
  Write-Error $_.Exception.Message
  exit 1
}
