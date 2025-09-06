<# 
.SYNOPSIS
  Enable/Disable automatic logon to desktop for Windows Server 2022 (no password prompt, no Ctrl+Alt+Del)

.PARAMETER Enable
  Enable automatic logon (interactive input of account and password)

.PARAMETER Disable
  Disable automatic logon and clear related registry values
#>

param(
  [switch]$Enable,
  [switch]$Disable
)

function Assert-Admin {
  $current = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($current)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Please run PowerShell with administrator privileges."
  }
}

function Enable-AutoLogon {
  Write-Host "=== Enabling Automatic Logon Settings ===" -ForegroundColor Cyan

  # Interactive input
  $user = Read-Host "Please enter the account for automatic logon (e.g., Administrator or domain\user)"
  if ([string]::IsNullOrWhiteSpace($user)) { throw "Account cannot be empty." }

  # Parse domain/local
  $domain = ""
  $username = $user
  if ($user -like "*\*") {
    $parts = $user.Split("\",2)
    $domain = $parts[0]
    $username = $parts[1]
  } else {
    # Default to using the local computer name as DefaultDomainName
    $domain = $env:COMPUTERNAME
  }

  # Secure password input (not displayed), then converted to plain text for registry (AutoLogon requirement)
  $securePwd = Read-Host "Please enter the password for the account (input will not be displayed)" -AsSecureString
  if (-not $securePwd) { throw "Password cannot be empty." }
  $password = [Runtime.InteropServices.Marshal]::PtrToStringUni(
      [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePwd)
  )

  $winlogonKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
  $policySysKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

  # Create necessary keys
  if (-not (Test-Path $winlogonKey)) { New-Item -Path $winlogonKey | Out-Null }
  if (-not (Test-Path $policySysKey)) { New-Item -Path $policySysKey | Out-Null }

  # Write AutoAdminLogon related values
  New-ItemProperty -Path $winlogonKey -Name 'AutoAdminLogon'     -PropertyType String -Value '1' -Force | Out-Null
  New-ItemProperty -Path $winlogonKey -Name 'DefaultUserName'    -PropertyType String -Value $username -Force | Out-Null
  New-ItemProperty -Path $winlogonKey -Name 'DefaultDomainName'  -PropertyType String -Value $domain   -Force | Out-Null
  New-ItemProperty -Path $winlogonKey -Name 'DefaultPassword'    -PropertyType String -Value $password -Force | Out-Null
  # Force AutoAdminLogon after each logout
  New-ItemProperty -Path $winlogonKey -Name 'ForceAutoLogon'     -PropertyType String -Value '1' -Force | Out-Null
  # If multiple screens/shell issues, ensure shell restarts automatically
  New-ItemProperty -Path $winlogonKey -Name 'AutoRestartShell'   -PropertyType DWord  -Value 1   -Force | Out-Null

  # Remove Ctrl+Alt+Del requirement
  New-ItemProperty -Path $policySysKey -Name 'DisableCAD'        -PropertyType DWord  -Value 1   -Force | Out-Null

  Write-Host "`nSettings complete. The system will automatically log in as: $domain\$username after reboot." -ForegroundColor Green
  Write-Host "Reminder: The password has been written to the registry in plain text (DefaultPassword). Please ensure machine security."
}

function Disable-AutoLogon {
  Write-Host "=== Disabling Automatic Logon and Clearing Settings ===" -ForegroundColor Yellow
  $winlogonKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
  $policySysKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

  $props = @('AutoAdminLogon','DefaultUserName','DefaultDomainName','DefaultPassword','ForceAutoLogon','AutoRestartShell')
  foreach ($p in $props) {
    if (Get-ItemProperty -Path $winlogonKey -Name $p -ErrorAction SilentlyContinue) {
      Remove-ItemProperty -Path $winlogonKey -Name $p -ErrorAction SilentlyContinue
    }
  }

  # Restore Ctrl+Alt+Del requirement (optional)
  if (Get-ItemProperty -Path $policySysKey -Name 'DisableCAD' -ErrorAction SilentlyContinue) {
    Set-ItemProperty -Path $policySysKey -Name 'DisableCAD' -Value 0
  }

  Write-Host "Automatic logon has been disabled and sensitive registry values cleared." -ForegroundColor Green
}

try {
  Assert-Admin

  if ($Enable -and $Disable) { throw "Please choose either -Enable or -Disable." }
  elseif ($Enable) { Enable-AutoLogon }
  elseif ($Disable) { Disable-AutoLogon }
  else {
    Write-Host "Usage:" -ForegroundColor Cyan
    Write-Host "  Enable automatic logon:" -NoNewline
    Write-Host "  .\AutoLogon.ps1 -Enable" -ForegroundColor White
    Write-Host "  Disable automatic logon:" -NoNewline
    Write-Host "  .\AutoLogon.ps1 -Disable" -ForegroundColor White
  }
}
catch {
  Write-Error $_.Exception.Message
  exit 1
}
