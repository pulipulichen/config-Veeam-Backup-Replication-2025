<# 
.SYNOPSIS
  啟用/停用 Windows Server 2022 的自動登入到桌面（免密碼提示、免 Ctrl+Alt+Del）

.PARAMETER Enable
  啟用自動登入（互動式輸入帳密）

.PARAMETER Disable
  停用自動登入並清除相關登錄值
#>

param(
  [switch]$Enable,
  [switch]$Disable
)

function Assert-Admin {
  $current = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($current)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "請以系統管理員權限執行 PowerShell。"
  }
}

function Enable-AutoLogon {
  Write-Host "=== 啟用自動登入設定 ===" -ForegroundColor Cyan

  # 互動式輸入
  $user = Read-Host "請輸入要自動登入的帳號（例如 Administrator 或 domain\user）"
  if ([string]::IsNullOrWhiteSpace($user)) { throw "帳號不可為空。" }

  # 解析網域/本機
  $domain = ""
  $username = $user
  if ($user -like "*\*") {
    $parts = $user.Split("\",2)
    $domain = $parts[0]
    $username = $parts[1]
  } else {
    # 預設使用本機電腦名稱作為 DefaultDomainName
    $domain = $env:COMPUTERNAME
  }

  # 安全輸入密碼（輸入時不顯示），之後轉為明文寫入登錄（AutoLogon需求）
  $securePwd = Read-Host "請輸入該帳號密碼（輸入不會顯示）" -AsSecureString
  if (-not $securePwd) { throw "密碼不可為空。" }
  $password = [Runtime.InteropServices.Marshal]::PtrToStringUni(
      [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePwd)
  )

  $winlogonKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
  $policySysKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

  # 建立必要機碼
  if (-not (Test-Path $winlogonKey)) { New-Item -Path $winlogonKey | Out-Null }
  if (-not (Test-Path $policySysKey)) { New-Item -Path $policySysKey | Out-Null }

  # 寫入 AutoAdminLogon 相關值
  New-ItemProperty -Path $winlogonKey -Name 'AutoAdminLogon'     -PropertyType String -Value '1' -Force | Out-Null
  New-ItemProperty -Path $winlogonKey -Name 'DefaultUserName'    -PropertyType String -Value $username -Force | Out-Null
  New-ItemProperty -Path $winlogonKey -Name 'DefaultDomainName'  -PropertyType String -Value $domain   -Force | Out-Null
  New-ItemProperty -Path $winlogonKey -Name 'DefaultPassword'    -PropertyType String -Value $password -Force | Out-Null
  # 強制每次登出後仍使用 AutoAdminLogon
  New-ItemProperty -Path $winlogonKey -Name 'ForceAutoLogon'     -PropertyType String -Value '1' -Force | Out-Null
  # 若有多螢幕/殼層異常，確保殼層自動重啟
  New-ItemProperty -Path $winlogonKey -Name 'AutoRestartShell'   -PropertyType DWord  -Value 1   -Force | Out-Null

  # 移除 Ctrl+Alt+Del 需求
  New-ItemProperty -Path $policySysKey -Name 'DisableCAD'        -PropertyType DWord  -Value 1   -Force | Out-Null

  Write-Host "`n設定完成。接下來重開機後會自動登入為：$domain\$username" -ForegroundColor Green
  Write-Host "提醒：密碼已以明文寫入登錄（DefaultPassword）。請確保機器安全性控管。"
}

function Disable-AutoLogon {
  Write-Host "=== 停用自動登入並清除設定 ===" -ForegroundColor Yellow
  $winlogonKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
  $policySysKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'

  $props = @('AutoAdminLogon','DefaultUserName','DefaultDomainName','DefaultPassword','ForceAutoLogon','AutoRestartShell')
  foreach ($p in $props) {
    if (Get-ItemProperty -Path $winlogonKey -Name $p -ErrorAction SilentlyContinue) {
      Remove-ItemProperty -Path $winlogonKey -Name $p -ErrorAction SilentlyContinue
    }
  }

  # 還原 Ctrl+Alt+Del 要求（可選）
  if (Get-ItemProperty -Path $policySysKey -Name 'DisableCAD' -ErrorAction SilentlyContinue) {
    Set-ItemProperty -Path $policySysKey -Name 'DisableCAD' -Value 0
  }

  Write-Host "已停用自動登入並清掉敏感登錄值。" -ForegroundColor Green
}

try {
  Assert-Admin

  if ($Enable -and $Disable) { throw "請擇一：-Enable 或 -Disable" }
  elseif ($Enable) { Enable-AutoLogon }
  elseif ($Disable) { Disable-AutoLogon }
  else {
    Write-Host "用法：" -ForegroundColor Cyan
    Write-Host "  啟用自動登入：" -NoNewline
    Write-Host "  .\AutoLogon.ps1 -Enable" -ForegroundColor White
    Write-Host "  停用自動登入：" -NoNewline
    Write-Host "  .\AutoLogon.ps1 -Disable" -ForegroundColor White
  }
}
catch {
  Write-Error $_.Exception.Message
  exit 1
}
