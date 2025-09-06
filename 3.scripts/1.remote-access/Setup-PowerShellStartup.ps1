#Requires -Version 5.1
# Enable strict mode
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function New-AutoElevatedPSSession {
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetFolder
    )

    try {
        Write-Verbose "Checking target folder..."
        if (-not (Test-Path -Path $TargetFolder -PathType Container)) {
            throw "Target folder does not exist: $TargetFolder"
        }

        # Get Startup folder
        $StartupFolder = [Environment]::GetFolderPath("Startup")
        $ShortcutPath  = Join-Path -Path $StartupFolder -ChildPath "PowerShell-Admin-ConfigVeeam.lnk"

        Write-Verbose "Startup folder: $StartupFolder"
        Write-Verbose "Shortcut path: $ShortcutPath"

        # Remove old shortcut if exists
        if (Test-Path $ShortcutPath) {
            Remove-Item $ShortcutPath -Force
            Write-Verbose "Old shortcut removed."
        }

        # Create WScript.Shell COM object
        $WshShell = New-Object -ComObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($ShortcutPath)

        # PowerShell target with elevation and custom Start-Location
        $Shortcut.TargetPath = "powershell.exe"
        $Shortcut.Arguments  = "-NoExit -Command `"Set-Location -Path '$TargetFolder'`""
        $Shortcut.WorkingDirectory = $TargetFolder
        $Shortcut.IconLocation = "powershell.exe,0"
        $Shortcut.Description  = "Auto start PowerShell (Admin) in $TargetFolder"

        # Set RunAsAdmin (via shortcut property)
        $Shortcut.Save()

        # Mark shortcut as 'Run as Administrator'
        $bytes = [System.IO.File]::ReadAllBytes($ShortcutPath)
        $bytes[0x15] = $bytes[0x15] -bor 0x20
        [System.IO.File]::WriteAllBytes($ShortcutPath, $bytes)

        Write-Information "Shortcut created successfully at $ShortcutPath" -InformationAction Continue
    }
    catch {
        Write-Error "Failed to create auto-elevated PowerShell shortcut: $_"
    }
}

# ===== Example Usage =====
# Replace with your actual Desktop path if needed
$Desktop = [Environment]::GetFolderPath("Desktop")
$Target  = Join-Path $Desktop "config-Veeam-Backup-Replication-2025\3.scripts\1.remote-access"

# Run function (with -Verbose to see details)
New-AutoElevatedPSSession -TargetFolder $Target -Verbose
