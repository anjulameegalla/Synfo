# Synfo.ps1

# function for colored output
function Write-Header ($Text, $Color = "Cyan") {
    Write-Host ""
    Write-Host "--- $($Text) ---" -ForegroundColor $Color -BackgroundColor "DarkGray"
}

# --- Banner ---
Write-Host "==================================================================================" -ForegroundColor Yellow
Write-Host "                        SYSTEM DIAGNOSTIC REPORT (SYNFO)" -ForegroundColor Yellow
Write-Host "==================================================================================" -ForegroundColor Yellow

try {
    # Pre-fetch common objects for efficiency and single querying
    $OS = Get-CimInstance Win32_OperatingSystem
    $Processor = Get-CimInstance Win32_Processor
    $Computer = Get-CimInstance Win32_ComputerSystem
    $Reg = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)

    # --- SYSTEM INFORMATION ---
    Write-Header "SYSTEM INFORMATION"
    $BootTime = $OS.LastBootUpTime
    $CurrentTime = Get-Date
    $Uptime = New-TimeSpan -Start $BootTime -End $CurrentTime

    [PSCustomObject]@{
        Caption = $OS.Caption
        Architecture = $OS.OSArchitecture
        BuildNumber = $OS.BuildNumber
        BootTime = $BootTime.ToString('yyyy-MM-dd HH:mm:ss')
        Uptime = "$($Uptime.Days)d $($Uptime.Hours)h $($Uptime.Minutes)m"
        SystemRole = $Computer.SystemType
    } | Format-List

    # --- BIOS INFORMATION (Hardware Integrity) ---
    Write-Header "BIOS INFORMATION"
    Get-CimInstance Win32_Bios | Select-Object Manufacturer, Name, Version, SerialNumber | Format-List

    # --- CPU INFORMATION ---

    # CPU usage percentage
    $CpuUsage = 0.00
    try {
        $PerfCounter = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 2 -ErrorAction Stop | Select-Object -ExpandProperty CounterSamples
        $CpuUsage = $PerfCounter[1].CookedValue
    } catch {
        Write-Warning "Could not retrieve CPU usage percentage. Skipping."
    }

    Write-Header "CPU INFORMATION"
    [PSCustomObject]@{
        Model = $Processor.Name
        LogicalCores = $Processor.NumberOfLogicalProcessors
        PhysicalCores = $Processor.NumberOfCores
        MaxClockSpeed = "$([Math]::Round($Processor.MaxClockSpeed / 1000, 2)) GHz"
        CurrentUsage = "{0:N2}%" -f $CpuUsage
    } | Format-List
    
    # --- MEMORY INFORMATION ---

    $TotalMemoryGB = $OS.TotalVisibleMemorySize / 1MB
    $FreeMemoryGB = $OS.FreePhysicalMemory / 1MB
    $UsedMemoryGB = $TotalMemoryGB - $FreeMemoryGB

    Write-Header "MEMORY SUMMARY (GB)"
    [PSCustomObject]@{
        TotalRAM = "{0:N2} GB" -f $TotalMemoryGB
        UsagePercent = "{0:N2}%" -f (($UsedMemoryGB / $TotalMemoryGB) * 100)
    } | Format-List
    
    Write-Host "  $([char]0x2022) PHYSICAL MEMORY STICKS:" # Using a simple bullet point
    # Convert Bytes to GB, MHz to Speed, and get Manufacturer/Part Number
    Get-CimInstance Win32_PhysicalMemory | Select-Object Manufacturer, PartNumber,
        @{N='CapacityGB'; E={[Math]::Round($_.Capacity/1GB, 2)}},
        @{N='SpeedMHz'; E={$_.Speed}},
        @{N='Locator'; E={$_.DeviceLocator}} | Format-Table -AutoSize

    # --- DISK INFORMATION (Physical and Logical) ---

    Write-Header "DISK INFORMATION"
    Write-Host "  $([char]0x2022) PHYSICAL DISK DRIVES:"
    Get-CimInstance Win32_DiskDrive | Select-Object DeviceID, Model, MediaType, 
        @{N='SizeGB'; E={[Math]::Round($_.Size/1GB, 2)}} | Format-Table -AutoSize

    Write-Host "  $([char]0x2022) LOGICAL VOLUME USAGE:"
    Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | Select-Object DeviceID, VolumeName, 
        @{N='TotalSizeGB'; E={[math]::Round($_.Size/1GB, 2)}}, 
        @{N='FreeSpaceGB'; E={[math]::Round($_.Freespace/1GB, 2)}}, 
        @{N='UsagePercent'; E={"{0:N2}%" -f (($_.Size - $_.Freespace) / $_.Size * 100)}} | Format-Table -AutoSize

    # --- NETWORK INTERFACES ---

    Write-Header "NETWORK INTERFACES (IPv4)"
    Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notlike "Loopback*" } | Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize

    # --- SECURITY STATUS & HARDENING CHECKS ---

    Write-Header "SECURITY & HARDENING CHECKS" -Color Red

    # Antivirus Status
    $AV = Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue
    $AVStatus = if ($AV) { $AV.DisplayName } else { "N/A or Disabled" }
    
    # UAC Status (1 = Enabled, 0 = Disabled)
    $UACKey = $Reg.OpenSubKey("Software\Microsoft\Windows\CurrentVersion\Policies\System")
    $UACEnabled = $UACKey.GetValue("EnableLUA") -eq 1
    $UACStatus = if ($UACEnabled) { "Enabled (Good)" } else { "Disabled (CRITICAL)" }
    $UACColor = if ($UACEnabled) { "Green" } else { "Red" }
    $UACKey.Close()
    
    # Execution Policy
    $ExecPolicy = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue
    $ExecColor = if ($ExecPolicy -eq "RemoteSigned" -or $ExecPolicy -eq "AllSigned") { "Green" } elseif ($ExecPolicy -eq "Restricted") { "Yellow" } else { "Red" }

    Write-Host "UAC Status: $($UACStatus)" -ForegroundColor $UACColor
    Write-Host "PS Execution Policy (LocalMachine): $($ExecPolicy)" -ForegroundColor $ExecColor
    Write-Host "Antivirus: $($AVStatus)" -ForegroundColor "Yellow"
    
    # --- INSTALLED HOTFIXES (Patch Level) ---

    Write-Header "INSTALLED HOTFIXES (Patch Level)"
    $HotfixCount = (Get-Hotfix -ErrorAction SilentlyContinue).Count
    Write-Output "Total Hotfixes Installed: $HotfixCount"
    
    # --- SERVICES CHECK (Reliability & Security) ---

    Write-Header "SERVICES CHECK (CRITICAL/CONCERN)"

    # Show services that are: 1. Running and Automatic, OR 2. Stopped but Automatic (highlight Stopped/Automatic in Red)
    Get-Service | Where-Object { 
        ($_.Status -eq "Running" -and $_.StartType -eq "Automatic") -or
        ($_.Status -eq "Stopped" -and $_.StartType -eq "Automatic") 
    } | Select-Object Name, DisplayName, Status, StartType, Description | Format-Table -AutoSize -Wrap

    # --- ACTIVE USERS ---

    Write-Header "ACTIVE USERS"
    $Computer | Select-Object UserName | Format-List
    
    # --- ENVIRONMENTAL VARIABLES (Security Check) ---

    Write-Header "ENVIRONMENTAL VARIABLES (COMMON)"
    $env | Where-Object { 
        $_.Name -in @("USERNAME", "COMPUTERNAME", "PATH", "TEMP", "APPDATA", "LOGONSERVER")
    } | Select-Object Name, Value | Format-Table -AutoSize

    # --- OPEN NETWORK CONNECTIONS (Security Relevant) ---
    
    Write-Header "OPEN NETWORK CONNECTIONS (LISTEN/ESTABLISHED)"
    $NetConnections = Get-NetTCPConnection | Where-Object { $_.State -in @('Listen', 'Established') }
    
    $ProcessMap = @{}
    $PIDs = $NetConnections.OwningProcess | Select-Object -Unique
    Get-Process -Id $PIDs -ErrorAction SilentlyContinue | ForEach-Object {
        $ProcessMap[$_.Id] = $_.ProcessName
    }

    $NetConnections | ForEach-Object {
        $ProcessName = $ProcessMap[$_.OwningProcess]
        
        [PSCustomObject]@{
            PID = $_.OwningProcess
            Process = if ($ProcessName) {$ProcessName} else {"N/A"}
            LocalAddress = "$($_.LocalAddress):$($_.LocalPort)"
            RemoteAddress = "$($_.RemoteAddress):$($_.RemotePort)"
            Status = $_.State
        }
    } | Format-Table -AutoSize

}
catch {
    Write-Error "An error occurred during system information retrieval: $($_.Exception.Message)"
    Write-Error "Please ensure you have necessary permissions (Run as Administrator) and are on a supported Windows version."
}
Write-Host "==================================================================================" -ForegroundColor Yellow

# --- Post-script Action (Focus Mode) ---
# Write-Host "Activating Focus Mode: Maximizing PowerShell window..." -ForegroundColor DarkYellow

# 1. Maximize the current PowerShell window (Full Screen)
# $Host.UI.RawUI.WindowSize = $Host.UI.RawUI.MaxWindowSize

# 2. Open Task Manager automatically for live performance analysis
# Write-Host "Launching Task Manager for live performance review..." -ForegroundColor DarkYellow
# Start-Process taskmgr.exe -ErrorAction SilentlyContinue