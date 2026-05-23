#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets up the LocalScan malware analysis sandbox on a fresh Windows VM.

.DESCRIPTION
    1. Installs Python 3 (via winget, then pip)
    2. Creates C:\MalwareAnalysis directory layout
    3. Copies source files (expects them next to this script)
    4. Installs pip dependencies
    5. Configures Windows Defender (keeps real-time on, disables cloud reporting)
    6. Enables process-creation audit policy (Event ID 4688)
    7. Installs Sysmon for deep process/network visibility (optional)
    8. Opens firewall for port 5000
    9. Creates a Scheduled Task that launches the server on user login
   10. Adds a desktop shortcut

.NOTES
    Run from the folder containing app.py, scanner.py, monitor.py,
    requirements.txt, and the templates\ folder.

    Tested on Windows 10 / 11 (x64).
    For an isolated VirtualBox VM only -- do NOT run on a production machine.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
function Write-Step([string]$msg) {
    Write-Host ""
    Write-Host "[+] $msg" -ForegroundColor Cyan
}
function Write-Ok([string]$msg) {
    Write-Host "    [OK] $msg" -ForegroundColor Green
}
function Write-Warn([string]$msg) {
    Write-Host "    [!!] $msg" -ForegroundColor Yellow
}
function Write-Err([string]$msg) {
    Write-Host "    [XX] $msg" -ForegroundColor Red
}

$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallDir = "C:\MalwareAnalysis"
$PythonExe  = $null

# ---------------------------------------------------------------------------
# 1. Python
# ---------------------------------------------------------------------------
Write-Step "Checking for Python 3.10+"

$existing = Get-Command python -ErrorAction SilentlyContinue
if ($existing) {
    $ver = & python --version 2>&1
    if ($ver -match "3\.(\d+)" -and [int]$Matches[1] -ge 10) {
        $PythonExe = $existing.Source
        Write-Ok "Found $ver at $PythonExe"
    }
}

if (-not $PythonExe) {
    Write-Warn "Python 3.10+ not found. Attempting install via winget..."
    try {
        winget install --id Python.Python.3.11 --silent --accept-source-agreements --accept-package-agreements
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("Path","User")
        $PythonExe = (Get-Command python -ErrorAction Stop).Source
        Write-Ok "Python installed: $PythonExe"
    }
    catch {
        Write-Err "winget install failed: $_"
        Write-Host "    Please install Python 3.10+ from https://python.org then re-run." -ForegroundColor Yellow
        exit 1
    }
}

# ---------------------------------------------------------------------------
# 2. Create directory layout
# ---------------------------------------------------------------------------
Write-Step "Creating directory layout at $InstallDir"

foreach ($dir in @($InstallDir,
                   "$InstallDir\uploads",
                   "$InstallDir\results",
                   "$InstallDir\templates",
                   "$InstallDir\logs")) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}
Write-Ok "Directories created"

# ---------------------------------------------------------------------------
# 3. Copy source files
# ---------------------------------------------------------------------------
Write-Step "Copying source files from $ScriptDir"

$requiredFiles = @("app.py", "scanner.py", "monitor.py", "requirements.txt")
foreach ($f in $requiredFiles) {
    $src = Join-Path $ScriptDir $f
    if (-not (Test-Path $src)) {
        Write-Err "Missing required file: $f  (looked in $ScriptDir)"
        exit 1
    }
    Copy-Item $src $InstallDir -Force
    Write-Ok "Copied $f"
}

$tplSrc = Join-Path $ScriptDir "templates"
if (Test-Path $tplSrc) {
    Copy-Item "$tplSrc\*" "$InstallDir\templates\" -Recurse -Force
    Write-Ok "Copied templates\"
}
else {
    Write-Err "templates\ folder not found in $ScriptDir"
    exit 1
}

# ---------------------------------------------------------------------------
# 4. pip install
# ---------------------------------------------------------------------------
Write-Step "Installing Python dependencies"

& $PythonExe -m pip install --upgrade pip --quiet
& $PythonExe -m pip install -r "$InstallDir\requirements.txt" --quiet

if ($LASTEXITCODE -ne 0) {
    Write-Err "pip install failed"
    exit 1
}
Write-Ok "Dependencies installed (flask, psutil, pywin32)"

try {
    $scripts = Join-Path (Split-Path $PythonExe) "Scripts"
    $post    = Join-Path $scripts "pywin32_postinstall.py"
    if (Test-Path $post) {
        & $PythonExe $post -install 2>&1 | Out-Null
        Write-Ok "pywin32 post-install OK"
    }
}
catch {
    Write-Warn "pywin32 post-install skipped (not always needed on Python 3.11+)"
}

# ---------------------------------------------------------------------------
# 5. Windows Defender tuning
# ---------------------------------------------------------------------------
Write-Step "Configuring Windows Defender"

Set-MpPreference -SubmitSamplesConsent  NeverSend -ErrorAction SilentlyContinue
Set-MpPreference -MAPSReporting         Disabled  -ErrorAction SilentlyContinue
Set-MpPreference -DisableAutoExclusions $false    -ErrorAction SilentlyContinue
Add-MpPreference -ExclusionPath "$InstallDir\uploads" -ErrorAction SilentlyContinue

Write-Ok "Defender configured (real-time ON, cloud reporting OFF, uploads\ excluded from auto-quarantine)"
Write-Warn "Samples in uploads\ will NOT be auto-quarantined. Keep this VM isolated!"

# ---------------------------------------------------------------------------
# 6. Enable process-creation audit (Event ID 4688)
# ---------------------------------------------------------------------------
Write-Step "Enabling process creation audit policy (Event ID 4688)"

auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null

$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $regPath)) {
    New-Item $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

Write-Ok "Process creation (with command line) logging enabled"

# ---------------------------------------------------------------------------
# 7. Sysmon (optional)
# ---------------------------------------------------------------------------
Write-Step "Checking for Sysmon"

$sysmonExe = Get-Command sysmon64.exe -ErrorAction SilentlyContinue
if (-not $sysmonExe) {
    $sysmonExe = Get-Command sysmon.exe -ErrorAction SilentlyContinue
}

if ($sysmonExe) {
    Write-Ok "Sysmon already installed at $($sysmonExe.Source)"
}
else {
    Write-Warn "Sysmon not found. Attempting download from Sysinternals..."
    $sysmonZip = "$env:TEMP\Sysmon.zip"
    $sysmonDir = "$env:TEMP\Sysmon"
    try {
        Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
                          -OutFile $sysmonZip -UseBasicParsing -TimeoutSec 30
        Expand-Archive -Path $sysmonZip -DestinationPath $sysmonDir -Force

        $sysmonCfg = @"
<Sysmon schemaversion="4.90">
  <HashAlgorithms>md5,sha256</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="include">
        <Rule groupRelation="or"><Image condition="is not">System</Image></Rule>
      </ProcessCreate>
      <NetworkConnect onmatch="include">
        <Rule groupRelation="or"><Initiated condition="is">true</Initiated></Rule>
      </NetworkConnect>
      <DnsQuery onmatch="include">
        <Rule groupRelation="or"><QueryName condition="contains">.</QueryName></Rule>
      </DnsQuery>
      <FileCreate onmatch="include">
        <Rule groupRelation="or">
          <TargetFilename condition="end with">.exe</TargetFilename>
          <TargetFilename condition="end with">.dll</TargetFilename>
          <TargetFilename condition="end with">.bat</TargetFilename>
          <TargetFilename condition="end with">.ps1</TargetFilename>
        </Rule>
      </FileCreate>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"@
        $cfgPath = "$sysmonDir\localscan.xml"
        $sysmonCfg | Out-File -Encoding UTF8 -FilePath $cfgPath

        if (Test-Path "$sysmonDir\Sysmon64.exe") {
            $sysmonBin = "$sysmonDir\Sysmon64.exe"
        }
        else {
            $sysmonBin = "$sysmonDir\Sysmon.exe"
        }

        & $sysmonBin -accepteula -i $cfgPath 2>&1 | Out-Null
        Copy-Item $sysmonBin "C:\Windows\System32\" -Force
        Write-Ok "Sysmon installed and configured"
    }
    catch {
        Write-Warn "Sysmon auto-install failed: $_"
        Write-Warn "Download manually from https://docs.microsoft.com/sysinternals/downloads/sysmon"
        Write-Warn "The sandbox works without it -- you just get less telemetry."
    }
}

# ---------------------------------------------------------------------------
# 8. Firewall rule for port 5000
# ---------------------------------------------------------------------------
Write-Step "Adding Windows Firewall rule (TCP 5000 inbound)"

$ruleName = "LocalScan-API"
$existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($existingRule) {
    Remove-NetFirewallRule -DisplayName $ruleName
}
New-NetFirewallRule -DisplayName $ruleName `
                    -Direction Inbound `
                    -Protocol TCP `
                    -LocalPort 5000 `
                    -Action Allow `
                    -Profile Any | Out-Null
Write-Ok "Firewall rule '$ruleName' created (TCP 5000 inbound)"

# ---------------------------------------------------------------------------
# 9. Launcher script
# ---------------------------------------------------------------------------
Write-Step "Creating launcher script"

$launcherPath = "$InstallDir\start_server.ps1"
$launcherContent = @"
# LocalScan server launcher
Set-Location '$InstallDir'
Start-Transcript -Path '$InstallDir\logs\server.log' -Append -NoClobber
Write-Host 'Starting LocalScan on http://localhost:5000 ...'
& '$PythonExe' app.py
"@
$launcherContent | Out-File -Encoding UTF8 -FilePath $launcherPath

Write-Ok "Launcher written to $launcherPath"

# ---------------------------------------------------------------------------
# 10. Scheduled Task (at login, hidden window)
# ---------------------------------------------------------------------------
Write-Step "Creating Scheduled Task 'LocalScan-Server'"

$taskName = "LocalScan-Server"
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NonInteractive -WindowStyle Hidden -File `"$launcherPath`"" `
    -WorkingDirectory $InstallDir

$trigger = New-ScheduledTaskTrigger -AtLogOn

$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit (New-TimeSpan -Hours 23) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $taskName `
                       -Action $action `
                       -Trigger $trigger `
                       -Settings $settings `
                       -RunLevel Highest `
                       -Force | Out-Null

Write-Ok "Scheduled Task created (runs at login, elevated)"

# ---------------------------------------------------------------------------
# 11. Desktop shortcut
# ---------------------------------------------------------------------------
Write-Step "Creating desktop shortcut"

$wsh      = New-Object -ComObject WScript.Shell
$shortcut = $wsh.CreateShortcut("$env:PUBLIC\Desktop\LocalScan.lnk")
$shortcut.TargetPath  = "http://localhost:5000"
$shortcut.Description = "LocalScan Malware Analysis Sandbox"
$shortcut.Save()
Write-Ok "Shortcut created on Public Desktop"

# ---------------------------------------------------------------------------
# 12. Start server now
# ---------------------------------------------------------------------------
Write-Step "Launching server in a new window"

Start-Process powershell.exe `
    -ArgumentList "-NoExit -File `"$launcherPath`"" `
    -WorkingDirectory $InstallDir

Start-Sleep -Seconds 3
Write-Ok "Server should be starting at http://localhost:5000"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "==========================================================" -ForegroundColor Magenta
Write-Host "  LocalScan setup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "  Web UI  : http://localhost:5000" -ForegroundColor White
Write-Host "  Install : $InstallDir" -ForegroundColor White
Write-Host "  Logs    : $InstallDir\logs\server.log" -ForegroundColor White
Write-Host "  Uploads : $InstallDir\uploads\" -ForegroundColor White
Write-Host "  Results : $InstallDir\results\" -ForegroundColor White
Write-Host ""
Write-Host "  REMINDER: Keep this VM isolated from production networks." -ForegroundColor Yellow
Write-Host "  Snapshot the VM now and restore after each analysis session." -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Magenta