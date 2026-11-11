$ErrorActionPreference = "Stop"

$Repo = "https://github.com/mobadawyx4/SubReconX.git"
$InstallDir = if ($env:SUBRECONX_HOME) { $env:SUBRECONX_HOME } else { Join-Path $env:LOCALAPPDATA "SubReconX" }
$BinDir = Join-Path $env:LOCALAPPDATA "Programs\SubReconX"
$Venv = Join-Path $InstallDir ".venv"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "Git for Windows is required."
}

$Python = Get-Command py -ErrorAction SilentlyContinue
if ($Python) {
    $PyCmd = "py"
    $PyArgs = @("-3")
} else {
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        throw "Python 3.10+ is required."
    }
    $PyCmd = "python"
    $PyArgs = @()
}

& $PyCmd @PyArgs -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"
if ($LASTEXITCODE -ne 0) { throw "Python 3.10+ is required." }

if (Test-Path (Join-Path $InstallDir ".git")) {
    git -C $InstallDir pull --ff-only
    if ($LASTEXITCODE -ne 0) { throw "Git update failed." }
} else {
    if (Test-Path $InstallDir) { throw "Install directory already exists and is not a Git repository." }
    New-Item -ItemType Directory -Force -Path (Split-Path $InstallDir) | Out-Null
    git clone --depth 1 $Repo $InstallDir
    if ($LASTEXITCODE -ne 0) { throw "Git clone failed." }
}

if (-not (Test-Path (Join-Path $Venv "Scripts\python.exe"))) {
    & $PyCmd @PyArgs -m venv $Venv
    if ($LASTEXITCODE -ne 0) { throw "Virtual environment creation failed." }
}

& (Join-Path $Venv "Scripts\python.exe") -m pip install --no-deps $InstallDir
if ($LASTEXITCODE -ne 0) { throw "Installation failed." }

New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$Launcher = Join-Path $BinDir "subreconx.cmd"
Set-Content -Encoding ASCII -Path $Launcher -Value "@echo off`r`n`"$Venv\Scripts\subreconx.exe`" %*"

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$Entries = @($UserPath -split ";" | Where-Object { $_ })
if ($Entries -notcontains $BinDir) {
    [Environment]::SetEnvironmentVariable("Path", (($Entries + $BinDir) -join ";"), "User")
}

Write-Host "SubReconX installed. Open a new PowerShell window."
Write-Host "Run: subreconx --help"
