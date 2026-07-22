# Install the ClaudeBridge Add-In for RobotStudio (DEVELOPER copy-install).
# Run with:  powershell -ExecutionPolicy Bypass -File install-addin.ps1
#
# End users should prefer the .rspak package instead (see build-rspak.ps1 /
# README): RobotStudio -> Add-Ins tab -> Install Package. No admin needed.
#
# RobotStudio scans %ProgramFiles(x86)%\Common Files\ABB\RobotStudio\Addins for
# .rsaddin files at startup (version-independent, all-users). Writing there needs
# administrator, so this script self-elevates. A third-party (General) add-in with
# autoLoad="true" is enabled + auto-started automatically on the next RobotStudio
# launch -- no manual "Load Add-in" step required.
#
# PRECEDENCE TRAP (measured on RobotStudio 2025): an installed distribution
# package under %LocalAppData%\ABB\DistributionPackages2 is scanned BEFORE the
# Common Files add-in folder, and RobotStudio loads only the FIRST add-in with a
# given ApplicationId. If a ClaudeBridge .rspak package is installed, it SHADOWS
# the copy this script deploys -- your freshly built DLL would never load. The
# check below warns about that.

param([switch]$Elevated)

$pkgShadow = Get-ChildItem "$env:LOCALAPPDATA\ABB\DistributionPackages2" -Directory -Filter 'Fohdeesha.ClaudeBridge-*' -ErrorAction SilentlyContinue
if ($pkgShadow) {
    Write-Host "WARNING: installed ClaudeBridge distribution package(s) found:" -ForegroundColor Yellow
    $pkgShadow | ForEach-Object { Write-Host "  $($_.FullName)" -ForegroundColor Yellow }
    Write-Host "These load BEFORE the copy this script installs (same ApplicationId =>" -ForegroundColor Yellow
    Write-Host "only the package copy loads). Uninstall the package from RobotStudio's" -ForegroundColor Yellow
    Write-Host "Add-Ins tab (or delete the folder above) for this dev copy to take effect." -ForegroundColor Yellow
}

$dll     = Join-Path $PSScriptRoot 'addin\bin\ClaudeBridge.dll'
$rsaddin = Join-Path $PSScriptRoot 'addin\ClaudeBridge.rsaddin'
$dest    = Join-Path ${env:ProgramFiles(x86)} 'Common Files\ABB\RobotStudio\Addins\ClaudeBridge'

if (-not (Test-Path $dll)) {
    Write-Host "ERROR: $dll not found. Build the add-in first:" -ForegroundColor Red
    Write-Host '  msbuild addin\ClaudeBridge.csproj /restore /p:Configuration=Release'
    exit 1
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Elevating to write the RobotStudio add-in folder (approve the UAC prompt)..."
    Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`"",'-Elevated'
} else {
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Copy-Item $dll     $dest -Force
    Copy-Item $rsaddin $dest -Force
    Write-Host "ClaudeBridge Add-In installed to: $dest"
}

if (-not $Elevated) {
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "1. Restart RobotStudio - the add-in auto-loads and starts an HTTP server on localhost:58080"
    Write-Host "2. Restart your MCP client (e.g. Claude Code) so the rs_*/rws_* tools attach"
    Write-Host ""
    Write-Host "Test: curl http://localhost:58080/ping"
}
