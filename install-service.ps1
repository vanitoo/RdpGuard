# Run as Administrator from the published folder.
$ErrorActionPreference = 'Stop'
$ServiceName = 'RdpGuard'
$Exe = Join-Path $PSScriptRoot 'RdpGuard.exe'
if (-not (Test-Path $Exe)) { throw "RdpGuard.exe not found in $PSScriptRoot. Publish/copy the application first." }

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

sc.exe create $ServiceName binPath= ('"' + $Exe + '"') start= auto obj= LocalSystem DisplayName= "RDP Guard" | Out-Host
sc.exe description $ServiceName "Blocks RDP brute-force IP addresses based on Security Event ID 4625 / LogonType 10." | Out-Host
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Host
Start-Service $ServiceName
Get-Service $ServiceName
