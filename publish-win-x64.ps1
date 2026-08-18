$ErrorActionPreference = 'Stop'
Push-Location (Join-Path $PSScriptRoot 'src')
try {
    dotnet restore
    dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o (Join-Path $PSScriptRoot 'publish')
    Copy-Item (Join-Path $PSScriptRoot 'install-service.ps1') (Join-Path $PSScriptRoot 'publish') -Force
    Copy-Item (Join-Path $PSScriptRoot 'uninstall-service.ps1') (Join-Path $PSScriptRoot 'publish') -Force
} finally { Pop-Location }
