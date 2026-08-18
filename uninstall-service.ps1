# Run as Administrator.
$ServiceName = 'RdpGuard'
Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue
sc.exe delete $ServiceName
