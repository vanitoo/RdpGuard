$taskname="BlockRDPBruteForce_Attack_PS"
$scriptPath="C:\PS\block_rdp_attack.ps1"
$triggers = @()
$triggers += New-ScheduledTaskTrigger -AtLogOn
$CIMTriggerClass = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler:MSFT_TaskEventTrigger
$trigger = New-CimInstance -CimClass $CIMTriggerClass -ClientOnly
$trigger.Subscription =
@"
<QueryList><Query Id="0" Path="Security"><Select Path="Security">*[System[(EventID=4625)]]</Select></Query></QueryList>
"@
$trigger.Enabled = $True
$triggers += $trigger
$User='Nt Authority\System'
$Action=New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File $scriptPath"
Register-ScheduledTask -TaskName $taskname -Trigger $triggers -User $User -Action $Action -RunLevel Highest -Force