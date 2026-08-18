<#
====================================================================
 RDP BRUTEFORCE PROTECTION SERVICE (Fail2Ban-like for Windows)
====================================================================

 НАЗНАЧЕНИЕ
 -------------------------------------------------------------------
 Данный PowerShell-скрипт предназначен для защиты Windows-сервера
 от атак перебора паролей (bruteforce) по протоколу RDP.

 Скрипт анализирует журнал безопасности Windows (Security Event Log),
 отслеживает неудачные попытки входа по RDP и автоматически блокирует
 IP-адреса злоумышленников с помощью Windows Firewall.

 Реализована логика, аналогичная fail2ban в Linux, но адаптированная
 под Windows-среду.

 -------------------------------------------------------------------

 КАК ЭТО РАБОТАЕТ
 -------------------------------------------------------------------
 1. Скрипт периодически анализирует события:
    - LogName: Security
    - Event ID: 4625 (Logon Failure)
    - LogonType: 10 (Remote Desktop / RDP)

 2. Для каждого IP-адреса анализируется:
    - количество неудачных попыток входа
    - временной интервал между попытками (скорость атаки)

 3. Используется "adaptive threshold":
    - чем быстрее идут попытки, тем меньше их нужно для блокировки
    - медленные или редкие ошибки входа не приводят к блокировке

 4. При обнаружении атаки:
    - IP-адрес добавляется в правило Windows Firewall
    - информация записывается в лог
    - IP сохраняется в state-файл для контроля времени блокировки

 5. Реализована автоматическая разблокировка:
    - IP удаляется из firewall по истечении заданного срока
    - защита от вечных блокировок

 -------------------------------------------------------------------

 ОСНОВНЫЕ ВОЗМОЖНОСТИ
 -------------------------------------------------------------------
 ✔ Adaptive threshold (реакция на скорость атак)
 ✔ Автоматическая блокировка IP
 ✔ Автоматическая разблокировка по таймеру
 ✔ Поддержка trusted IP / подсетей
 ✔ Dry-run режим (без реальных блокировок)
 ✔ Работа в режиме Windows Service
 ✔ Готово к Email / Telegram уведомлениям
 ✔ Надёжная работа без парсинга текста сообщений

 -------------------------------------------------------------------

 ТРЕБОВАНИЯ
 -------------------------------------------------------------------
 - Windows Server 2012 R2 и выше
 - Права администратора
 - Включён аудит неудачных входов (Security Log)
 - PowerShell 5.1+

 -------------------------------------------------------------------

 УСТАНОВКА
 -------------------------------------------------------------------

 1. Создать директорию:
    C:\ps

 2. Сохранить файл скрипта:
    C:\ps\rdp_block_service.ps1

 3. (Рекомендуется) Включить DryRun для тестирования:
    $DryRun = $true

 4. Проверить лог:
    C:\ps\rdp_block.log

 5. После проверки отключить DryRun:
    $DryRun = $false

 -------------------------------------------------------------------

 УСТАНОВКА КАК WINDOWS SERVICE (РЕКОМЕНДУЕТСЯ)
 -------------------------------------------------------------------

 Для стабильной круглосуточной работы рекомендуется запускать скрипт
 как Windows Service с использованием NSSM (Non-Sucking Service Manager).

 1. Скачать NSSM:
    https://nssm.cc/download

 2. Установить сервис:
    nssm install RDPBlocker

    Path:        powershell.exe
    Arguments:   -ExecutionPolicy Bypass -File C:\ps\rdp_block_service.ps1
    Startup dir: C:\ps

 3. Запустить сервис:
    nssm start RDPBlocker

 -------------------------------------------------------------------

 ЛОГИ И СОСТОЯНИЕ
 -------------------------------------------------------------------
 - Лог работы:
   C:\ps\rdp_block.log

 - Файл состояния (заблокированные IP и время блокировки):
   C:\ps\rdp_block_state.json

 -------------------------------------------------------------------

 ВНИМАНИЕ
 -------------------------------------------------------------------
 - Перед включением убедись, что твой IP добавлен в TrustedIPs
 - Рекомендуется сначала использовать DryRun режим
 - Изменение firewall-правил требует прав администратора

 -------------------------------------------------------------------

 АВТОР / ПОДДЕРЖКА
 -------------------------------------------------------------------
 Скрипт разработан как fail2ban-подобное решение для Windows.
 Предназначен для системных администраторов и DevOps инженеров.

====================================================================
#>

<# ===================== CONFIG ===================== #>
$DebugMode = $false

# Режим работы
$DryRun = $true            # true = только лог, без блокировок
$RunAsService = $true       # true = бесконечный цикл (для сервиса)

# Интервалы
$LoopDelaySeconds = 60      # проверка каждую минуту
$LookbackMinutes = 10       # анализ логов за X минут

# Adaptive threshold
$FastAttackAttempts = 3
$FastAttackSeconds = 30

$MediumAttackAttempts = 5
$MediumAttackMinutes = 5

$HardLimitAttempts = 10

# Авторазблокировка
$UnblockAfterDays = 3

# Firewall
$RdpLocalPort = 33389
$RuleMaxEntries = 3000

# Пути
$BaseDir   = "C:\ps"
$LogFile   = "$BaseDir\rdp_block.log"
$StateFile = "$BaseDir\rdp_block_state.json"

# Trusted IP / CIDR
$TrustedIPs = @(
    "127.0.0.1",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "213.79.104.231"
)

# Уведомления
$EnableEmailNotifications    = $false
$EnableTelegramNotifications = $false

# ===================== INIT =====================

if (-not (Test-Path $BaseDir)) {
    New-Item -ItemType Directory -Path $BaseDir | Out-Null
}


function Log($msg) {
    "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | $msg" >> $LogFile
}

function Debug($msg) {
    if ($DebugMode) {
        Log "DEBUG | $msg"
    }
}


# ===================== STATE =====================

# Загрузка состояния
$BlockedState = @{}

if (Test-Path $StateFile) {
    try {
        $Json = Get-Content $StateFile -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

        if ($Json) {
            $Json.PSObject.Properties | ForEach-Object {

                $Key = [string]$_.Name
                $Value = [string]$_.Value

                if (-not [string]::IsNullOrWhiteSpace($Key)) {
                    $BlockedState[$Key] = $Value
                }
            }
        }

        Debug "State loaded | Entries=$($BlockedState.Count)"
    }
    catch {
        Log "ERROR | State load failed: $($_.Exception.Message)"
        $BlockedState = @{}
    }
}

function Save-State {
    try {
        $BlockedState |
            ConvertTo-Json -Depth 5 |
            Set-Content -Path $StateFile -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        Log "ERROR | State save failed: $($_.Exception.Message)"
    }
}


# ===================== FIREWALL =====================

function Get-OrCreateRule {
    param($Index)

    $Name = "BlockRDPBruteForce_$Index"
    $Rule = Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue

    if (-not $Rule) {
        New-NetFirewallRule `
            -DisplayName $Name `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort $RdpLocalPort `
            -Action Block `
            -RemoteAddress "0.0.0.0"
    }

    Get-NetFirewallRule -DisplayName $Name
}

function Add-IpToFirewall($Ip) {
    if ($DryRun) {
        Log "DRY-RUN | BLOCK | $Ip"
        return
    }

    $Index = 1
    do {
        $Rule = Get-OrCreateRule $Index
		$AddrFilter = $Rule | Get-NetFirewallAddressFilter
		$List = @()
		if ($AddrFilter -and $AddrFilter.RemoteAddress) {
			$List = @($AddrFilter.RemoteAddress)
		}
		Debug "Firewall rule $($Rule.DisplayName) entries=$($List.Count)"
		
        $Index++
    } while ($List.Count -ge $RuleMaxEntries)

    $List += $Ip
    Set-NetFirewallRule -DisplayName $Rule.DisplayName -RemoteAddress $List
    Log "BLOCK | $Ip"
}

function Remove-IpFromFirewall($Ip) {
    if ($DryRun) {
        Log "DRY-RUN | UNBLOCK | $Ip"
        return
    }

    Get-NetFirewallRule -DisplayName "BlockRDPBruteForce_*" |
    ForEach-Object {
        $List = @($_ | Get-NetFirewallAddressFilter | Select-Object -Expand RemoteAddress)
        if ($List -contains $Ip) {
            $New = $List | Where-Object { $_ -ne $Ip }
            Set-NetFirewallRule -DisplayName $_.DisplayName -RemoteAddress $New
        }
    }

    Log "UNBLOCK | $Ip"
}

# ===================== ANALYSIS =====================

function Get-RdpFailures {

    $Minutes = [int]$LookbackMinutes
    $StartTime = [DateTime]::Now.AddMinutes(-1 * $Minutes)

    Log "DEBUG | LookbackMinutes=[$LookbackMinutes] Type=$($LookbackMinutes.GetType().FullName)"
    Log "DEBUG | StartTime=[$StartTime] Type=$($StartTime.GetType().FullName)"

    $Filter = @{
        LogName = 'Security'
        Id      = 4625
    }

    $Filter.StartTime = $StartTime

    try {
        $WinEvents = @(
            Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop
        )
    }
    catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
            Debug "No 4625 events during last $LookbackMinutes minutes"
            return @()
        }

        Log "ERROR | Get-WinEvent failed: $($_.Exception.Message)"
        Log "ERROR | StartTime=[$StartTime]"
        Log "ERROR | StartTimeType=$($StartTime.GetType().FullName)"
        Log "ERROR | LookbackMinutes=[$LookbackMinutes]"
        return @()
    }

    $Result = @()

    foreach ($Event in $WinEvents) {

        try {
            $Xml = [xml]$Event.ToXml()
            $Data = @{}

            foreach ($d in $Xml.Event.EventData.Data) {

                $Name = [string]$d.Name

                if (-not [string]::IsNullOrWhiteSpace($Name)) {
                    $Data[$Name] = [string]$d.'#text'
                }
            }

            if ($Data['LogonType'] -ne '10') {
                continue
            }

            $Ip = [string]$Data['IpAddress']

            if (
                [string]::IsNullOrWhiteSpace($Ip) -or
                $Ip -eq '-' -or
                $Ip -eq '::1'
            ) {
                continue
            }

            $Result += [PSCustomObject]@{
                Ip   = $Ip
                Time = $Event.TimeCreated
            }
        }
        catch {
            Log "ERROR | XML parse failed | RecordId=$($Event.RecordId) | $($_.Exception.Message)"
        }
    }

    return $Result
}


function Is-TrustedIp($Ip) {
    return [bool]($TrustedIPs | Where-Object { $Ip -like $_ })
}

function Detect-Attackers($Events) {
    foreach ($Group in ($Events | Group-Object Ip)) {

 		$Count = $Group.Count

		# Если только 1 событие — пропускаем
		if ($Count -lt 2) { continue }

		$Times = $Group.Group | Select-Object -Expand Time
		$Span  = $Times | Measure-Object -Maximum -Minimum

		# Защита от NULL
		if (-not $Span.Maximum -or -not $Span.Minimum) { continue }

		$Delta = $Span.Maximum - $Span.Minimum


        if (
            ($Count -ge $FastAttackAttempts   -and $Delta.TotalSeconds -lt $FastAttackSeconds) -or
            ($Count -ge $MediumAttackAttempts -and $Delta.TotalMinutes -lt $MediumAttackMinutes) -or
            ($Count -ge $HardLimitAttempts)
        ) {
            $Group.Name
        }
    }
}

# ===================== LOOP =====================

function Main-Loop {

    while ($true) {

        try {
            $Events = Get-RdpFailures
            $Attackers = Detect-Attackers $Events

            foreach ($Ip in $Attackers) {

                if (Is-TrustedIp $Ip) { continue }
                if ($BlockedState.ContainsKey($Ip)) { continue }

                Add-IpToFirewall $Ip
                $BlockedState[$Ip] = (Get-Date).ToString("s")
            }

            # Авторазблокировка
            foreach ($Ip in @($BlockedState.Keys)) {
                $BlockedAt = [DateTime]$BlockedState[$Ip]
                if ((Get-Date) - $BlockedAt -gt (New-TimeSpan -Days $UnblockAfterDays)) {
                    Remove-IpFromFirewall $Ip
                    $BlockedState.Remove($Ip)
                }
            }

            Save-State
        }
        catch {
            Log "ERROR | Message=$($_.Exception.Message)"
            Log "ERROR | Line=$($_.InvocationInfo.ScriptLineNumber)"
            Log "ERROR | Code=$($_.InvocationInfo.Line.Trim())"
            Log "ERROR | Position=$($_.InvocationInfo.PositionMessage)"
        }

        Start-Sleep -Seconds $LoopDelaySeconds
    }
}

# ===================== START =====================

Log "SERVICE STARTED"

if ($RunAsService) {
    Main-Loop
}
