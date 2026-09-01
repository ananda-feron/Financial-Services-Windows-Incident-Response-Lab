[CmdletBinding(DefaultParameterSetName = 'Local')]
param(
    [Parameter(ParameterSetName = 'Csv', Mandatory = $true)]
    [ValidateScript({ Test-Path $_ -PathType Leaf })]
    [string]$CsvPath,
    [Parameter(ParameterSetName = 'Local')]
    [ValidateRange(1, 168)]
    [int]$Hours = 24,
    [ValidateRange(2, 20)]
    [int]$FailureThreshold = 3
)

$ErrorActionPreference = 'Stop'
$start = (Get-Date).AddHours(-$Hours)

if ($PSCmdlet.ParameterSetName -eq 'Csv') {
    $events = Import-Csv -Path $CsvPath
} else {
    $security = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4624, 4625, 4672; StartTime = $start } |
        ForEach-Object { [pscustomobject]@{ TimeCreated = $_.TimeCreated; EventId = $_.Id; Channel = $_.LogName; Message = $_.Message } }
    $sysmon = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 1; StartTime = $start } |
        ForEach-Object { [pscustomobject]@{ TimeCreated = $_.TimeCreated; EventId = $_.Id; Channel = $_.LogName; Message = $_.Message } }
    $events = @($security) + @($sysmon)
}

$failed = @($events | Where-Object { [int]$_.EventId -eq 4625 })
$powershell = @($events | Where-Object { [int]$_.EventId -eq 1 -and $_.Message -match '(?i)(powershell|pwsh)\.exe' })
$suspicious = @($powershell | Where-Object {
    $_.Message -match '(?i)(-enc|-encodedcommand|-nop|bypass|invoke-expression|downloadstring)' -or
    $_.Message -match '(?i)ParentImage:.*(winword|excel|outlook|wscript|mshta)\.exe'
})

[pscustomobject]@{
    WindowStart = $start
    EventsReviewed = @($events).Count
    FailedLogons = $failed.Count
    FailureThresholdExceeded = ($failed.Count -ge $FailureThreshold)
    PowerShellProcesses = $powershell.Count
    SuspiciousPowerShellProcesses = $suspicious.Count
    RequiresEscalation = (($failed.Count -ge $FailureThreshold) -and ($suspicious.Count -gt 0))
} | Format-List

if ($suspicious.Count -gt 0) {
    $suspicious | Select-Object TimeCreated, EventId, Channel, Message | Format-List
}
