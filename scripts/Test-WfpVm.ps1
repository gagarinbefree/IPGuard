<#
.SYNOPSIS
Runs explicitly enabled WFP object tests only inside a designated disposable Windows VM.
.DESCRIPTION
The confirmations attest isolation and an existing host checkpoint. This script cannot verify them from inside the guest.
#>
[CmdletBinding()]
param(
    [switch]$ConfirmIsolatedVm,
    [switch]$ConfirmSnapshot,
    [string]$MachineName,
    [string]$SnapshotName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $ConfirmIsolatedVm -or -not $ConfirmSnapshot) {
    throw 'Supply -ConfirmIsolatedVm and -ConfirmSnapshot only inside the designated disposable VM.'
}
if ([string]::IsNullOrWhiteSpace($MachineName) -or $MachineName -ine [Environment]::MachineName) {
    throw 'MachineName must explicitly match this VM.'
}
if ([string]::IsNullOrWhiteSpace($SnapshotName)) {
    throw 'SnapshotName must identify an existing restore checkpoint.'
}
if ($null -ne [Environment]::GetEnvironmentVariable('GITHUB_ACTIONS') -or $null -ne [Environment]::GetEnvironmentVariable('CI')) {
    throw 'Mutating WFP VM tests cannot run in CI.'
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT -or -not [Environment]::Is64BitProcess) {
    throw 'Use a Windows x64 PowerShell process inside the VM.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Use an elevated administrator terminal inside the VM. The script does not request elevation.'
    }
} finally {
    $identity.Dispose()
}

$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$project = Join-Path $repository 'tests\IntegrationTests\IntegrationTests.csproj'
if (-not (Test-Path -LiteralPath (Join-Path $repository 'IPGuard.slnx'))) {
    throw 'Run the original script from the source repository.'
}
$dotnet = (Get-Command dotnet -CommandType Application -ErrorAction Stop).Source
$runName = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N')
$results = Join-Path $repository ('artifacts\wfp-vm\' + $runName)
New-Item -ItemType Directory -Path $results -ErrorAction Stop | Out-Null
@{
    machine = [Environment]::MachineName
    snapshot = $SnapshotName
    startedUtc = [DateTimeOffset]::UtcNow.ToString('O')
    scope = 'Object lifecycle only; traffic enforcement is not tested.'
} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $results 'run.json') -Encoding UTF8

$settings = @{
    IPGUARD_WFP_VM_ENABLE = '1'
    IPGUARD_WFP_VM_CONFIRMATION = 'I_CONFIRM_THIS_IS_AN_ISOLATED_VM'
    IPGUARD_WFP_VM_MACHINE = $MachineName
    IPGUARD_WFP_VM_SNAPSHOT = $SnapshotName
    IPGUARD_WFP_VM_RESULTS = $results
}
$previous = @{}
foreach ($name in $settings.Keys) {
    $previous[$name] = [Environment]::GetEnvironmentVariable($name)
}

Push-Location -LiteralPath $repository
try {
    & $dotnet restore $project --locked-mode
    if ($LASTEXITCODE -ne 0) {
        throw 'Restore failed before enabling VM tests.'
    }

    foreach ($name in $settings.Keys) {
        [Environment]::SetEnvironmentVariable($name, $settings[$name], [EnvironmentVariableTarget]::Process)
    }
    & $dotnet test $project --configuration Release --no-restore --filter 'Category=WfpVm' --logger 'trx;LogFileName=wfp-vm.trx' --results-directory $results
    if ($LASTEXITCODE -ne 0) {
        throw 'VM tests failed. Export the evidence and restore the VM checkpoint before another run.'
    }

    $report = Join-Path $results 'wfp-vm.trx'
    if (-not (Test-Path -LiteralPath $report)) {
        throw 'The VM test report is missing; no successful run can be claimed.'
    }
    [xml]$trx = Get-Content -LiteralPath $report -Raw
    $testResults = @($trx.SelectNodes("//*[local-name()='UnitTestResult']"))
    if ($testResults.Count -eq 0 -or @($testResults | Where-Object { $_.outcome -ne 'Passed' }).Count -gt 0) {
        throw 'VM tests were skipped, failed, or not discovered. The run is not a successful VM validation.'
    }
    Write-Output "Object lifecycle passed. Evidence: $results"
    Write-Output 'This result does not prove traffic enforcement, boot protection, or crash recovery.'
} finally {
    foreach ($name in $previous.Keys) {
        [Environment]::SetEnvironmentVariable($name, $previous[$name], [EnvironmentVariableTarget]::Process)
    }
    Pop-Location
}
