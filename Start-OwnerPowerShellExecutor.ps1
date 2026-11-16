#requires -Version 5.1
<#
Explicitly opt-in dedicated Windows PowerShell executor for authenticated
Fortis Owner Portal. This exposes arbitrary commands under this Windows user.
DO NOT run elevated or expose without TLS mutual authentication and firewall review.
The ordinary Script Center launcher supplies no machine options; machine ASK is disabled by default.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Bind,
    [Parameter(Mandatory=$true)][ValidateRange(1024,65535)][int]$Port,
    [Parameter(Mandatory=$true)][string]$ServerCert,
    [Parameter(Mandatory=$true)][string]$ServerKey,
    [Parameter(Mandatory=$true)][string]$ClientCA,
    [Parameter(Mandatory=$true)][string]$SecretFile,
    [Parameter(Mandatory=$true)][string]$ReceiptDb,
    [Parameter()][string]$MachineBearerFile,
    [Parameter()][string]$MachineProofFile,
    [Parameter()][string]$MachineActor,
    [Parameter()][string]$MachineTarget
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($env:OS -ne 'Windows_NT') { throw 'WINDOWS_REQUIRED' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'OWNER_SHELL_REQUIRES_NON_ADMIN_USER'
}
foreach ($path in @($ServerCert,$ServerKey,$ClientCA,$SecretFile)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "OWNER_SHELL_FILE_MISSING: $path" }
}
if (Test-Path -LiteralPath $ReceiptDb -PathType Container) { throw 'OWNER_SHELL_RECEIPT_PATH_INVALID' }
# Opt-in machine credentials are distinct from the owner-only secret. The
# existing Script Center launcher supplies NONE of these four optional flags;
# its installed owner-only behaviour is unchanged.
$machineValues = @($MachineBearerFile,$MachineProofFile,$MachineActor,$MachineTarget)
$machineSelected = @($machineValues | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
if ($machineSelected.Count -gt 0 -and $machineSelected.Count -ne 4) {
    throw 'MACHINE_SHELL_OPT_IN_INCOMPLETE'
}
$machineArgs = @()
if ($machineSelected.Count -eq 4) {
    if ($MachineActor -cnotmatch '^[a-z][a-z0-9-]{0,63}$' -or
        $MachineTarget -cnotmatch '^[a-z][a-z0-9-]{0,63}$') {
        throw 'MACHINE_SHELL_ACTOR_TARGET_INVALID'
    }
    $expectedRoot = [IO.Path]::GetFullPath(
        (Join-Path $env:LOCALAPPDATA 'Fortis\OwnerShell')
    ).TrimEnd('')
    $secretPaths = @($MachineBearerFile,$MachineProofFile)
    $normalized = @($SecretFile) + $secretPaths
    $fullPaths = @($normalized | ForEach-Object {
        [IO.Path]::GetFullPath($_)
    })
    if (@($fullPaths | Sort-Object -Unique).Count -ne 3) {
        throw 'MACHINE_SHELL_SECRET_PATH_REUSE_DENIED'
    }
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowedSids = @($currentSid,'S-1-5-18','S-1-5-32-544')
    foreach ($file in $secretPaths) {
        $path = [IO.Path]::GetFullPath($file)
        if (-not $path.StartsWith($expectedRoot + '',
                [StringComparison]::OrdinalIgnoreCase)) {
            throw 'MACHINE_SHELL_SECRET_OUTSIDE_PROTECTED_ROOT'
        }
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'MACHINE_SHELL_SECRET_PATH_INVALID'
        }
        $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
        foreach ($rule in $acl.Access) {
            if ($rule.AccessControlType -ne 'Allow') { continue }
            $sid = $rule.IdentityReference.Translate(
                [Security.Principal.SecurityIdentifier]).Value
            if ($sid -notin $allowedSids) {
                throw 'MACHINE_SHELL_SECRET_ACL_TOO_BROAD'
            }
        }
    }
    $machineArgs = @('--machine-bearer-file',$MachineBearerFile,
        '--machine-proof-file',$MachineProofFile,
        '--machine-actor',$MachineActor,'--machine-target',$MachineTarget)
}
$source = Split-Path -Parent $MyInvocation.MyCommand.Path
$py = (Get-Command py.exe -CommandType Application -ErrorAction Stop).Source
Push-Location -LiteralPath $source
try {
    & $py -3 -m fortis_powershell_executor.owner_shell --bind $Bind --port ([string]$Port) `
        --cert $ServerCert --key $ServerKey --client-ca $ClientCA `
        --secret-file $SecretFile --receipt-db $ReceiptDb @machineArgs
    if ($LASTEXITCODE -ne 0) { throw 'OWNER_SHELL_EXIT_FAILED' }
}
finally { Pop-Location }
