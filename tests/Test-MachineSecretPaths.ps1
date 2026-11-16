#requires -Version 5.1
# Windows CI negative / positive checks on throwaway files only.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$sourceRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
. (Join-Path $sourceRoot 'scripts\Assert-MachineSecretPaths.ps1')

function Assert-Denied {
    param([string]$Expected,[scriptblock]$Action)
    $observed = ''
    try {
        & $Action | Out-Null
    } catch {
        $observed = $_.Exception.Message
    }
    if ($observed -cne $Expected) {
        throw "MACHINE_SECRET_GUARD_TEST_FAILED expected=$Expected actual=$observed"
    }
}
function Set-OwnerOnlyTestAcl {
    param([string]$Path,[bool]$Directory)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($rule in @($acl.Access)) {
        [void]$acl.RemoveAccessRuleSpecific($rule)
    }
    $inherited = if ($Directory) {
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
    } else {
        [Security.AccessControl.InheritanceFlags]::None
    }
    $newRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $sid, [Security.AccessControl.FileSystemRights]::FullControl,
        $inherited, [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($newRule)
    $acl.SetOwner($sid)
    Set-Acl -LiteralPath $Path -AclObject $acl
}
$fixture = Join-Path ([IO.Path]::GetTempPath()) (
    'fortis-machine-secret-guard-' + [guid]::NewGuid().ToString('N'))
$root = Join-Path $fixture 'OwnerShell'
$outside = $root + '-not-OwnerShell'
$nested = Join-Path $root 'nested'
$bearer = Join-Path $root 'bearer'
$proof = Join-Path $root 'proof-key'
$original = Join-Path $fixture 'legacy-bearer'
try {
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    New-Item -ItemType Directory -Path $outside -Force | Out-Null
    New-Item -ItemType Directory -Path $nested -Force | Out-Null
    foreach ($file in @($bearer,$proof,$original)) {
        [IO.File]::WriteAllText($file,'synthetic-no-secret')
    }
    $good = Assert-FortisMachineSecretPathContainment -Root $root -File $bearer
    if ($good -cne [IO.Path]::GetFullPath($bearer)) {
        throw 'MACHINE_SECRET_GUARD_VALID_PATH_CHANGED'
    }

    Assert-Denied 'MACHINE_SHELL_SECRET_OUTSIDE_PROTECTED_ROOT' {
        Assert-FortisMachineSecretPathContainment -Root $root -File (
            Join-Path $outside 'proof-key')
    }
    Assert-Denied 'MACHINE_SHELL_SECRET_OUTSIDE_PROTECTED_ROOT' {
        Assert-FortisMachineSecretPathContainment -Root $root -File (
            Join-Path $nested 'proof-key')
    }
    Assert-Denied 'MACHINE_SHELL_SECRET_OUTSIDE_PROTECTED_ROOT' {
        Assert-FortisMachineSecretPathContainment -Root $root -File (
            Join-Path $root '..\OwnerShell-not-OwnerShell\proof-key')
    }

    Set-OwnerOnlyTestAcl -Path $root -Directory $true
    Set-OwnerOnlyTestAcl -Path $bearer -Directory $false
    Set-OwnerOnlyTestAcl -Path $proof -Directory $false
    Assert-FortisMachineSecretFiles -OwnerShellRoot $root -OwnerSecret $original -MachineBearer $bearer -MachineProof $proof

    Assert-Denied 'MACHINE_SHELL_SECRET_PATH_REUSE_DENIED' {
        Assert-FortisMachineSecretFiles -OwnerShellRoot $root -OwnerSecret $original -MachineBearer $bearer -MachineProof $bearer
    }

    $acl = Get-Acl -LiteralPath $proof
    $users = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
    $broad = [Security.AccessControl.FileSystemAccessRule]::new(
        $users,[Security.AccessControl.FileSystemRights]::Read,
        [Security.AccessControl.AccessControlType]::Allow)
    $acl.AddAccessRule($broad)
    Set-Acl -LiteralPath $proof -AclObject $acl
    Assert-Denied 'MACHINE_SHELL_SECRET_ACL_TOO_BROAD' {
        Assert-FortisMachineSecretFiles -OwnerShellRoot $root -OwnerSecret $original -MachineBearer $bearer -MachineProof $proof
    }
    Write-Host 'MACHINE_SECRET_PATH_ACL_GUARD_WINDOWS_PASS'
} finally {
    if (Test-Path -LiteralPath $fixture) {
        Remove-Item -LiteralPath $fixture -Recurse -Force
    }
}
