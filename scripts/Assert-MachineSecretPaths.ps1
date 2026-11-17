#requires -Version 5.1
# Only dot-sourced by the exact-SHA Fortis owner launcher on Windows.
# No secret content is read or printed by these preflight functions.
Set-StrictMode -Version Latest

function Assert-FortisMachineSecretPathContainment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Root,
        [Parameter(Mandatory=$true)][string]$File
    )
    $expected = [IO.Path]::GetFullPath($Root).TrimEnd([char[]]@('\', '/'))
    $actual = [IO.Path]::GetFullPath($File)
    $parent = [IO.Path]::GetDirectoryName($actual)
    if (-not [string]::Equals(
            $parent, $expected, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'MACHINE_SHELL_SECRET_OUTSIDE_PROTECTED_ROOT'
    }
    return $actual
}

function Assert-FortisMachinePrivateAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string[]]$AllowedSids
    )
    $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    $owner = $acl.GetOwner(
        [Security.Principal.SecurityIdentifier]).Value
    if (-not $acl.AreAccessRulesProtected -or
            $AllowedSids -cnotcontains $owner) {
        throw 'MACHINE_SHELL_SECRET_ACL_TOO_BROAD'
    }
    $rules = $acl.GetAccessRules(
        $true,$true,[Security.Principal.SecurityIdentifier])
    foreach ($rule in $rules) {
        if ($rule.AccessControlType -eq 'Allow' -and
                $AllowedSids -cnotcontains $rule.IdentityReference.Value) {
            throw 'MACHINE_SHELL_SECRET_ACL_TOO_BROAD'
        }
    }
}

function Assert-FortisMachineSecretFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$OwnerShellRoot,
        [Parameter(Mandatory=$true)][string]$OwnerSecret,
        [Parameter(Mandatory=$true)][string]$MachineBearer,
        [Parameter(Mandatory=$true)][string]$MachineProof
    )
    if ($env:OS -cne 'Windows_NT') {
        throw 'MACHINE_SHELL_WINDOWS_REQUIRED'
    }
    $root = [IO.Path]::GetFullPath($OwnerShellRoot).TrimEnd([char[]]@('\', '/'))
    $ownerPath = [IO.Path]::GetFullPath($OwnerSecret)
    $bearerPath = Assert-FortisMachineSecretPathContainment -Root $root -File $MachineBearer
    $proofPath = Assert-FortisMachineSecretPathContainment -Root $root -File $MachineProof
    if ($ownerPath -ieq $bearerPath -or $ownerPath -ieq $proofPath -or
            $bearerPath -ieq $proofPath) {
        throw 'MACHINE_SHELL_SECRET_PATH_REUSE_DENIED'
    }
    $dir = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not ($dir -is [IO.DirectoryInfo]) -or
            ($dir.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'MACHINE_SHELL_PROTECTED_ROOT_INVALID'
    }
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $allowedSids = @($sid,'S-1-5-18','S-1-5-32-544')
    Assert-FortisMachinePrivateAcl -Path $root -AllowedSids $allowedSids
    foreach ($file in @($bearerPath,$proofPath)) {
        $item = Get-Item -LiteralPath $file -Force -ErrorAction Stop
        if (-not ($item -is [IO.FileInfo]) -or
                ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'MACHINE_SHELL_SECRET_PATH_INVALID'
        }
        Assert-FortisMachinePrivateAcl -Path $file -AllowedSids $allowedSids
    }
}
