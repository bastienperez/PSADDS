<#
    .SYNOPSIS
    Reads the owner of an Active Directory security descriptor, as a SID and as an account name.

    .DESCRIPTION
    The SID is read first and is always available, even when the account cannot be translated into a name
    (deleted object, unreachable trusted domain). Matching on the SID is also immune to the localization of
    the built-in group names ('Domain Admins' vs 'Admins du domaine').

    Internal helper shared by the computer account functions, so that the owner is read and reported the
    same way whether the object is audited or remediated.

    .PARAMETER SecurityDescriptor
    The 'nTSecurityDescriptor' property of an AD object, as returned by Get-ADObject or Get-ADComputer.

    .OUTPUTS
    System.Management.Automation.PSCustomObject with the OwnerSID and OwnerName properties.
    Returns $null when no security descriptor is given.
#>
function Resolve-ADObjectOwner {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Position = 0)]
        [System.DirectoryServices.ActiveDirectorySecurity]$SecurityDescriptor
    )

    if ($null -eq $SecurityDescriptor) {
        return $null
    }

    $ownerSID = $SecurityDescriptor.GetOwner([System.Security.Principal.SecurityIdentifier])
    $ownerName = $null

    if ($null -ne $ownerSID) {
        try {
            $ownerName = $ownerSID.Translate([System.Security.Principal.NTAccount]).Value
        }
        catch {
            $ownerName = 'Unresolved owner (deleted object or unreachable domain)'
            Write-Verbose "Unable to translate the owner SID '$($ownerSID.Value)' into an account name"
        }
    }

    return [PSCustomObject][ordered]@{
        OwnerSID  = $ownerSID
        OwnerName = $ownerName
    }
}
