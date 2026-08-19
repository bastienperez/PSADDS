<#
    .SYNOPSIS
    Get the computers joined to the domain by a non built-in administrator account

    .DESCRIPTION
    Get the list of computers joined to the domain by a regular user or by a delegated account.

    Two complementary attributes tell who created a computer object:

    - 'ms-DS-CreatorSID' is populated with the SID of the creator when a computer object is created by a regular user,
      typically through the default machine account quota ('ms-DS-MachineAccountQuota', 10 computers per user by default:
      https://support.microsoft.com/en-us/help/243327/default-limit-to-number-of-workstations-a-user-can-join-to-the-domain).
      The attribute is NOT set when the creator has Domain Admin permissions, or has been delegated the
      'Create Computer Objects' permission at the time the object was created.

    - the owner of the object (read from 'nTSecurityDescriptor') is set to the creator in almost every case. It is the
      only trace left for a computer created by a delegated account (typically a Tier 1 / Tier 2 account), which has an
      empty 'ms-DS-CreatorSID'. Computers created by a built-in administrator usually show a group (Domain Admins,
      BUILTIN\Administrators) as the owner rather than an account.

    Both the creator and the owner are returned as a name and as a SID ('CreatorName' / 'CreatorSID', 'OwnerName' /
    'OwnerSID'). The SID is read first and is always available, even when the account cannot be translated into a name
    (deleted object, unreachable trusted domain). Matching on the SID is also immune to the localization of the built-in
    group names ('Domain Admins' vs 'Admins du domaine').

    By default both attributes are returned, so nothing is missed.

    The output carries a 'DistinguishedName' alias property, so the results can be piped directly to
    Reset-ADComputerAccountSecurity to restore the default owner and permissions.

    .PARAMETER Identity
    Restrict the search to a single object. Accepts either:
    - a computer (sAMAccountName, name or distinguished name): returns the creator and the owner of that computer;
    - any other principal - user, gMSA, group (sAMAccountName, UPN, name or distinguished name): returns every computer
      this principal created, matching on 'ms-DS-CreatorSID' and/or on the owner depending on -SearchBy.
    The type of the object is resolved automatically. Wildcards are supported.
    Accepts pipeline input, by value or by property name ('DistinguishedName', 'SamAccountName', 'Name'), so the output
    of Get-ADUser, Get-ADGroupMember or Get-ADComputer can be piped directly. Duplicates are removed from the output.

    .PARAMETER SearchBy
    Which attribute is used to determine the creator:
    - 'All' (default): both, one column each. Nothing is filtered out.
    - 'CreatorSID': only the computers with a non-empty 'ms-DS-CreatorSID' (creations through the machine account quota).
    - 'Owner': only the owner is resolved, the creator columns are left empty. Covers the delegated creations.
    When an -Identity other than a computer is given, this also selects which attribute is matched against it.

    .PARAMETER SearchBase
    Distinguished name of the OU to search in. Defaults to the whole domain.

    .PARAMETER Server
    Domain controller or domain to query. Defaults to the one selected by the ActiveDirectory module.

    .EXAMPLE
    Get-ADComputerJoinedByUser

    Returns every computer object of the domain, with its creator and its owner.

    .EXAMPLE
    Get-ADComputerJoinedByUser -SearchBy CreatorSID

    Returns only the computers joined by regular users through the machine account quota. Fastest mode, the filter is
    applied server side and the security descriptors are not retrieved.

    .EXAMPLE
    Get-ADComputerJoinedByUser -SearchBy Owner

    Returns every computer with its owner only. Use it to spot the computers created by a delegated account
    (Tier 1 / Tier 2), which leave 'ms-DS-CreatorSID' empty.

    .EXAMPLE
    Get-ADComputerJoinedByUser -SearchBy CreatorSID | Group-Object CreatorName | Sort-Object Count -Descending

    Shows how many computers each user joined to the domain, which highlights the accounts getting close to the
    'ms-DS-MachineAccountQuota' limit (10 by default).

    .EXAMPLE
    Get-ADComputerJoinedByUser | Where-Object { $null -eq $_.CreatorSID }

    Returns the computers created by an administrator or by a delegated account: 'ms-DS-CreatorSID' is empty, only the
    owner tells who did it.

    .EXAMPLE
    $domainSID = (Get-ADDomain).DomainSID.Value
    Get-ADComputerJoinedByUser -SearchBy Owner | Where-Object { $_.OwnerSID.Value -notin @("$domainSID-512", 'S-1-5-32-544') }

    Returns the computers whose owner is neither Domain Admins (RID 512) nor BUILTIN\Administrators (S-1-5-32-544).
    Filtering on the SID rather than on 'OwnerName' avoids any dependency on the language of the domain.

    .EXAMPLE
    $domainSID = (Get-ADDomain).DomainSID.Value
    Get-ADComputerJoinedByUser -SearchBy Owner |
        Where-Object { $_.OwnerSID.Value -notin @("$domainSID-512", 'S-1-5-32-544') } |
        Reset-ADComputerAccountSecurity -Scope Owner -Simulation

    Chains the audit and the remediation: every computer still owned by its creator would get its owner reset to the
    Domain Admins group. Remove -Simulation to actually apply the change.

    .EXAMPLE
    Get-ADComputerJoinedByUser -Identity 'jdoe'

    Returns every computer created by the account 'jdoe', whether it was recorded in 'ms-DS-CreatorSID' or in the owner.

    .EXAMPLE
    Get-ADComputerJoinedByUser -Identity 'jdoe@contoso.com' -SearchBy Owner

    Same account resolved by its UPN, matching on the owner only.

    .EXAMPLE
    Get-ADComputerJoinedByUser -Identity 'Tier1-Deploy*'

    Returns every computer created by an account whose name starts with 'Tier1-Deploy'. Wildcards are supported.

    .EXAMPLE
    Get-ADComputerJoinedByUser -Identity 'WKS0042'

    Returns the creator and the owner of the computer 'WKS0042'. The trailing dollar sign of the computer
    sAMAccountName is optional.

    .EXAMPLE
    'jdoe', 'asmith' | Get-ADComputerJoinedByUser

    Returns the computers created by either account, in a single deduplicated output.

    .EXAMPLE
    Get-ADGroupMember -Identity 'Helpdesk' | Get-ADComputerJoinedByUser -SearchBy Owner

    Returns every computer owned by a member of the 'Helpdesk' group. The objects are bound on their
    'DistinguishedName' property.

    .EXAMPLE
    Get-ADComputer -Filter * -SearchBase 'OU=Workstations,DC=contoso,DC=com' | Get-ADComputerJoinedByUser

    Returns the creator and the owner of each computer of an OU, from an existing Get-ADComputer result.

    .EXAMPLE
    Get-ADComputerJoinedByUser -SearchBase 'OU=Workstations,DC=contoso,DC=com'

    Restricts the search to a single OU, which matters on a large directory since the security descriptor of every
    object has to be retrieved.

    .EXAMPLE
    Get-ADComputerJoinedByUser | Export-Csv -Path 'C:\temp\ComputersJoinedByUser.csv' -NoTypeInformation -Encoding UTF8 -Delimiter ';'

    Exports the full report.

    .OUTPUTS
    System.Management.Automation.PSCustomObject, one per computer object, emitted as they are found.
    If you have some tiering in your domain, you will find some computers created by accounts with tiering permissions,
    it's not a problem.

    .NOTES
    Version : 2.0 - August 2026
    Author : Bastien Perez - ITPro-Tips (https://itpro-tips.com)

    .LINK
    https://itpro-tips.com
#>

function Get-ADComputerJoinedByUser {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name')]
        [string]$Identity,

        [ValidateSet('All', 'CreatorSID', 'Owner')]
        [string]$SearchBy = 'All',

        [string]$SearchBase,

        [string]$Server
    )

    begin {
        # Common parameters forwarded to every ActiveDirectory cmdlet call
        $adParameters = @{ ErrorAction = 'Stop' }

        if ($PSBoundParameters.ContainsKey('Server')) {
            $adParameters.Add('Server', $Server)
        }

        # Keep track of the computers already returned, the same object can match several piped identities
        $processedComputersDN = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        # 'CreatorSID' is the only mode that can be filtered server side, the owner lives in the security descriptor
        if ($SearchBy -eq 'CreatorSID') {
            $baseLdapFilter = '(&(objectClass=computer)(mS-DS-CreatorSID=*))'
        }
        else {
            $baseLdapFilter = '(objectClass=computer)'
        }

        Write-Verbose "[i] Search computer objects (SearchBy: $SearchBy)"
    }

    process {
        $targetComputerDN = $null
        $targetPrincipalSID = $null

        # Resolve -Identity first: a computer narrows the LDAP query, any other principal filters the results afterwards
        if (-not [string]::IsNullOrWhiteSpace($Identity)) {

            # A computer sAMAccountName ends with a dollar sign, accept the name without it
            $identityFilter = '(|(sAMAccountName=' + $Identity + ')(sAMAccountName=' + $Identity + '$)(name=' + $Identity + ')(distinguishedName=' + $Identity + ')(userPrincipalName=' + $Identity + '))'

            $identityObject = $null

            try {
                $identityObject = Get-ADObject -LDAPFilter $identityFilter -Properties objectSid @adParameters
            }
            catch {
                Write-Warning "Unable to resolve the identity '$Identity': $($_.Exception.Message)"
                return
            }

            if (-not $identityObject) {
                Write-Warning "No object found for the identity '$Identity'"
                return
            }

            if ($identityObject.Count -gt 1) {
                $matchedNames = $identityObject.Name -join ', '
                Write-Warning "The identity '$Identity' matches several objects ($matchedNames), please be more specific"
                return
            }

            if ($identityObject.ObjectClass -eq 'computer') {
                $targetComputerDN = $identityObject.DistinguishedName
            }
            else {
                $targetPrincipalSID = $identityObject.objectSid
            }
        }

        $ldapFilter = $baseLdapFilter

        if ($targetComputerDN) {
            $ldapFilter = '(&' + $baseLdapFilter + '(distinguishedName=' + $targetComputerDN + '))'
        }

        $getADObjectParams = $adParameters.Clone()
        $getADObjectParams.LDAPFilter = $ldapFilter
        $getADObjectParams.Properties = 'ms-DS-CreatorSID', 'sAMAccountName', 'WhenCreated', 'WhenChanged', 'nTSecurityDescriptor'

        if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
            $getADObjectParams.SearchBase = $SearchBase
        }

        $computersFound = $null

        try {
            $computersFound = Get-ADObject @getADObjectParams
        }
        catch {
            Write-Warning "Unable to query the domain: $($_.Exception.Message)"
        }

        if (-not ($computersFound -and $computersFound.Count -gt 0)) {
            return
        }

        foreach ($computerFound in $computersFound) {

            $creatorSID = $null
            $creatorName = $null

            # Empty when the creator was an admin or had a delegated 'Create Computer Objects' permission
            if (($SearchBy -ne 'Owner') -and ($null -ne $computerFound.'ms-DS-CreatorSID')) {
                try {
                    $creatorSID = [System.Security.Principal.SecurityIdentifier]::new($computerFound.'ms-DS-CreatorSID', 0)
                    $creatorName = $creatorSID.Translate([System.Security.Principal.NTAccount]).Value
                }
                catch {
                    $creatorName = 'Unknown user (maybe user deleted from AD)'
                }
            }

            # The owner is the creator in almost every case, and is the only trace left for a delegated creation
            $ownerSID = $null
            $ownerName = $null

            if ($SearchBy -ne 'CreatorSID') {
                $owner = Resolve-ADObjectOwner -SecurityDescriptor $computerFound.nTSecurityDescriptor

                if ($null -ne $owner) {
                    $ownerSID = $owner.OwnerSID
                    $ownerName = $owner.OwnerName
                }
            }

            # An identity that is not a computer filters on the creator and/or on the owner, both matched on their SID
            if ($targetPrincipalSID) {
                $matchCreator = ($null -ne $creatorSID) -and ($creatorSID.Value -eq $targetPrincipalSID.Value)
                $matchOwner = ($null -ne $ownerSID) -and ($ownerSID.Value -eq $targetPrincipalSID.Value)

                if (-not ($matchCreator -or $matchOwner)) {
                    continue
                }
            }

            if (-not $processedComputersDN.Add($computerFound.DistinguishedName)) {
                continue
            }

            $whenCreated = $null

            if ($null -ne $computerFound.WhenCreated) {
                $whenCreated = $computerFound.WhenCreated.ToString('yyyyMMdd-HH:mm:ss')
            }

            $whenChanged = $null

            if ($null -ne $computerFound.WhenChanged) {
                $whenChanged = $computerFound.WhenChanged.ToString('yyyyMMdd-HH:mm:ss')
            }

            $computerInfo = [PSCustomObject][ordered]@{
                ComputerName   = $computerFound.Name
                ComputerDN     = $computerFound.DistinguishedName
                SamAccountName = $computerFound.sAMAccountName
                CreatorName    = $creatorName
                CreatorSID     = $creatorSID
                OwnerName      = $ownerName
                OwnerSID       = $ownerSID
                WhenCreated    = $whenCreated
                WhenChanged    = $whenChanged
            }

            # Alias so the result can be piped straight into Reset-ADComputerAccountSecurity, which binds on
            # 'SamAccountName' or, when it is empty, on 'DistinguishedName'
            $computerInfo | Add-Member -MemberType AliasProperty -Name 'DistinguishedName' -Value 'ComputerDN'

            $computerInfo
        }
    }
}
