<#
    .SYNOPSIS
    Get the computers of the domain whose creator or owner is not one of the expected administrative groups.

    .DESCRIPTION
    Returns only the non compliant computers: those created or owned by anyone other than 'Domain Admins' or
    'BUILTIN\Administrators'. A computer owned by one of those two groups is not returned, whatever its creator,
    since the owner is what actually grants control over the object today.

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
    group names ('Domain Admins' vs 'Admins du domaine'), which is also what the compliance check itself relies on.

    By default both attributes are returned, so nothing is missed.

    The output carries a 'DistinguishedName' alias property, so the results can be piped directly to
    Reset-ADComputerAccountSecurity to restore the default owner and permissions.

    .PARAMETER Identity
    Restrict the search to a single object. Accepts either:
    - a computer (sAMAccountName, name or distinguished name): returns the creator and the owner of that computer,
      and only that computer, but the compliance filter still applies: a compliant computer produces no output;
    - any other principal - user, gMSA, group (sAMAccountName, UPN, name or distinguished name): returns every non
      compliant computer this principal created, matching on 'ms-DS-CreatorSID' and/or on the owner depending on
      -SearchBy.
    The type of the object is resolved automatically. Wildcards are supported.
    Accepts pipeline input, by value or by property name ('DistinguishedName', 'SamAccountName', 'Name'), so the output
    of Get-ADUser, Get-ADGroupMember or Get-ADComputer can be piped directly. Duplicates are removed from the output.

    .PARAMETER SearchBy
    Which attribute is used to determine the creator, and against which the compliance check runs:
    - 'All' (default): both are resolved and returned, filtered on the owner.
    - 'CreatorSID': only the computers with a non-empty 'ms-DS-CreatorSID' (creations through the machine account
      quota). The LDAP filter itself already excludes the compliant ones, since this attribute is never set for a
      creator with Domain Admin permissions: fastest mode, the security descriptor is not even retrieved.
    - 'Owner': only the owner is resolved and used for the filter, the creator columns are left empty. Covers the
      delegated creations, which 'CreatorSID' cannot see.

    .PARAMETER SearchBase
    Distinguished name of the OU to search in. Defaults to the whole domain.

    .PARAMETER Server
    Domain controller or domain to query. Defaults to the one selected by the ActiveDirectory module.

    .EXAMPLE
    Get-ADComputerJoinedByUser

    Returns every computer of the domain whose creator or owner is not 'Domain Admins' or 'BUILTIN\Administrators'.

    .EXAMPLE
    Get-ADComputerJoinedByUser -SearchBy CreatorSID

    Returns only the computers joined by regular users through the machine account quota. Fastest mode, the filter is
    applied server side and the security descriptors are not retrieved.

    .EXAMPLE
    Get-ADComputerJoinedByUser -SearchBy Owner

    Returns the non compliant computers with their owner only. Use it to spot the computers created by a delegated
    account (Tier 1 / Tier 2), which leave 'ms-DS-CreatorSID' empty.

    .EXAMPLE
    Get-ADComputerJoinedByUser -SearchBy CreatorSID | Group-Object CreatorName | Sort-Object Count -Descending

    Shows how many computers each user joined to the domain, which highlights the accounts getting close to the
    'ms-DS-MachineAccountQuota' limit (10 by default).

    .EXAMPLE
    Get-ADComputerJoinedByUser | Where-Object { $null -eq $_.CreatorSID }

    Among the non compliant computers, returns those created by a delegated account rather than through the machine
    account quota: 'ms-DS-CreatorSID' is empty, only the owner tells who did it.

    .EXAMPLE
    Get-ADComputerJoinedByUser -SearchBy Owner | Reset-ADComputerAccountSecurity -Scope Owner -Simulation

    Chains the audit and the remediation: every non compliant computer would get its owner reset to the Domain
    Admins group. Remove -Simulation to actually apply the change.

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

    Returns the creator and the owner of the computer 'WKS0042', but only if it is not compliant: the filter applies
    here too. The trailing dollar sign of the computer sAMAccountName is optional.

    .EXAMPLE
    'jdoe', 'asmith' | Get-ADComputerJoinedByUser

    Returns the computers created by either account, in a single deduplicated output.

    .EXAMPLE
    Get-ADGroupMember -Identity 'Helpdesk' | Get-ADComputerJoinedByUser -SearchBy Owner

    Returns every computer owned by a member of the 'Helpdesk' group. The objects are bound on their
    'DistinguishedName' property.

    .EXAMPLE
    Get-ADComputer -Filter * -SearchBase 'OU=Workstations,DC=contoso,DC=com' | Get-ADComputerJoinedByUser

    Returns the non compliant computers of an OU, from an existing Get-ADComputer result.

    .EXAMPLE
    Get-ADComputerJoinedByUser -SearchBase 'OU=Workstations,DC=contoso,DC=com'

    Restricts the search to a single OU, which matters on a large directory since the security descriptor of every
    object has to be retrieved.

    .EXAMPLE
    Get-ADComputerJoinedByUser | Export-Csv -Path 'C:\temp\ComputersJoinedByUser.csv' -NoTypeInformation -Encoding UTF8 -Delimiter ';'

    Exports the non compliance report.

    .OUTPUTS
    System.Management.Automation.PSCustomObject, one per non compliant computer object, emitted as they are found.
    If you have some tiering in your domain, the accounts with tiering permissions will show up here as the creator
    or the owner of the computers they provisioned: it is not a bug, they are not 'Domain Admins' or
    'BUILTIN\Administrators', which is exactly the point of a tiered delegation.

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

        # 'CreatorSID' is the only mode that can be filtered server side, the owner lives in the security descriptor.
        # It is also already restricted to the non compliant computers: 'ms-DS-CreatorSID' is never set for a
        # creator with Domain Admin permissions, so every match here is by definition not one of the compliant owners.
        if ($SearchBy -eq 'CreatorSID') {
            $baseLdapFilter = '(&(objectClass=computer)(mS-DS-CreatorSID=*))'
        }
        else {
            $baseLdapFilter = '(objectClass=computer)'

            # The compliance check itself: a computer owned by one of those two groups is not returned.
            try {
                $domainAdminsSID = "$((Get-ADDomain @adParameters).DomainSID.Value)-512"
            }
            catch {
                throw "Unable to resolve the domain SID, required to identify 'Domain Admins': $($_.Exception.Message)"
            }

            $compliantOwnerSIDs = [System.Collections.Generic.HashSet[string]]::new(
                [string[]]@($domainAdminsSID, 'S-1-5-32-544'),
                [System.StringComparer]::OrdinalIgnoreCase
            )
        }

        Write-Verbose "[i] Search non compliant computer objects (SearchBy: $SearchBy)"
    }

    process {
        $targetComputerDN = $null
        $targetPrincipalSID = $null

        # Resolve -Identity first: a computer narrows the LDAP query, any other principal filters the results afterwards
        if (-not [string]::IsNullOrWhiteSpace($Identity)) {

            # A computer sAMAccountName ends with a dollar sign, accept the name without it
            $identityFilter = '(|(sAMAccountName=' + $Identity + ')(sAMAccountName=' + $Identity + '$)(name=' + $Identity + ')(distinguishedName=' + $Identity + ')(userPrincipalName=' + $Identity + '))'

            # The result has to be wrapped in an array: an ADObject implements IDictionary, so 'Count' on a
            # single object returns its number of properties, not 1
            $identityObjects = @()

            try {
                $identityObjects = @(Get-ADObject -LDAPFilter $identityFilter -Properties objectSid @adParameters)
            }
            catch {
                Write-Warning "Unable to resolve the identity '$Identity': $($_.Exception.Message)"
                return
            }

            if ($identityObjects.Count -eq 0) {
                Write-Warning "No object found for the identity '$Identity'"
                return
            }

            if ($identityObjects.Count -gt 1) {
                $matchedNames = ($identityObjects.Name | Sort-Object) -join ', '
                Write-Warning "The identity '$Identity' matches several objects ($matchedNames), please be more specific"
                return
            }

            $identityObject = $identityObjects[0]

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

        # Same as above, the result is wrapped so that a single computer is not mistaken for a collection
        $computersFound = @()

        try {
            $computersFound = @(Get-ADObject @getADObjectParams)
        }
        catch {
            Write-Warning "Unable to query the domain: $($_.Exception.Message)"
        }

        if ($computersFound.Count -eq 0) {
            Write-Verbose "No computer object matched the search"
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

                # The compliance check: a computer owned by 'Domain Admins' or 'BUILTIN\Administrators' is not
                # returned, whatever its creator. Applies uniformly, including when -Identity names one computer.
                if (($null -ne $ownerSID) -and $compliantOwnerSIDs.Contains($ownerSID.Value)) {
                    continue
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
