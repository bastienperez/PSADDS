<#
    .SYNOPSIS
    Get the replication metadata of an Active Directory object: which attribute changed, when, and on which
    domain controller.

    .DESCRIPTION
    Reads the msDS-ReplAttributeMetaData constructed attribute, which the domain controller builds on the fly
    and which records, for every attribute of the object, the version number, the date of the last originating
    change and the domain controller where that change was made.

    This is the only reliable way to answer "when was this account disabled, and by which DC was the change
    written", long after whenChanged has been overwritten by another modification.

    The metadata is local to the domain controller answering the query. Two DCs can report different values
    for the same object, which is exactly what makes -Server useful when investigating a replication problem.

    Linked attributes are out of scope: 'member', 'manager', 'managedBy' and the like are replicated as linked
    values, so their history lives in msDS-ReplValueMetaData and never shows up here. Group membership is read
    with Get-ADGroupMembershipMetadata. 'memberOf' carries no metadata at all, being a back-link computed from
    the 'member' attribute of the groups.

    Requires the ActiveDirectory module (RSAT).

    .PARAMETER Identity
    The distinguished name of the object. Any other form (sAMAccountName, common name, display name) is
    accepted as a fallback: the object is then searched with an ambiguous name resolution (anr) filter, which
    must match exactly one object.

    .PARAMETER Attributes
    Restricts the output to these attribute names. An attribute the object carries no metadata for is reported
    with a warning rather than as an empty row.

    .PARAMETER Server
    Domain controller to query. Defaults to a discovered DC of the current domain.

    .PARAMETER OnlyAttributesWithRecentChanges
    Keeps only the attributes whose last originating change is more recent than -Days.

    .PARAMETER Days
    Number of days used by -OnlyAttributesWithRecentChanges. Default is 10.

    .PARAMETER OnlyUpdatedAttributes
    Keeps only the attributes whose version is greater than 1, that is, the attributes modified at least once
    since the object was created.

    .EXAMPLE
    Get-ADObjectMetadata 'CN=John Doe,OU=Users,DC=example,DC=com'

    Every attribute of the object, with the date and origin of its last change.

    .EXAMPLE
    Get-ADObjectMetadata jdoe -Attributes userAccountControl, pwdLastSet

    Resolves jdoe with an anr search, then reports when the account state and the password were last changed.

    .EXAMPLE
    Get-ADObjectMetadata 'CN=John Doe,OU=Users,DC=example,DC=com' -OnlyAttributesWithRecentChanges -Days 5

    What changed on the object over the last five days.

    .EXAMPLE
    Get-ADObjectMetadata 'CN=Domain Admins,CN=Users,DC=example,DC=com' -Server 'dc02.example.com' -OnlyUpdatedAttributes

    The attributes modified at least once, as dc02 knows them. Comparing the output with another DC shows what
    has not replicated yet.

    .LINK
    https://github.com/bastienperez/PSADDS
#>
function Get-ADObjectMetadata {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias('ObjectDN', 'DistinguishedName')]
        [string]$Identity,

        [Parameter(Mandatory = $false, Position = 1)]
        [string[]]$Attributes,

        [Parameter(Mandatory = $false)]
        [Alias('DomainController')]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [switch]$OnlyAttributesWithRecentChanges,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Days = 10,

        [Parameter(Mandatory = $false)]
        [switch]$OnlyUpdatedAttributes
    )

    if (-not $Server) {
        $Server = (Get-ADDomainController -Discover -Service ADWS).HostName
        Write-Verbose "No domain controller specified, using the discovered one: $Server"
    }

    [System.Collections.Generic.List[PSObject]]$objectMetadata = @()

    try {
        $adObject = Get-ADObject -Identity $Identity -Properties 'msDS-ReplAttributeMetaData' -Server $Server -ErrorAction Stop
    }
    catch {
        Write-Verbose "'$Identity' is not a distinguished name, searching the object with (anr=$Identity)"

        try {
            $adObject = @(Get-ADObject -LDAPFilter "(anr=$Identity)" -Properties 'msDS-ReplAttributeMetaData' -Server $Server -ErrorAction Stop)
        }
        catch {
            Write-Warning "Unable to search '$Identity' with (anr=$Identity): $($_.Exception.Message)"
            return
        }

        if ($adObject.Count -gt 1) {
            Write-Warning "Several objects match (anr=$Identity), use the exact distinguished name: $($adObject.DistinguishedName -join ', ')"
            return
        }

        if (-not $adObject) {
            Write-Warning "No object found for '$Identity', neither as a distinguished name nor with (anr=$Identity)"
            return
        }

        $adObject = $adObject[0]
        Write-Verbose "Object found: $($adObject.DistinguishedName)"
    }

    $replAttributeMetaData = ConvertFrom-ADReplMetadata -RawMetadata $adObject.'msDS-ReplAttributeMetaData'

    if (-not $replAttributeMetaData) {
        Write-Warning "No replication metadata returned by $Server for $($adObject.DistinguishedName)"
        return
    }

    # linked attributes never appear in msDS-ReplAttributeMetaData, so an empty result on one of them means
    # "look at the linked value metadata", not "the attribute is not set"
    $linkedAttributes = 'member', 'memberOf', 'manager', 'directReports', 'managedBy', 'managedObjects', 'msDS-ManagedBy', 'msDS-ManagedByObjects', 'msDS-NC-RO-Replica-Locations', 'siteObject', 'siteObjectBL'

    if ($Attributes) {
        $selectedMetadata = foreach ($attribute in $Attributes) {
            $attributeMetadata = $replAttributeMetaData | Where-Object { $_.pszAttributeName -eq $attribute }

            if (-not $attributeMetadata) {
                if ($attribute -eq 'member') {
                    Write-Warning "'member' is a linked attribute: its history is carried by msDS-ReplValueMetaData, not by msDS-ReplAttributeMetaData. Use Get-ADGroupMembershipMetadata '$($adObject.DistinguishedName)' instead."
                }
                elseif ($attribute -eq 'memberOf') {
                    Write-Warning "'memberOf' is a back-link, computed from the 'member' attribute of the groups, and carries no metadata of its own. The history of a membership belongs to the group: Get-ADGroupMembershipMetadata <group DN>."
                }
                elseif ($attribute -in $linkedAttributes) {
                    Write-Warning "'$attribute' is a linked attribute: its history is carried by msDS-ReplValueMetaData, which this function does not read."
                }
                else {
                    Write-Warning "No metadata for the attribute '$attribute' on $($adObject.DistinguishedName): the attribute is either not set or does not exist"
                }

                continue
            }

            $attributeMetadata
        }
    }
    else {
        $selectedMetadata = $replAttributeMetaData
    }

    foreach ($metadata in $selectedMetadata) {
        $object = [PSCustomObject][ordered]@{
            ObjectDN                  = $adObject.DistinguishedName
            AttributeName             = $metadata.pszAttributeName
            Version                   = [int]$metadata.dwVersion
            TimeLastOriginatingChange = ConvertTo-ADReplMetadataDate -Timestamp $metadata.ftimeLastOriginatingChange
            usnOriginatingChange      = $metadata.usnOriginatingChange
            usnLocalChange            = $metadata.usnLocalChange
            LastOriginatingDsaDN      = $metadata.pszLastOriginatingDsaDN
            FromDomainController      = $Server
        }

        $objectMetadata.Add($object)
    }

    $result = $objectMetadata

    if ($OnlyAttributesWithRecentChanges.IsPresent) {
        $limit = (Get-Date).ToUniversalTime().AddDays(-$Days)
        $result = $result | Where-Object { $null -ne $_.TimeLastOriginatingChange -and $_.TimeLastOriginatingChange -gt $limit }
    }

    if ($OnlyUpdatedAttributes.IsPresent) {
        $result = $result | Where-Object { $_.Version -gt 1 }
    }

    return $result
}
