<#
    .SYNOPSIS
    Get the replication metadata of the membership of an Active Directory group: when each member was added,
    when it was removed, and on which domain controller.

    .DESCRIPTION
    Group membership is a linked value, so its history is not carried by msDS-ReplAttributeMetaData but by
    msDS-ReplValueMetaData, which holds one entry per value of the link, including the values that were
    removed. That makes it the only way to answer "who was added to this group last week, and who was removed
    from it" without a security event log.

    Removed members remain visible until the tombstone lifetime of the forest has elapsed, 180 days by default
    on a forest created in Windows Server 2003 SP1 or later.

    The metadata is local to the domain controller answering the query, hence -Server.

    Requires the ActiveDirectory module (RSAT).

    .PARAMETER Identity
    The distinguished name of the group. Accepts pipeline input by property name, so Get-ADGroup can be piped
    into this function.

    .PARAMETER Server
    Domain controller to query. Defaults to a discovered DC of the current domain.

    .PARAMETER DeletedOnly
    Keeps only the members that were removed from the group.

    .PARAMETER CurrentOnly
    Keeps only the members currently in the group.

    .EXAMPLE
    Get-ADGroupMembershipMetadata 'CN=Domain Admins,CN=Users,DC=example,DC=com'

    The whole membership history of the group, current and removed members alike.

    .EXAMPLE
    Get-ADGroupMembershipMetadata 'CN=Domain Admins,CN=Users,DC=example,DC=com' -DeletedOnly

    Who was removed from Domain Admins, and when.

    .EXAMPLE
    Get-ADGroup -Filter 'adminCount -eq 1' | Get-ADGroupMembershipMetadata | Where-Object { $_.TimeCreated -gt (Get-Date).AddDays(-30) }

    Every addition to a privileged group over the last thirty days.

    .LINK
    https://github.com/bastienperez/PSADDS
#>
function Get-ADGroupMembershipMetadata {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Alias('GroupDN', 'DistinguishedName')]
        [string]$Identity,

        [Parameter(Mandatory = $false)]
        [Alias('DomainController')]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [switch]$DeletedOnly,

        [Parameter(Mandatory = $false)]
        [switch]$CurrentOnly
    )

    begin {
        if ($DeletedOnly.IsPresent -and $CurrentOnly.IsPresent) {
            throw 'The -DeletedOnly and -CurrentOnly parameters are mutually exclusive.'
        }

        if (-not $Server) {
            $Server = (Get-ADDomainController -Discover -Service ADWS).HostName
            Write-Verbose "No domain controller specified, using the discovered one: $Server"
        }
    }

    process {
        try {
            $group = Get-ADObject -Identity $Identity -Properties 'msDS-ReplValueMetaData' -Server $Server -ErrorAction Stop
        }
        catch {
            Write-Warning "Unable to read the group '$Identity': $($_.Exception.Message)"
            return
        }

        $replValueMetaData = ConvertFrom-ADReplMetadata -RawMetadata $group.'msDS-ReplValueMetaData'

        if (-not $replValueMetaData) {
            Write-Warning "No linked value metadata returned by $Server for $($group.DistinguishedName): the group never had a member, or its links predate the metadata"
            return
        }

        foreach ($metadata in $replValueMetaData) {
            # msDS-ReplValueMetaData covers every linked attribute of the object, keep the membership only
            if ($metadata.pszAttributeName -and $metadata.pszAttributeName -ne 'member') {
                continue
            }

            $timeDeleted = ConvertTo-ADReplMetadataDate -Timestamp $metadata.ftimeDeleted

            if ($DeletedOnly.IsPresent -and $null -eq $timeDeleted) {
                continue
            }

            if ($CurrentOnly.IsPresent -and $null -ne $timeDeleted) {
                continue
            }

            [PSCustomObject][ordered]@{
                GroupDN                   = $group.DistinguishedName
                MemberDN                  = $metadata.pszObjectDn
                IsDeleted                 = ($null -ne $timeDeleted)
                TimeCreated               = ConvertTo-ADReplMetadataDate -Timestamp $metadata.ftimeCreated
                TimeDeleted               = $timeDeleted
                Version                   = [int]$metadata.dwVersion
                TimeLastOriginatingChange = ConvertTo-ADReplMetadataDate -Timestamp $metadata.ftimeLastOriginatingChange
                LastOriginatingDsaDN      = $metadata.pszLastOriginatingDsaDN
                FromDomainController      = $Server
            }
        }
    }
}
