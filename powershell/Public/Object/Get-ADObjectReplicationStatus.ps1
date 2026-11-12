<#
    .SYNOPSIS
    Shows, for every domain controller, whether an Active Directory object is present, when it was created and
    how long its last change took to reach that domain controller.

    .DESCRIPTION
    Resolves the object once, then queries each domain controller by objectGUID so that the same object is
    compared everywhere, even if it was renamed or moved in the meantime.

    For every domain controller the function reports:
    - whether the object is present (a missing object is reported as 'Missing', not as an error)
    - WhenCreatedUTC, the originating creation time, identical on every DC
    - uSNCreated, the local USN of the object on that DC (it differs per DC)
    - WhenChangedOnDCUTC (whenChanged), which is NOT replicated: each DC stamps it with the time the change was applied locally
    - the latest originating change time and the originating DC, read from msDS-ReplAttributeMetaData
    - ReplicationDelay, whenChanged on that DC minus the latest originating change time

    ReplicationDelay is the propagation delay of the most recent change of the object. For an object that was
    never modified after its creation, it is the creation replication delay. Once the object is modified again,
    the value describes that later change instead: AD stores no per-DC arrival time for the creation itself.
    The delay is also skewed by any clock difference between DCs, and it is empty on the originating DC.

    Requires the ActiveDirectory module (RSAT).

    .PARAMETER Identity
    The distinguished name of the object. Any other form (sAMAccountName, common name, display name) is
    accepted as a fallback: the object is then searched with an ambiguous name resolution (anr) filter, which
    must match exactly one object.

    .PARAMETER Server
    Domain controller used to resolve the object. Defaults to a discovered DC of the current domain.

    .PARAMETER DomainController
    Restricts the comparison to these domain controllers. Defaults to every domain controller of the domain
    of the resolving server.

    .EXAMPLE
    Get-ADObjectReplicationStatus jdoe

    One row per domain controller: presence, creation date and replication delay of the last change.

    .EXAMPLE
    Get-ADObjectReplicationStatus 'CN=John Doe,OU=Users,DC=example,DC=com' | Where-Object Status -ne 'Present'

    The domain controllers that do not have the object yet (or cannot be reached).

    .EXAMPLE
    Get-ADObjectReplicationStatus 'newserver01$' -DomainController dc01, dc02 | Format-Table -AutoSize

    Compares two domain controllers only.

    .LINK
    https://github.com/bastienperez/PSADDS
#>
function Get-ADObjectReplicationStatus {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [Alias('ObjectDN', 'DistinguishedName')]
        [string]$Identity,

        [Parameter(Mandatory = $false)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [string[]]$DomainController
    )

    if (-not $Server) {
        $Server = (Get-ADDomainController -Discover -Service ADWS).HostName
        Write-Verbose "No domain controller specified, using the discovered one: $Server"
    }

    $properties = 'whenCreated', 'whenChanged', 'uSNCreated', 'uSNChanged', 'objectGUID', 'msDS-ReplAttributeMetaData'

    # resolve the object once on the reference server
    try {
        $referenceObject = Get-ADObject -Identity $Identity -Properties $properties -Server $Server -ErrorAction Stop
    }
    catch {
        Write-Verbose "'$Identity' is not a distinguished name, searching the object with (anr=$Identity)"

        try {
            $referenceObject = @(Get-ADObject -LDAPFilter "(anr=$Identity)" -Properties $properties -Server $Server -ErrorAction Stop)
        }
        catch {
            Write-Warning "Unable to search '$Identity' with (anr=$Identity): $($_.Exception.Message)"
            return
        }

        if ($referenceObject.Count -gt 1) {
            Write-Warning "Several objects match (anr=$Identity), use the exact distinguished name: $($referenceObject.DistinguishedName -join ', ')"
            return
        }

        if (-not $referenceObject) {
            Write-Warning "No object found for '$Identity', neither as a distinguished name nor with (anr=$Identity)"
            return
        }

        $referenceObject = $referenceObject[0]
    }

    $objectGuid = $referenceObject.ObjectGUID
    Write-Verbose "Object resolved: $($referenceObject.DistinguishedName) ($objectGuid)"

    # domain controllers to compare
    try {
        if ($DomainController) {
            $domainControllers = foreach ($name in $DomainController) {
                Get-ADDomainController -Identity $name -Server $Server -ErrorAction Stop
            }
        }
        else {
            $domainControllers = Get-ADDomainController -Filter * -Server $Server -ErrorAction Stop
        }
    }
    catch {
        Write-Warning "Unable to list the domain controllers from ${Server}: $($_.Exception.Message)"
        return
    }

    [System.Collections.Generic.List[PSObject]]$results = @()

    foreach ($dc in $domainControllers) {
        $status = 'Present'
        $adObject = $null
        $errorMessage = $null

        try {
            $adObject = Get-ADObject -Identity $objectGuid -Properties $properties -Server $dc.HostName -ErrorAction Stop
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            $status = 'Missing'
        }
        catch {
            $status = 'Unreachable'
            $errorMessage = $_.Exception.Message
            Write-Verbose "Unable to query $($dc.HostName): $errorMessage"
        }

        $whenCreated = $null
        $whenChangedLocal = $null
        $usnCreated = $null
        $latestOriginatingChange = $null
        $originatingDc = $null
        $replicationDelay = $null

        if ($adObject) {
            $whenCreated = $adObject.whenCreated.ToUniversalTime()
            $whenChangedLocal = $adObject.whenChanged.ToUniversalTime()
            $usnCreated = $adObject.uSNCreated

            $metadata = @(ConvertFrom-ADReplMetadata -RawMetadata $adObject.'msDS-ReplAttributeMetaData')

            # whenChanged is a local stamp: compare it with the most recent originating change of the object
            $latest = $metadata |
                Where-Object { $null -ne (ConvertTo-ADReplMetadataDate -Timestamp $_.ftimeLastOriginatingChange) } |
                Sort-Object -Property { ConvertTo-ADReplMetadataDate -Timestamp $_.ftimeLastOriginatingChange } -Descending |
                Select-Object -First 1

            if ($latest) {
                $latestOriginatingChange = ConvertTo-ADReplMetadataDate -Timestamp $latest.ftimeLastOriginatingChange

                # CN=NTDS Settings,CN=<server>,CN=Servers,... : the server name is the second RDN
                if ($latest.pszLastOriginatingDsaDN -match '^CN=NTDS Settings,CN=([^,]+),') {
                    $originatingDc = $Matches[1]
                }
                else {
                    $originatingDc = $latest.pszLastOriginatingDsaDN
                }

                if ($originatingDc -and $dc.Name -ne $originatingDc -and $whenChangedLocal) {
                    $replicationDelay = $whenChangedLocal - $latestOriginatingChange
                }
            }
        }

        $object = [PSCustomObject][ordered]@{
            DomainController = $dc.HostName
            Site = $dc.Site
            Status = $status
            WhenCreatedUTC = $whenCreated
            USNCreatedLocal = $usnCreated
            WhenChangedOnDCUTC = $whenChangedLocal
            LatestOriginatingChangeUTC = $latestOriginatingChange
            OriginatingDC = $originatingDc
            ReplicationDelay = $replicationDelay
            ObjectDN = if ($adObject) { $adObject.DistinguishedName } else { $referenceObject.DistinguishedName }
            Error = $errorMessage
        }

        $results.Add($object)
    }

    return $results
}
