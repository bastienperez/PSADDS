<#
    .SYNOPSIS
    Return the Active Directory schema version of the forest, and the Windows Server release it corresponds to.

    .DESCRIPTION
    Reads the 'objectVersion' attribute of the schema partition and maps it to the Windows Server release that
    introduced it.

    The version tells you the highest release whose schema extensions have been applied to the forest. It says
    nothing about the operating system of the domain controllers, nor about the functional levels. A forest can run
    on Windows Server 2025 domain controllers with a schema still at 88, if adprep was never run for 2025.

    Reference: https://learn.microsoft.com/troubleshoot/windows-server/identity/find-current-schema-version

    Both the number and its meaning are returned. An unknown number is reported as such and kept in the output,
    rather than collapsed into the string 'Unknown', so a schema newer than this table can still be identified.

    .PARAMETER Server
    Domain controller or domain to query. Defaults to the one selected by the ActiveDirectory module.

    .EXAMPLE
    Get-ADSchemaVersion

    Returns the schema version of the current forest.

    .EXAMPLE
    (Get-ADSchemaVersion).ObjectVersion -ge 88

    Tests whether the schema has at least the Windows Server 2019 extensions, for instance before deploying
    something that depends on them.

    .OUTPUTS
    System.Management.Automation.PSCustomObject with ObjectVersion, WindowsServerRelease, IsKnown and
    SchemaNamingContext.

    .NOTES
    Version : 2.0 - August 2026. Migrated from the ActiveDirectory-Toolbox repository.
    Author : Bastien Perez - ITPro-Tips (https://itpro-tips.com)

    .LINK
    https://itpro-tips.com
#>

function Get-ADSchemaVersion {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [string]$Server
    )

    $ErrorActionPreference = 'Stop'

    # Common parameters forwarded to every ActiveDirectory cmdlet call
    $adParameters = @{ ErrorAction = 'Stop' }

    if ($PSBoundParameters.ContainsKey('Server')) {
        $adParameters.Add('Server', $Server)
    }

    $adSchemaVersions = @{
        13 = 'Windows 2000 Server'
        30 = 'Windows Server 2003 RTM, Service Pack 1, Service Pack 2'
        31 = 'Windows Server 2003 R2'
        44 = 'Windows Server 2008 RTM'
        47 = 'Windows Server 2008 R2'
        56 = 'Windows Server 2012'
        69 = 'Windows Server 2012 R2'
        87 = 'Windows Server 2016'
        88 = 'Windows Server 2019 or 2022'
        90 = 'Windows Server 2025'
    }

    try {
        $schemaNamingContext = (Get-ADRootDSE @adParameters).schemaNamingContext
        $schemaObject = Get-ADObject -Identity $schemaNamingContext -Properties 'objectVersion' @adParameters
    }
    catch {
        Write-Error "Unable to read the schema partition: $($_.Exception.Message)"
        return
    }

    $objectVersion = $schemaObject.objectVersion

    if ($adSchemaVersions.ContainsKey($objectVersion)) {
        $windowsServerRelease = $adSchemaVersions[$objectVersion]
        $isKnown = $true
    }
    else {
        # A schema newer than this table is not an error, it just means the table needs an entry
        $windowsServerRelease = 'Unknown, this version is not in the reference table'
        $isKnown = $false
        Write-Warning "Schema objectVersion $objectVersion is not in the reference table"
    }

    return [PSCustomObject][ordered]@{
        ObjectVersion        = $objectVersion
        WindowsServerRelease = $windowsServerRelease
        IsKnown              = $isKnown
        SchemaNamingContext  = $schemaNamingContext
    }
}
