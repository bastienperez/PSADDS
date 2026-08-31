<#
    .SYNOPSIS
    List the classes that can be created directly under an instance of an Active Directory class.

    .DESCRIPTION
    Reads the 'possibleInferiors' attribute of the class definition in the schema. Active Directory calculates that
    attribute itself, from the possSuperiors and systemPossSuperiors of every other class, so the answer already
    accounts for inheritance and needs no walking of the schema.

    Useful when designing an OU structure, or when a creation fails with a naming violation and you want to know
    what the container will actually accept.

    Note this is what the schema allows, not what the current user is allowed to do. Permissions are not taken into
    account here, and the answer does not depend on the rights of the account running the query.

    Reference: https://learn.microsoft.com/windows/win32/adschema/a-possibleinferiors

    .PARAMETER ClassName
    LDAP display name of the class, such as 'user', 'organizationalUnit' or 'container'.

    .PARAMETER Server
    Domain controller or domain to query. Defaults to the one selected by the ActiveDirectory module.

    .EXAMPLE
    Get-ADSchemaClassPossibleChildren -ClassName 'organizationalUnit'

    Lists everything that can be created inside an OU.

    .EXAMPLE
    Get-ADSchemaClassPossibleChildren -ClassName 'computer'

    Lists what can live under a computer object, which is where the printQueue and the LAPS related objects show up.

    .EXAMPLE
    Get-ADSchemaClassPossibleChildren -ClassName 'user' -Server 'dc01.contoso.com'

    Queries a specific domain controller.

    .OUTPUTS
    System.String, one per class, sorted.

    .NOTES
    Version : 2.0 - August 2026. Migrated from the ActiveDirectory-Toolbox repository.

    The original built the distinguished name as "CN=$ClassName,$schemaNC", which assumes the common name of the
    class equals its LDAP display name. That holds for 'user' but not for most classes: the LDAP display name
    'organizationalUnit' has 'Organizational-Unit' as its common name, so the lookup failed. The class is now
    resolved on its lDAPDisplayName, which is what the parameter has always been documented to take.

    Author : Bastien Perez - ITPro-Tips (https://itpro-tips.com)

    .LINK
    https://itpro-tips.com
#>

function Get-ADSchemaClassPossibleChildren {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory, Position = 0)]
        [string]$ClassName,

        [string]$Server
    )

    $ErrorActionPreference = 'Stop'

    # Common parameters forwarded to every ActiveDirectory cmdlet call
    $adParameters = @{ ErrorAction = 'Stop' }

    if ($PSBoundParameters.ContainsKey('Server')) {
        $adParameters.Add('Server', $Server)
    }

    try {
        $schemaNamingContext = (Get-ADRootDSE @adParameters).schemaNamingContext
    }
    catch {
        Write-Error "Unable to read the RootDSE: $($_.Exception.Message)"
        return
    }

    $getADObjectParams = $adParameters.Clone()
    $getADObjectParams.SearchBase = $schemaNamingContext
    $getADObjectParams.LDAPFilter = "(&(objectClass=classSchema)(lDAPDisplayName=$ClassName))"
    $getADObjectParams.Properties = 'possibleInferiors'

    # Wrapped in an array, an ADObject implements IDictionary so 'Count' on a single object would return its
    # number of properties rather than 1
    $classesFound = @()

    try {
        $classesFound = @(Get-ADObject @getADObjectParams)
    }
    catch {
        Write-Error "Unable to query the schema partition: $($_.Exception.Message)"
        return
    }

    if ($classesFound.Count -eq 0) {
        Write-Error "Class '$ClassName' not found in the schema"
        return
    }

    $possibleChildren = @($classesFound[0].possibleInferiors)

    if ($possibleChildren.Count -eq 0) {
        Write-Warning "The class '$ClassName' cannot contain any object"
        return
    }

    return ($possibleChildren | Sort-Object)
}
