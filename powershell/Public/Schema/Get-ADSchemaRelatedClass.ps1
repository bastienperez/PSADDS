<#
    .SYNOPSIS
    List every class an Active Directory class inherits from or is extended by.

    .DESCRIPTION
    Returns the class itself, every parent class up the subClassOf chain until 'top', and every auxiliary class
    attached along the way, including the system auxiliary classes.

    This is the set of classes that decide which attributes an object of that class can actually hold. An attribute
    rarely sits on the class you are looking at: on an extended schema it usually comes from a parent or from an
    auxiliary class added by a product such as Exchange.

    Use Get-ADAttributeInfo when you want the attributes themselves and where each one comes from. This function
    answers the narrower question of which classes are involved.

    .PARAMETER ClassName
    LDAP display name of the class, such as 'user', 'group' or 'computer'.

    .PARAMETER Server
    Domain controller or domain to query. Defaults to the one selected by the ActiveDirectory module.

    .EXAMPLE
    Get-ADSchemaRelatedClass -ClassName 'user'

    Returns user, organizationalPerson, person, top and the auxiliary classes attached to any of them.

    .EXAMPLE
    Get-ADSchemaRelatedClass -ClassName 'user' | ForEach-Object { Get-ADAttributeInfo -ClassName $_ }

    Walks the whole inheritance tree of the user class and lists the attributes of each class in it.

    .OUTPUTS
    System.String, one per class, without duplicates.

    .NOTES
    Version : 2.0 - August 2026. Migrated from the ActiveDirectory-Toolbox repository.

    The original was a modified version of https://www.neroblanco.co.uk/2017/09/get-possible-ad-attributes-user-group/
    and never ran: it was renamed to Get-ADSchemaRelatedClass but kept calling itself under its former name,
    Get-RelatedClass, which existed nowhere. It failed as soon as a class had a parent, so always except on 'top'.
    Fixed here, along with the missing systemAuxiliaryClass, the duplicates and the absence of any protection
    against a loop between two auxiliary classes.

    Author : Bastien Perez - ITPro-Tips (https://itpro-tips.com)

    .LINK
    https://itpro-tips.com
#>

function Get-ADSchemaRelatedClass {
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

    # Ordered, so the class asked for comes first and its parents follow in inheritance order
    $relatedClasses = [System.Collections.Generic.List[string]]@()

    # A class is reachable through several paths, and two auxiliary classes can reference each other. Without this
    # the recursion never ends.
    $visitedClasses = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    function Resolve-RelatedClass {
        param (
            [string]$Name
        )

        if ([string]::IsNullOrWhiteSpace($Name)) {
            return
        }

        if (-not $visitedClasses.Add($Name)) {
            return
        }

        $getADObjectParams = $adParameters.Clone()
        $getADObjectParams.SearchBase = $schemaNamingContext
        $getADObjectParams.LDAPFilter = "(&(objectClass=classSchema)(lDAPDisplayName=$Name))"
        $getADObjectParams.Properties = 'lDAPDisplayName', 'subClassOf', 'auxiliaryClass', 'systemAuxiliaryClass'

        # Wrapped in an array, an ADObject implements IDictionary so 'Count' on a single object would return its
        # number of properties rather than 1
        $classesFound = @()

        try {
            $classesFound = @(Get-ADObject @getADObjectParams)
        }
        catch {
            Write-Warning "Unable to read the class '$Name': $($_.Exception.Message)"
            return
        }

        if ($classesFound.Count -eq 0) {
            Write-Warning "Class '$Name' not found in the schema"
            return
        }

        $classFound = $classesFound[0]
        $relatedClasses.Add($classFound.lDAPDisplayName)

        # 'top' is its own parent, which is where the chain stops
        if (($null -ne $classFound.subClassOf) -and ($classFound.subClassOf -ne $classFound.lDAPDisplayName)) {
            Resolve-RelatedClass -Name $classFound.subClassOf
        }

        foreach ($property in @('auxiliaryClass', 'systemAuxiliaryClass')) {
            if ($null -eq $classFound.$property) {
                continue
            }

            foreach ($auxiliaryClass in @($classFound.$property)) {
                Resolve-RelatedClass -Name $auxiliaryClass
            }
        }
    }

    Resolve-RelatedClass -Name $ClassName

    if ($relatedClasses.Count -eq 0) {
        Write-Warning "No class found for '$ClassName'"
    }

    return $relatedClasses
}
