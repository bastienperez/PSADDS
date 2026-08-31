<#
    .SYNOPSIS
    List the attributes of an Active Directory class, or the classes using an attribute, and say where each one
    actually comes from.

    .DESCRIPTION
    Works in two modes:

    - by class, with -ClassName: every attribute the class exposes, mandatory and optional;
    - by attribute, with -AttributeName: every class exposing that attribute. Wildcards are supported.

    In both modes the 'Source' column tells where the attribute is really defined, which is the part a plain schema
    listing does not give you. An attribute can reach a class three different ways:

    - 'Direct', defined on the class itself through mustContain, mayContain, systemMustContain or systemMayContain;
    - inherited from a parent class, following the subClassOf chain up to 'top';
    - brought in by an auxiliary class, through auxiliaryClass or systemAuxiliaryClass.

    That last case is the one that matters on an extended schema. When Exchange or a third party product adds an
    auxiliary class to 'user', the attributes show up on every user object without ever appearing in the class
    definition itself. Knowing which auxiliary class carries an attribute is what tells you which product owns it,
    and what you would break by removing it.

    Each row also carries the confidentiality of the attribute:

    - 'Confidential', the attribute IS marked confidential, bit 128 of 'searchFlags'. Reading it then requires the
      CONTROL_ACCESS right rather than a plain READ_PROPERTY.
    - 'CanBeConfidential', the attribute COULD be. Only attributes outside the base schema can: Microsoft states
      that bit 128 is "ignored for base schema attributes (systemFlags=0x10)". An attribute with the bit set and
      CanBeConfidential = False is protected in appearance only.

    Reference: https://learn.microsoft.com/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential

    .PARAMETER ClassName
    LDAP display name of the class to inspect, such as 'user', 'group' or 'computer'.

    .PARAMETER AttributeName
    LDAP display name of the attribute to look for across every class. Wildcards are supported, so 'mail*',
    '*password*' or 'ms-Mcs-Adm*' work.

    .PARAMETER Server
    Domain controller or domain to query. Defaults to the one selected by the ActiveDirectory module.

    .EXAMPLE
    Get-ADSchemaClassAttribute -ClassName 'user'

    Returns every attribute of the user class, with the class each one is defined on.

    .EXAMPLE
    Get-ADSchemaClassAttribute -ClassName 'user' | Where-Object { $_.Source -ne 'Direct' } | Group-Object Source

    Shows which parent and auxiliary classes actually populate the user class, and how many attributes each brings.

    .EXAMPLE
    Get-ADSchemaClassAttribute -ClassName 'user' | Where-Object { $_.Required -eq 'Mandatory' }

    Returns only the mandatory attributes, the ones a creation cannot omit.

    .EXAMPLE
    Get-ADSchemaClassAttribute -AttributeName 'mail'

    Returns every class exposing the 'mail' attribute.

    .EXAMPLE
    Get-ADSchemaClassAttribute -AttributeName 'ms-Mcs-Adm*'

    Returns the legacy LAPS attributes and the classes carrying them. Wildcards are supported.

    .EXAMPLE
    Get-ADSchemaClassAttribute -ClassName 'computer' | Where-Object { $_.Confidential }

    Returns the attributes of the computer class that are marked confidential, which is where a LAPS password
    should show up.

    .EXAMPLE
    Get-ADSchemaClassAttribute -ClassName 'user' | Where-Object { $_.CanBeConfidential -and -not $_.Confidential }

    Returns the attributes of the user class that could be marked confidential and are not. Extended attributes
    holding sensitive data usually belong here.

    .OUTPUTS
    System.Management.Automation.PSCustomObject, one per class and attribute pair.

    .NOTES
    Version : 2.0 - August 2026. Migrated from the ActiveDirectory-Toolbox repository, where it was named
    Get-ADSchemaClassAttributev2.
    Author : Bastien Perez - ITPro-Tips (https://itpro-tips.com)

    .LINK
    https://itpro-tips.com
#>

function Get-ADSchemaClassAttribute {
    [CmdletBinding(DefaultParameterSetName = 'Attribute')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory, ParameterSetName = 'Class', Position = 0)]
        [string]$ClassName,

        [Parameter(Mandatory, ParameterSetName = 'Attribute', Position = 0)]
        [string]$AttributeName,

        [string]$Server
    )

    $ErrorActionPreference = 'Stop'

    # Common parameters forwarded to every ActiveDirectory cmdlet call
    $adParameters = @{ ErrorAction = 'Stop' }

    if ($PSBoundParameters.ContainsKey('Server')) {
        $adParameters.Add('Server', $Server)
    }

    try {
        $rootDSE = Get-ADRootDSE @adParameters
    }
    catch {
        Write-Error "Unable to read the RootDSE: $($_.Exception.Message)"
        return
    }

    $schemaNamingContext = $rootDSE.schemaNamingContext

    Write-Verbose "[i] Reading the class definitions from $schemaNamingContext"

    $getClassParams = $adParameters.Clone()
    $getClassParams.SearchBase = $schemaNamingContext
    $getClassParams.Filter = "objectClass -eq 'classSchema'"
    $getClassParams.Properties = @(
        'lDAPDisplayName', 'subClassOf', 'auxiliaryClass', 'systemAuxiliaryClass',
        'mustContain', 'systemMustContain', 'mayContain', 'systemMayContain'
    )

    try {
        $classesFound = @(Get-ADObject @getClassParams)
    }
    catch {
        Write-Error "Unable to query the schema partition: $($_.Exception.Message)"
        return
    }

    # Indexed by LDAP display name so the inheritance chain can be walked without querying again
    $classesByName = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($classFound in $classesFound) {
        if (-not [string]::IsNullOrWhiteSpace($classFound.lDAPDisplayName)) {
            $classesByName[$classFound.lDAPDisplayName] = $classFound
        }
    }

    Write-Verbose "[i] $($classesByName.Count) classes read"

    # Confidentiality lives on the attributeSchema objects, read once for the whole schema. Three properties on a
    # few thousand objects is cheaper than one query per attribute found.
    Write-Verbose '[i] Reading the attribute definitions'

    $getAttributeParams = $adParameters.Clone()
    $getAttributeParams.SearchBase = $schemaNamingContext
    $getAttributeParams.Filter = "objectClass -eq 'attributeSchema'"
    $getAttributeParams.Properties = @('lDAPDisplayName', 'searchFlags', 'systemFlags')

    $attributesByName = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)

    try {
        foreach ($attributeFound in (Get-ADObject @getAttributeParams)) {
            if (-not [string]::IsNullOrWhiteSpace($attributeFound.lDAPDisplayName)) {
                $attributesByName[$attributeFound.lDAPDisplayName] = $attributeFound
            }
        }
    }
    catch {
        Write-Warning "Unable to read the attribute definitions, the confidentiality columns will be empty: $($_.Exception.Message)"
    }

    # Resolve every attribute reachable from a class: defined on it, inherited from its parents, or brought in by an
    # auxiliary class. Returns a dictionary of attribute name to the class it is defined on and whether it is
    # mandatory. Memoised, since the same parent classes are walked over and over in attribute mode.
    $resolvedClasses = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)

    # Shared counter, incremented every time the recursion refuses to walk a class it is already inside. A result
    # computed while that happened is truncated, so it must not be cached. Held in a hashtable because a nested
    # function cannot assign to a plain variable of its parent scope.
    $resolutionState = @{ CycleHits = 0 }

    function Resolve-ClassAttribute {
        param (
            [string]$Name,
            [System.Collections.Generic.HashSet[string]]$Visited
        )

        if ($resolvedClasses.ContainsKey($Name)) {
            return $resolvedClasses[$Name]
        }

        # 'top' is its own parent, and an auxiliary class can be reachable through several paths
        if (-not $Visited.Add($Name)) {
            $resolutionState.CycleHits++
            return [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }

        $cycleHitsBefore = $resolutionState.CycleHits

        $attributes = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::OrdinalIgnoreCase)

        if (-not $classesByName.ContainsKey($Name)) {
            Write-Verbose "[*] Class '$Name' referenced but not found in the schema"
            return $attributes
        }

        $classObject = $classesByName[$Name]

        # Inherited first, so a definition on the class itself overwrites it and wins the 'Source' column
        $parents = @()

        foreach ($property in @('subClassOf', 'auxiliaryClass', 'systemAuxiliaryClass')) {
            if ($null -ne $classObject.$property) {
                $parents += @($classObject.$property)
            }
        }

        foreach ($parent in $parents) {
            if ([string]::IsNullOrWhiteSpace($parent) -or ($parent -eq $Name)) {
                continue
            }

            foreach ($inherited in (Resolve-ClassAttribute -Name $parent -Visited $Visited).GetEnumerator()) {
                # A mandatory definition anywhere wins over an optional one
                if ((-not $attributes.ContainsKey($inherited.Key)) -or ($inherited.Value.Required -eq 'Mandatory')) {
                    $attributes[$inherited.Key] = $inherited.Value
                }
            }
        }

        $directSets = @(
            @{ Properties = @('mustContain', 'systemMustContain'); Required = 'Mandatory' }
            @{ Properties = @('mayContain', 'systemMayContain'); Required = 'Optional' }
        )

        foreach ($directSet in $directSets) {
            foreach ($property in $directSet.Properties) {
                if ($null -eq $classObject.$property) {
                    continue
                }

                foreach ($attribute in @($classObject.$property)) {
                    if ([string]::IsNullOrWhiteSpace($attribute)) {
                        continue
                    }

                    # Defined on the class itself, this always replaces an inherited definition
                    $attributes[$attribute] = [PSCustomObject]@{
                        Required = $directSet.Required
                        Source   = $Name
                    }
                }
            }
        }

        # Only cache a complete result. If the recursion hit a cycle below this class, what was built is partial
        # and caching it would poison every later lookup.
        if ($resolutionState.CycleHits -eq $cycleHitsBefore) {
            $resolvedClasses[$Name] = $attributes
        }

        return $attributes
    }

    # Build one output row per class and attribute pair
    function New-AttributeInfo {
        param (
            [string]$Class,
            [string]$Attribute,
            [string]$Required,
            [string]$DefinedOn
        )

        $confidential = $null
        $canBeConfidential = $null
        $searchFlags = $null

        if ($attributesByName.ContainsKey($Attribute)) {
            $definition = $attributesByName[$Attribute]
            $flags = ConvertFrom-ADSearchFlags -SearchFlags $definition.searchFlags
            $confidential = $flags.Confidential
            $searchFlags = $flags.SearchFlags

            # systemFlags bit 0x10 is FLAG_SCHEMA_BASE_OBJECT, and the confidential bit is ignored on those
            $systemFlags = 0

            if ($null -ne $definition.systemFlags) {
                $systemFlags = [int]$definition.systemFlags
            }

            $canBeConfidential = (-not [bool]($systemFlags -band 0x10))
        }

        # 'Direct' rather than repeating the class name, so the interesting rows stand out at a glance
        if ($DefinedOn -eq $Class) {
            $source = 'Direct'
        }
        else {
            $source = $DefinedOn
        }

        return [PSCustomObject][ordered]@{
            Class             = $Class
            Attribute         = $Attribute
            Required          = $Required
            Source            = $source
            Confidential      = $confidential
            CanBeConfidential = $canBeConfidential
            SearchFlags       = $searchFlags
        }
    }

    [System.Collections.Generic.List[PSCustomObject]]$results = @()

    if ($PSCmdlet.ParameterSetName -eq 'Class') {

        if (-not $classesByName.ContainsKey($ClassName)) {
            Write-Error "Class '$ClassName' not found in the schema"
            return
        }

        $resolvedName = $classesByName[$ClassName].lDAPDisplayName
        $attributes = Resolve-ClassAttribute -Name $resolvedName -Visited ([System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase))

        foreach ($attribute in ($attributes.Keys | Sort-Object)) {
            $results.Add((New-AttributeInfo -Class $resolvedName -Attribute $attribute -Required $attributes[$attribute].Required -DefinedOn $attributes[$attribute].Source))
        }
    }
    else {
        Write-Verbose "[i] Looking for '$AttributeName' across $($classesByName.Count) classes"

        foreach ($name in ($classesByName.Keys | Sort-Object)) {
            $attributes = Resolve-ClassAttribute -Name $name -Visited ([System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase))

            foreach ($attribute in ($attributes.Keys | Sort-Object)) {
                # -like covers both the exact name and the wildcard forms
                if ($attribute -like $AttributeName) {
                    $results.Add((New-AttributeInfo -Class $name -Attribute $attribute -Required $attributes[$attribute].Required -DefinedOn $attributes[$attribute].Source))
                }
            }
        }

        if ($results.Count -eq 0) {
            Write-Warning "No class exposes an attribute matching '$AttributeName'"
        }
    }

    return $results
}
