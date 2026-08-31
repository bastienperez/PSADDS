<#
    .SYNOPSIS
    Report on the Active Directory schema attributes, with their indexing, replication and confidentiality flags.

    .DESCRIPTION
    Returns one object per attributeSchema object of the forest schema, with its definition (syntax, single valued,
    range, dates) and its 'searchFlags' decoded into readable columns rather than left as a raw integer.

    Two columns answer the confidentiality question, and they are not the same question:

    - 'Confidential' says the attribute IS marked confidential, which is bit 128 of 'searchFlags'. Reading it then
      requires the CONTROL_ACCESS right, a plain READ_PROPERTY is no longer enough.
    - 'CanBeConfidential' says the attribute COULD be marked confidential. Only attributes that are not part of the
      base schema can. Microsoft is explicit about it: bit 128 is "ignored for base schema attributes
      (systemFlags=0x10)". So an attribute can carry the bit and have it do nothing, which is exactly the kind of
      false sense of security an audit has to surface. That case shows up as Confidential = True and
      CanBeConfidential = False.

    Reference: https://learn.microsoft.com/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential

    'IsMemberOfPartialAttributeSet' tells whether the attribute is replicated to the global catalog, and
    'RodcFiltered' whether it is deliberately kept away from read only domain controllers.

    .PARAMETER Attribute
    Restrict the output to the attributes whose LDAP display name matches. Wildcards are supported, so 'ms-Mcs-Adm*'
    or '*password*' work. Defaults to every attribute of the schema.

    .PARAMETER ConfidentialOnly
    Return only the attributes marked confidential. Shorthand for the audit question "what is confidential here".

    .PARAMETER Server
    Domain controller or domain to query. Defaults to the one selected by the ActiveDirectory module.

    .EXAMPLE
    Get-ADSchemaAttribute

    Returns every attribute of the schema with its decoded flags.

    .EXAMPLE
    Get-ADSchemaAttribute -Attribute 'msLAPS-Password'

    Returns the definition of the Windows LAPS password attribute. Its searchFlags of 904 decodes to RodcFiltered,
    NeverAudit, Confidential and PreserveOnDelete, which is the reference layout for a sensitive attribute.

    .EXAMPLE
    Get-ADSchemaAttribute -ConfidentialOnly

    Returns the attributes marked confidential in this forest.

    .EXAMPLE
    Get-ADSchemaAttribute -ConfidentialOnly | Where-Object { -not $_.CanBeConfidential }

    Returns the attributes carrying the confidential bit while being part of the base schema, so the bit is ignored
    and the data is readable by anyone. Worth checking on every audit.

    .EXAMPLE
    Get-ADSchemaAttribute | Where-Object { $_.CanBeConfidential -and -not $_.Confidential -and $_.LdapDisplayName -like '*password*' }

    Returns the extended attributes that look credential related and could be marked confidential but are not.

    .EXAMPLE
    Get-ADSchemaAttribute | Where-Object { $_.Confidential -and -not $_.RodcFiltered }

    Returns the confidential attributes that are still replicated to the read only domain controllers. Microsoft
    recommends doing both, so this is a gap worth reviewing.

    .EXAMPLE
    Get-ADSchemaAttribute | Export-Csv -Path 'C:\temp\ADSchemaInfo.csv' -NoTypeInformation -Encoding UTF8 -Delimiter ';'

    Exports the full schema report.

    .OUTPUTS
    System.Management.Automation.PSCustomObject, one per attributeSchema object.

    .NOTES
    Version : 2.0 - August 2026. Migrated from the ActiveDirectory-Toolbox repository.
    Author : Bastien Perez - ITPro-Tips (https://itpro-tips.com)

    .LINK
    https://itpro-tips.com
#>

function Get-ADSchemaAttribute {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Position = 0)]
        [string]$Attribute,

        [switch]$ConfidentialOnly,

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

    # Filtering server side rather than in PowerShell, the schema partition holds thousands of objects
    if ([string]::IsNullOrWhiteSpace($Attribute)) {
        $filter = "objectClass -eq 'attributeSchema'"
    }
    else {
        $filter = "objectClass -eq 'attributeSchema' -and lDAPDisplayName -like '$Attribute'"
    }

    $properties = @(
        'lDAPDisplayName', 'adminDescription', 'adminDisplayName', 'attributeID', 'attributeSyntax',
        'isSingleValued', 'systemOnly', 'linkID', 'rangeLower', 'rangeUpper', 'searchFlags', 'systemFlags',
        'isMemberOfPartialAttributeSet', 'schemaIDGUID', 'whenCreated', 'whenChanged'
    )

    $getADObjectParams = $adParameters.Clone()
    $getADObjectParams.SearchBase = $schemaNamingContext
    $getADObjectParams.Filter = $filter
    $getADObjectParams.Properties = $properties

    [System.Collections.Generic.List[PSCustomObject]]$schemaAttributes = @()

    try {
        $attributesFound = @(Get-ADObject @getADObjectParams)
    }
    catch {
        Write-Error "Unable to query the schema partition: $($_.Exception.Message)"
        return
    }

    if ($attributesFound.Count -eq 0) {
        Write-Warning "No attribute matched '$Attribute' in the schema"
        return
    }

    Write-Verbose "[i] $($attributesFound.Count) attributes read from $schemaNamingContext"

    foreach ($attributeFound in $attributesFound) {

        $flags = ConvertFrom-ADSearchFlags -SearchFlags $attributeFound.searchFlags

        if ($ConfidentialOnly -and (-not $flags.Confidential)) {
            continue
        }

        # systemFlags bit 0x10 is FLAG_SCHEMA_BASE_OBJECT. The confidential bit is ignored on those attributes,
        # so they cannot be protected this way whatever searchFlags says.
        $systemFlags = 0

        if ($null -ne $attributeFound.systemFlags) {
            $systemFlags = [int]$attributeFound.systemFlags
        }

        $isBaseSchemaObject = [bool]($systemFlags -band 0x10)

        $schemaAttributes.Add([PSCustomObject][ordered]@{
                LdapDisplayName               = $attributeFound.lDAPDisplayName
                AdminDisplayName              = $attributeFound.adminDisplayName
                AdminDescription              = $attributeFound.adminDescription
                AttributeID                   = $attributeFound.attributeID
                AttributeSyntax               = $attributeFound.attributeSyntax
                IsSingleValued                = $attributeFound.isSingleValued
                SystemOnly                    = $attributeFound.systemOnly
                LinkID                        = $attributeFound.linkID
                RangeLower                    = $attributeFound.rangeLower
                RangeUpper                    = $attributeFound.rangeUpper
                IsMemberOfPartialAttributeSet = [bool]$attributeFound.isMemberOfPartialAttributeSet
                Confidential                  = $flags.Confidential
                CanBeConfidential             = (-not $isBaseSchemaObject)
                IsBaseSchemaObject            = $isBaseSchemaObject
                RodcFiltered                  = $flags.RodcFiltered
                NeverAudit                    = $flags.NeverAudit
                Indexed                       = $flags.Indexed
                ContainerIndexed              = $flags.ContainerIndexed
                ANR                           = $flags.ANR
                PreserveOnDelete              = $flags.PreserveOnDelete
                CopyOnCopy                    = $flags.CopyOnCopy
                TupleIndexed                  = $flags.TupleIndexed
                SubtreeIndexed                = $flags.SubtreeIndexed
                SearchFlags                   = $flags.SearchFlags
                SystemFlags                   = $systemFlags
                DistinguishedName             = $attributeFound.DistinguishedName
                ObjectGUID                    = $attributeFound.ObjectGUID
                WhenCreated                   = $attributeFound.whenCreated
                WhenChanged                   = $attributeFound.whenChanged
            })
    }

    return $schemaAttributes
}
