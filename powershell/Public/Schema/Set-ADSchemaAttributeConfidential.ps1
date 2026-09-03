<#
    .SYNOPSIS
    Mark an Active Directory schema attribute as confidential, or remove that mark, after checking that the
    attribute can actually carry it.

    .DESCRIPTION
    Confidentiality is bit 128 (fCONFIDENTIAL) of the 'searchFlags' attribute of an attributeSchema object. Once
    set, reading the attribute requires the CONTROL_ACCESS right on it, a plain READ_PROPERTY is no longer enough,
    so 'Authenticated Users' stop seeing the value.

    The bit is not honoured everywhere, and setting it where it is ignored gives a false sense of security. The
    function therefore validates the attribute before writing anything:

    - the attribute must exist in the schema partition, matched on its lDAPDisplayName;
    - it must not be part of the base schema. Microsoft is explicit: bit 128 is "ignored for base schema
      attributes (systemFlags=0x10)". Those are rejected, unless -Force is used to write the bit anyway;
    - it must not be a constructed attribute (systemFlags bit 0x4). A constructed attribute is computed at read
      time and is not stored, so 'searchFlags' does not gate it. Those are rejected as well, -Force overrides;
    - the write must target the schema master. Objects of the schema partition are only writable there, so the
      function resolves the role owner and uses it by default.

    The check is self contained: it reads 'searchFlags' and 'systemFlags' directly and does not call
    Get-ADSchemaAttribute, so the function stands on its own.

    Requires the ActiveDirectory module (RSAT) and membership of Schema Admins. Supports -WhatIf and -Confirm.

    Reference: https://learn.microsoft.com/troubleshoot/windows-server/windows-security/mark-attribute-as-confidential

    .PARAMETER Attribute
    One or more attributes, given by their LDAP display name ('employeeNumber', 'msDS-cloudExtensionAttribute1').
    No wildcard: marking an attribute confidential is a schema change, it is done on named attributes only.
    Accepts pipeline input, including the 'LdapDisplayName' property emitted by Get-ADSchemaAttribute.

    .PARAMETER Remove
    Clear the confidential bit instead of setting it. The attribute becomes readable again by anyone holding
    READ_PROPERTY on it.

    .PARAMETER Force
    Write the bit even when it will be ignored, that is on a base schema attribute or a constructed attribute.
    Present for the rare case where the value has to be aligned across forests, not for general use.

    .PARAMETER Server
    Domain controller to write to. Defaults to the schema master of the forest, which is the only writable copy
    of the schema partition. A -Server that is not the schema master is warned about, and the write will fail.

    .PARAMETER PassThru
    Return an object describing the attribute and the change, instead of returning nothing.

    .EXAMPLE
    Set-ADSchemaAttributeConfidential -Attribute 'employeeNumber' -WhatIf

    Shows what would be written without changing the schema.

    .EXAMPLE
    Set-ADSchemaAttributeConfidential -Attribute 'msDS-cloudExtensionAttribute1' -PassThru

    Marks the attribute confidential and returns the old and new 'searchFlags'.

    .EXAMPLE
    Set-ADSchemaAttributeConfidential -Attribute 'employeeNumber' -Remove

    Removes the confidential bit, leaving the other 'searchFlags' bits untouched.

    .EXAMPLE
    Set-ADSchemaAttributeConfidential -Attribute 'description'

    Fails: 'description' is a base schema attribute, the bit would be stored and ignored.

    .OUTPUTS
    None by default. System.Management.Automation.PSCustomObject with -PassThru.

    .NOTES
    Author : Bastien Perez - ITPro-Tips (https://itpro-tips.com)

    .LINK
    https://github.com/bastienperez/PSADDS
#>

function Set-ADSchemaAttributeConfidential {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('LdapDisplayName', 'Name')]
        [string[]]$Attribute,

        [Parameter(Mandatory = $false)]
        [switch]$Remove,

        [Parameter(Mandatory = $false)]
        [switch]$Force,

        [Parameter(Mandatory = $false)]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    begin {
        if (-not (Get-Command -Name 'Get-ADRootDSE' -ErrorAction SilentlyContinue)) {
            throw 'The ActiveDirectory module is required (RSAT). Import it and try again.'
        }

        # searchFlags bit 128, the only bit this function touches. The others are preserved.
        $confidentialBit = 128

        # systemFlags bits that make the confidential bit meaningless
        $flagSchemaBaseObject = 0x10
        $flagAttrIsConstructed = 0x4

        # Objects of the schema partition are only writable on the schema master, so it is the default target
        try {
            $schemaMaster = (Get-ADForest -ErrorAction Stop).SchemaMaster
        }
        catch {
            $schemaMaster = $null
            Write-Verbose "[i] Unable to resolve the schema master: $($_.Exception.Message)"
        }

        $adParams = @{ ErrorAction = 'Stop' }

        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $adParams['Server'] = $Server

            if ($schemaMaster -and ($Server -notlike "$schemaMaster*") -and ($schemaMaster -notlike "$Server*")) {
                Write-Warning "[!] '$Server' does not look like the schema master ('$schemaMaster'). The schema partition is only writable on the schema master."
            }
        }
        elseif ($schemaMaster) {
            $adParams['Server'] = $schemaMaster
            Write-Verbose "[i] Targeting the schema master '$schemaMaster'"
        }

        try {
            $schemaNamingContext = (Get-ADRootDSE @adParams).schemaNamingContext
        }
        catch {
            throw "Unable to read the RootDSE: $($_.Exception.Message)"
        }
    }

    process {
        foreach ($attributeName in $Attribute) {

            if ([string]::IsNullOrWhiteSpace($attributeName)) {
                continue
            }

            # Escaped for the LDAP filter. An lDAPDisplayName never contains those characters, but the input is
            # not trusted: a wildcard would silently widen a schema change to several attributes.
            $escapedName = $attributeName -replace '\\', '\5c' -replace '\*', '\2a' -replace '\(', '\28' -replace '\)', '\29'

            $getADObjectParams = $adParams.Clone()
            $getADObjectParams['SearchBase'] = $schemaNamingContext
            $getADObjectParams['LDAPFilter'] = "(&(objectCategory=attributeSchema)(lDAPDisplayName=$escapedName))"
            $getADObjectParams['Properties'] = @('lDAPDisplayName', 'searchFlags', 'systemFlags', 'isDefunct')

            try {
                $schemaAttributes = @(Get-ADObject @getADObjectParams)
            }
            catch {
                Write-Warning "[!] Unable to query the schema for '$attributeName'. $($_.Exception.Message)"
                continue
            }

            if ($schemaAttributes.Count -eq 0) {
                Write-Warning "[!] No attributeSchema object named '$attributeName' in $schemaNamingContext"
                continue
            }

            $schemaAttribute = $schemaAttributes[0]

            # An attribute with no flag at all has an empty searchFlags rather than a zero, same for systemFlags
            $currentSearchFlags = 0

            if ($null -ne $schemaAttribute.searchFlags) {
                $currentSearchFlags = [int]$schemaAttribute.searchFlags
            }

            $systemFlags = 0

            if ($null -ne $schemaAttribute.systemFlags) {
                $systemFlags = [int]$schemaAttribute.systemFlags
            }

            $isBaseSchemaObject = [bool]($systemFlags -band $flagSchemaBaseObject)
            $isConstructed = [bool]($systemFlags -band $flagAttrIsConstructed)
            $isConfidential = [bool]($currentSearchFlags -band $confidentialBit)

            # Validation. Only the set direction is blocked: clearing a bit that is ignored is always safe.
            if (-not $Remove) {
                $blockingReasons = [System.Collections.Generic.List[string]]::new()

                if ($isBaseSchemaObject) {
                    $blockingReasons.Add('it is a base schema attribute (systemFlags 0x10), the confidential bit is ignored on those')
                }

                if ($isConstructed) {
                    $blockingReasons.Add('it is a constructed attribute (systemFlags 0x4), its value is computed at read time and is not gated by searchFlags')
                }

                if ($blockingReasons.Count -gt 0) {
                    $reasonText = $blockingReasons -join ', and '

                    if (-not $Force) {
                        Write-Warning "[!] '$($schemaAttribute.lDAPDisplayName)' cannot be made confidential: $reasonText. Use -Force to write the bit anyway."
                        continue
                    }

                    Write-Warning "[*] '$($schemaAttribute.lDAPDisplayName)': $reasonText. -Force was specified, the bit is written but will have no effect."
                }
            }

            if ($schemaAttribute.isDefunct -eq $true) {
                Write-Warning "[*] '$($schemaAttribute.lDAPDisplayName)' is defunct, it is no longer usable in the directory."
            }

            if ($Remove) {
                $newSearchFlags = $currentSearchFlags -band (-bnot $confidentialBit)
                $action = "Remove the confidential bit, searchFlags $currentSearchFlags -> $newSearchFlags"
            }
            else {
                $newSearchFlags = $currentSearchFlags -bor $confidentialBit
                $action = "Mark as confidential, searchFlags $currentSearchFlags -> $newSearchFlags"
            }

            $changed = $false

            if ($newSearchFlags -eq $currentSearchFlags) {
                $state = if ($isConfidential) { 'already confidential' } else { 'already not confidential' }
                Write-Verbose "[i] '$($schemaAttribute.lDAPDisplayName)' is $state (searchFlags $currentSearchFlags), nothing to do."
            }
            elseif ($PSCmdlet.ShouldProcess($schemaAttribute.DistinguishedName, $action)) {
                $setADObjectParams = $adParams.Clone()
                $setADObjectParams['Identity'] = $schemaAttribute.DistinguishedName
                $setADObjectParams['Replace'] = @{ searchFlags = $newSearchFlags }

                try {
                    Set-ADObject @setADObjectParams
                    $changed = $true
                }
                catch {
                    Write-Warning "[!] Failed to update '$($schemaAttribute.lDAPDisplayName)'. $($_.Exception.Message)"
                    continue
                }

                if ($Remove) {
                    Write-Host -ForegroundColor Green "[OK] '$($schemaAttribute.lDAPDisplayName)' is no longer confidential (searchFlags $newSearchFlags)"
                }
                else {
                    Write-Host -ForegroundColor Green "[OK] '$($schemaAttribute.lDAPDisplayName)' is now confidential (searchFlags $newSearchFlags)"
                }
            }
            else {
                # -WhatIf, or the confirmation was declined
                continue
            }

            if ($PassThru) {
                $object = [PSCustomObject][ordered]@{
                    LdapDisplayName     = $schemaAttribute.lDAPDisplayName
                    DistinguishedName   = $schemaAttribute.DistinguishedName
                    Server              = $adParams['Server']
                    PreviousSearchFlags = $currentSearchFlags
                    SearchFlags         = $newSearchFlags
                    Confidential        = [bool]($newSearchFlags -band $confidentialBit)
                    IsBaseSchemaObject  = $isBaseSchemaObject
                    IsConstructed       = $isConstructed
                    Changed             = $changed
                }

                $object
            }
        }
    }
}
