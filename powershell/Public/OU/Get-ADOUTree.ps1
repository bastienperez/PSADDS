<#
    .SYNOPSIS
    List the organizational units of a domain as an indented tree.

    .DESCRIPTION
    Reads the organizational units of the domain, or of one branch, and returns them in tree order: every OU comes
    right after its parent, and its name is indented by its depth.

    One object is returned per OU. The Tree property holds the indented name, so the tree reads at the console
    and the same objects export to CSV with their distinguished name and depth.

    Only organizational units are listed. Containers such as CN=Users are not OUs and are not returned.

    .PARAMETER SearchBase
    Distinguished name of the OU to start from. This OU is returned at depth 0 with everything below it.
    Defaults to the domain: the top level OUs are at depth 0.

    .PARAMETER Server
    Domain controller or domain to query. Defaults to the one selected by the ActiveDirectory module.

    .PARAMETER IncludeObjectCount
    Adds ObjectCount, the number of objects directly in each OU (not in its child OUs). One more query per OU,
    so it is slower on a large directory.

    .PARAMETER Indent
    String repeated once per level to indent the Tree property. Defaults to four spaces.

    .EXAMPLE
    Get-ADOUTree | Select-Object -ExpandProperty Tree

    Prints the OU tree of the current domain.

    .EXAMPLE
    Get-ADOUTree -SearchBase 'OU=Tier0,DC=contoso,DC=com' -IncludeObjectCount | Format-Table Tree, ObjectCount

    Shows one branch with the number of objects directly in each OU.

    .EXAMPLE
    Get-ADOUTree -IncludeObjectCount | Export-Csv -Path .\ou-tree.csv -NoTypeInformation

    Exports the whole structure with its distinguished names and depths.

    .OUTPUTS
    System.Management.Automation.PSCustomObject with Tree, Name, Depth, DistinguishedName, CanonicalName and, with
    -IncludeObjectCount, ObjectCount.

    .NOTES
    Version : 1.0 - November 2026.
    Author : Bastien Perez - ITPro-Tips (https://itpro-tips.com)

    .LINK
    https://itpro-tips.com
#>

function Get-ADOUTree {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [string]$SearchBase,

        [string]$Server,

        [switch]$IncludeObjectCount,

        [string]$Indent = '    '
    )

    $ErrorActionPreference = 'Stop'

    # Common parameters forwarded to every ActiveDirectory cmdlet call
    $adParameters = @{ ErrorAction = 'Stop' }

    if ($PSBoundParameters.ContainsKey('Server')) {
        $adParameters.Add('Server', $Server)
    }

    $ouParameters = @{
        Filter     = '*'
        Properties = 'CanonicalName'
    }

    if ($PSBoundParameters.ContainsKey('SearchBase')) {
        $ouParameters.Add('SearchBase', $SearchBase)
    }

    $organizationalUnits = @(Get-ADOrganizationalUnit @ouParameters @adParameters)

    # A '/' inside an OU name is escaped as '\/' in the canonical name: only the unescaped ones separate levels.
    $separator = '(?<!\\)/'

    # Sorting on the canonical name alone breaks the tree when a name starts like another one followed by a
    # character that sorts before '/' ('Paris Nord' would come before 'Paris/Users'). The separator is replaced
    # by a control character that sorts before any character a name can hold, and the sort is ordinal because
    # a culture-aware comparison ignores control characters.
    $sortedUnits = New-Object -TypeName 'System.Collections.Generic.SortedDictionary[string,object]' -ArgumentList ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($organizationalUnit in $organizationalUnits) {
        $sortedUnits[($organizationalUnit.CanonicalName -replace $separator, [string][char]1)] = $organizationalUnit
    }
    $sorted = @($sortedUnits.Values)

    $baseDepth = 0

    if ($PSBoundParameters.ContainsKey('SearchBase')) {
        # The base OU is returned too: its own depth becomes 0.
        $baseCanonicalName = ($organizationalUnits | Where-Object { $_.DistinguishedName -eq $SearchBase } | Select-Object -First 1).CanonicalName
        if ($baseCanonicalName) {
            $baseDepth = @($baseCanonicalName -split $separator).Count - 2
        }
    }

    foreach ($organizationalUnit in $sorted) {
        $depth = @($organizationalUnit.CanonicalName -split $separator).Count - 2 - $baseDepth

        $result = [ordered]@{
            Tree              = ($Indent * $depth) + $organizationalUnit.Name
            Name              = $organizationalUnit.Name
            Depth             = $depth
            DistinguishedName = $organizationalUnit.DistinguishedName
            CanonicalName     = $organizationalUnit.CanonicalName
        }

        if ($IncludeObjectCount) {
            $objects = @(Get-ADObject -Filter * -SearchBase $organizationalUnit.DistinguishedName -SearchScope OneLevel @adParameters)
            # The child OUs are counted by their own line, not as objects of the parent.
            $result.ObjectCount = @($objects | Where-Object { $_.ObjectClass -ne 'organizationalUnit' }).Count
        }

        [PSCustomObject]$result
    }

    return
}
