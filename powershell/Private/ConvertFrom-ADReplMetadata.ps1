<#
    .SYNOPSIS
    Parses the raw replication metadata carried by the msDS-ReplAttributeMetaData and msDS-ReplValueMetaData
    constructed attributes.

    .DESCRIPTION
    A domain controller returns those two attributes as a set of XML fragments, one per attribute or per linked
    value, each of them being a standalone document with no common root and padded with null characters. They
    cannot be cast to [xml] as they are: the fragments must first be wrapped in a single root element and the
    null characters replaced.

    This helper does that normalization once and returns the XML nodes, so that every public function reading
    replication metadata parses it the same way.

    Internal helper.

    .PARAMETER RawMetadata
    The value of the msDS-ReplAttributeMetaData or msDS-ReplValueMetaData property of an AD object.

    .OUTPUTS
    System.Xml.XmlElement, one per DS_REPL_ATTR_META_DATA or DS_REPL_VALUE_META_DATA entry.
    Returns nothing when the object carries no metadata.

    .LINK
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1a9177f4-0272-4ab8-aa22-3c3eafd39e4b
#>
function ConvertFrom-ADReplMetadata {
    [CmdletBinding()]
    [OutputType([System.Xml.XmlElement])]
    param (
        [Parameter(Position = 0)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$RawMetadata
    )

    if (-not $RawMetadata) {
        Write-Verbose 'No replication metadata to parse'
        return
    }

    # the fragments are concatenated under a single root, and the null padding is replaced, so the whole
    # set can be cast to [xml] in one go
    $normalized = '<root>' + ($RawMetadata -join '') + '</root>'
    $normalized = $normalized.Replace([char]0, ' ')

    try {
        $xml = [xml]$normalized
    }
    catch {
        Write-Warning "Unable to parse the replication metadata: $($_.Exception.Message)"
        return
    }

    # DS_REPL_ATTR_META_DATA for msDS-ReplAttributeMetaData, DS_REPL_VALUE_META_DATA for msDS-ReplValueMetaData
    $xml.root.ChildNodes
}
