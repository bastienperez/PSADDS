<#
    .SYNOPSIS
    Decode the 'searchFlags' attribute of a schema attribute into named booleans.

    .DESCRIPTION
    'searchFlags' is a bit field carried by every attributeSchema object. Reading it as a raw integer tells nobody
    anything, so it is decoded here once and reused by every function that reports on the schema.

    Reference: https://learn.microsoft.com/windows/win32/adschema/a-searchflags

    | Bit  | Name                   | Meaning                                                              |
    |------|------------------------|----------------------------------------------------------------------|
    | 1    | fATTINDEX              | Indexed                                                              |
    | 2    | fPDNTATTINDEX          | Indexed in each container, for one level searches                    |
    | 4    | fANR                   | Part of the Ambiguous Name Resolution set                            |
    | 8    | fPRESERVEONDELETE      | Kept on the tombstone when the object is deleted                     |
    | 16   | fCOPY                  | Copied when the object is copied                                     |
    | 32   | fTUPLEINDEX            | Tuple index, speeds up searches with a leading wildcard              |
    | 64   | fSUBTREEATTINDEX       | Subtree index, for VLV searches                                      |
    | 128  | fCONFIDENTIAL          | Confidential, reading it requires CONTROL_ACCESS                     |
    | 256  | fNEVERVALUEAUDIT       | Value auditing disabled                                              |
    | 512  | fRODCFilteredAttribute | NOT replicated to read only domain controllers                       |

    Two names deserve attention, because getting them backwards inverts the conclusion of an audit:

    - bit 256 does not enable auditing, it disables it. The property is named 'NeverAudit'.
    - bit 512 does not mean the attribute works on an RODC, it means it is filtered out and never replicated to one.
      The property is named 'RodcFiltered'.

    ms-LAPS-Password is the reference example, with a 'searchFlags' of 904: 512 + 256 + 128 + 8, so filtered out of
    the RODCs, never audited, confidential and preserved on delete.

    .PARAMETER SearchFlags
    The raw 'searchFlags' value. A null value is treated as zero, which is what an attribute with no flag looks like.

    .EXAMPLE
    ConvertFrom-ADSearchFlags -SearchFlags 904

    Returns the decoded flags of ms-LAPS-Password.

    .OUTPUTS
    System.Management.Automation.PSCustomObject

    .NOTES
    Author : Bastien Perez - ITPro-Tips (https://itpro-tips.com)
#>

function ConvertFrom-ADSearchFlags {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Position = 0, ValueFromPipeline)]
        [AllowNull()]
        [System.Nullable[int]]$SearchFlags
    )

    process {
        # An attribute with no flag at all has an empty searchFlags rather than a zero
        if ($null -eq $SearchFlags) {
            $flags = 0
        }
        else {
            $flags = [int]$SearchFlags
        }

        [PSCustomObject][ordered]@{
            SearchFlags      = $flags
            Indexed          = [bool]($flags -band 1)
            ContainerIndexed = [bool]($flags -band 2)
            ANR              = [bool]($flags -band 4)
            PreserveOnDelete = [bool]($flags -band 8)
            CopyOnCopy       = [bool]($flags -band 16)
            TupleIndexed     = [bool]($flags -band 32)
            SubtreeIndexed   = [bool]($flags -band 64)
            Confidential     = [bool]($flags -band 128)
            NeverAudit       = [bool]($flags -band 256)
            RodcFiltered     = [bool]($flags -band 512)
        }
    }
}
