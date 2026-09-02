<#
    .SYNOPSIS
    Converts a replication metadata timestamp into a DateTime, or into $null when the timestamp means "never".

    .DESCRIPTION
    The ftimeCreated, ftimeDeleted and ftimeLastOriginatingChange fields of the replication metadata are strings.
    Returning them as they are makes any sort or date comparison a string comparison, and a value that was never
    set is reported as 1601-01-01, the zero of a Windows FILETIME, instead of being empty.

    Internal helper.

    .PARAMETER Timestamp
    The raw string read from a replication metadata node.

    .OUTPUTS
    System.DateTime, or $null when the timestamp is empty or equal to the FILETIME zero.
#>
function ConvertTo-ADReplMetadataDate {
    [CmdletBinding()]
    [OutputType([datetime])]
    param (
        [Parameter(Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Timestamp
    )

    if ([string]::IsNullOrWhiteSpace($Timestamp)) {
        return $null
    }

    try {
        $date = [datetime]::Parse($Timestamp, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
    }
    catch {
        Write-Verbose "Unable to convert the replication metadata timestamp '$Timestamp' into a date"
        return $null
    }

    # 1601-01-01 is the zero of a Windows FILETIME: the value was never set
    if ($date -eq [datetime]::new(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)) {
        return $null
    }

    return $date
}
