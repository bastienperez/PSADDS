<#
    .SYNOPSIS
    Lists the members of a group using the WinNT ADSI provider.

    .DESCRIPTION
    Reads group membership through the WinNT ADSI provider, without requiring the ActiveDirectory module
    (RSAT). This provider is suitable for groups exposed through WinNT:// paths.

    .PARAMETER Identity
    The WinNT ADSI path of the group, for example 'WinNT://CONTOSO/Helpdesk'.

    .EXAMPLE
    Get-ADGroupMemberWinNT -Identity 'WinNT://CONTOSO/Helpdesk'

    Lists the names of the members of the Helpdesk group.

    .LINK
    https://github.com/bastienperez/PSADDS
#>
function Get-ADGroupMemberWinNT {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('GroupPath')]
        [string]$Identity
    )

    process {
        $group = [ADSI]$Identity

        foreach ($member in $group.Invoke('Members')) {
            $member.GetType().InvokeMember('Name', 'GetProperty', $null, $member, $null)
        }
    }
}
