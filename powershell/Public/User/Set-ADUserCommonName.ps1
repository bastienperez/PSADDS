<#
    .SYNOPSIS
    Set the common name (CN) of an Active Directory user to a consistent "GivenName Surname" format (or reversed).

    .DESCRIPTION
    Renames the AD user object so its CN (the relative distinguished name) matches the user's GivenName and
    Surname, in the chosen order. Useful to homogenize the CN across a directory where objects were created
    with inconsistent naming conventions.

    Only the CN (object name) is changed. The sAMAccountName, userPrincipalName, DisplayName and other
    attributes are left untouched. Supports -WhatIf and -Confirm.

    Requires the ActiveDirectory module (RSAT) and rights to rename the target objects.

    .PARAMETER Identity
    One or more AD users (sAMAccountName, distinguishedName, GUID or SID). Accepts pipeline input,
    including objects piped from Get-ADUser.

    .PARAMETER NameOrder
    Order used to build the CN:
    - 'GivenNameSurname' (default) -> "John Doe"
    - 'SurnameGivenName'           -> "Doe John"

    .PARAMETER Separator
    String placed between the given name and the surname. Default is a single space.

    .PARAMETER Server
    Optional domain controller to target.

    .PARAMETER GenerateCmdlets
    When specified, generates the equivalent Rename-ADObject commands and saves them to a file instead of executing them.

    .PARAMETER OutputFile
    Path to the output file where generated commands are saved.
    Default: a timestamped .ps1 file in the current directory.

    .EXAMPLE
    Set-ADUserCommonName -Identity jdoe

    Renames the CN of jdoe to "GivenName Surname".

    .EXAMPLE
    Get-ADUser -Filter * -SearchBase 'OU=Users,DC=contoso,DC=com' | Set-ADUserCommonName -NameOrder SurnameGivenName -WhatIf

    Previews renaming every user in the OU so the CN becomes "Surname GivenName".

    .EXAMPLE
    Get-ADUser -Filter * -SearchBase 'OU=Users,DC=contoso,DC=com' | Set-ADUserCommonName -GenerateCmdlets -OutputFile 'C:\Temp\rename-commands.ps1'

    Generates the Rename-ADObject commands for every user in the OU and saves them to the specified file without executing them.

    .EXAMPLE
    Get-ADUser -Filter { EmployeeID -like '*' } -Properties EmployeeID | Set-ADUserCommonName

    Renames the CN of all users who have a non-empty EmployeeID.

    .LINK
    https://github.com/bastienperez/PSADDS
#>

function Set-ADUserCommonName {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('SamAccountName', 'DistinguishedName', 'ObjectGUID')]
        [Object[]]$Identity,

        [Parameter(Mandatory = $false)]
        [ValidateSet('GivenNameSurname', 'SurnameGivenName')]
        [String]$NameOrder = 'GivenNameSurname',

        [Parameter(Mandatory = $false)]
        [String]$Separator = ' ',

        [Parameter(Mandatory = $false)]
        [String]$Server,

        [Parameter(Mandatory = $false)]
        [switch]$GenerateCmdlets,

        [Parameter(Mandatory = $false)]
        [String]$OutputFile = "$(Get-Date -Format 'yyyy-MM-dd_HHmmss')-SetADUserCommonName-Commands.ps1"
    )

    begin {
        if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
            throw 'The ActiveDirectory module is required (RSAT). Import it and try again.'
        }

        # Forward an optional -Server to every AD call via splatting.
        $adParams = @{}
        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $adParams['Server'] = $Server
        }

        $commands = @()
    }

    process {
        foreach ($id in $Identity) {
            try {
                $resolvedId = if ($id -is [Microsoft.ActiveDirectory.Management.ADUser]) { $id.DistinguishedName } else { [string]$id }
                $user = Get-ADUser -Identity $resolvedId -Properties GivenName, Surname @adParams -ErrorAction Stop
            }
            catch {
                Write-Warning "[!] Cannot find AD user '$id'. $($_.Exception.Message)"
                continue
            }

            $givenName = $user.GivenName
            $surname = $user.Surname

            if (([string]::IsNullOrWhiteSpace($givenName)) -or ([string]::IsNullOrWhiteSpace($surname))) {
                Write-Warning "[*] '$($user.SamAccountName)' is missing GivenName or Surname, skipping."
                continue
            }

            if ($NameOrder -eq 'SurnameGivenName') {
                $newCN = "$surname$Separator$givenName"
            }
            else {
                $newCN = "$givenName$Separator$surname"
            }

            # $user.Name is the RDN (the CN value for a user object).
            if ($user.Name -ceq $newCN) {
                Write-Verbose "[i] '$($user.SamAccountName)' CN is already '$newCN', skipping."
                continue
            }

            if ($GenerateCmdlets) {
                $serverParam = if ($adParams.ContainsKey('Server')) { " -Server '$($adParams['Server'])'" } else { '' }
                $commands += "Rename-ADObject -Identity `"$($user.DistinguishedName)`" -NewName `"$newCN`"$serverParam"
            }
            elseif ($PSCmdlet.ShouldProcess($user.DistinguishedName, "Rename CN to '$newCN'")) {
                try {
                    Rename-ADObject -Identity $user.DistinguishedName -NewName $newCN @adParams -ErrorAction Stop
                    Write-Host -ForegroundColor Green "[OK] '$($user.SamAccountName)' CN set to '$newCN'"
                }
                catch {
                    Write-Warning "[!] Failed to rename '$($user.SamAccountName)' to '$newCN'. $($_.Exception.Message)"
                }
            }
        }
    }

    end {
        if ($GenerateCmdlets -and $commands -and $commands.Count -gt 0) {
            $commands | Out-File -FilePath $OutputFile -Encoding UTF8
            $fullPath = (Get-Item -LiteralPath $OutputFile).FullName
            Write-Host -ForegroundColor Cyan "[i] Commands generated in file: $fullPath"
        }
    }
}
