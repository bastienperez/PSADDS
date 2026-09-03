<#
    .SYNOPSIS
    Get the password state of Active Directory users, together with the password policy that actually applies to them.

    .DESCRIPTION
    For each user, resolves the effective password policy (the default domain policy, or the Fine Grained Password
    Policy / PSO that wins over it) and reports the password expiration date computed by the domain controller
    through msDS-UserPasswordExpiryTimeComputed, plus the lockout settings and the bad password counters.

    The special cases that make a raw msDS-UserPasswordExpiryTimeComputed misleading are handled explicitly:
    a password flagged "must change at next logon" (pwdLastSet = 0), an account with PasswordNeverExpires, a
    domain with no maximum password age, and an account with PasswordNotRequired, which lets the user bypass
    any policy and set an empty password.

    Queries the PDC emulator by default: it is the only domain controller holding an up to date value for
    badPwdCount and lockout state.

    Requires the ActiveDirectory module (RSAT).

    .PARAMETER Identity
    One or more users. Like Get-ADUser, accepts a distinguished name (DN), a GUID, a security identifier (SID),
    a SAM account name, a user object variable, or a user object piped in (from Get-ADUser, Get-ADGroupMember,
    and so on). When omitted, every user of the domain is processed.

    .PARAMETER Server
    Domain controller to query. Defaults to the PDC emulator of the current domain.

    .PARAMETER SimulatedMaxPasswordAgeDays
    Simulates a different maximum password age, in days, and adds SimulatedPasswordExpirationDateUTC and
    SimulatedPasswordExpired to the output. Useful to measure the impact of a policy change before applying it.

    .EXAMPLE
    Get-ADUserPasswordInfo

    Reports the password state of every user of the domain.

    .EXAMPLE
    Get-ADUserPasswordInfo -Identity 'jdoe', 'asmith'

    Reports the password state of two users, resolved by their sAMAccountName.

    .EXAMPLE
    Get-ADUserPasswordInfo -Identity 'CN=John Doe,OU=Users,DC=contoso,DC=com'

    Reports the password state of a single user, resolved by its distinguished name.

    .EXAMPLE
    Get-ADGroupMember -Identity 'Helpdesk' | Get-ADUserPasswordInfo

    Reports the password state of every member of the 'Helpdesk' group, piped in as user objects.

    .EXAMPLE
    Get-ADUserPasswordInfo -SimulatedMaxPasswordAgeDays 180 | Where-Object SimulatedPasswordExpired

    Lists the users whose password would already be expired if the maximum password age was set to 180 days.

    .EXAMPLE
    Get-ADUserPasswordInfo | Export-Excel -Path 'C:\temp\PasswordInfo.xlsx' -AutoSize -FreezeTopRow -TableStyle Light9

    Exports the report to an .xlsx file. Requires the ImportExcel module (not a dependency of PSADDS, install it
    separately with 'Install-Module ImportExcel' if needed).

    .EXAMPLE
    $report = Get-ADUserPasswordInfo
    $path = 'C:\temp\PasswordInfo.xlsx'

    $report | Export-Excel -Path $path -WorksheetName 'Users' -AutoSize -FreezeTopRow -TableStyle Light9

    [PSCustomObject][ordered]@{
        TotalUsers           = $report.Count
        Enabled              = ($report | Where-Object Enabled).Count
        Disabled             = ($report | Where-Object { -not $_.Enabled }).Count
        PasswordExpired      = ($report | Where-Object PasswordExpired).Count
        PasswordNeverExpires = ($report | Where-Object PasswordNeverExpires).Count
        CannotChangePassword = ($report | Where-Object CannotChangePassword).Count
        NeverLoggedIn        = ($report | Where-Object { $_.LastLogonDate -eq 'Never logged in' }).Count
    } | Export-Excel -Path $path -WorksheetName 'Stats' -AutoSize -TableStyle Light9

    Adds a second worksheet with a few counts, alongside the raw data. Both calls target the same file and
    default to appending a new worksheet rather than overwriting the workbook.

    .LINK
    https://github.com/bastienperez/PSADDS
#>
function Get-ADUserPasswordInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('SamAccountName', 'DistinguishedName', 'ObjectGUID', 'SID')]
        [object[]]$Identity,

        [Parameter(Mandatory = $false)]
        [Alias('DomainController')]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$SimulatedMaxPasswordAgeDays
    )

    begin {
        [System.Collections.Generic.List[PSObject]]$passwordSettingsByUser = @()
        [System.Collections.Generic.List[PSObject]]$usersFound = @()
        $anyIdentityGiven = $false

        # Some calculated properties of Get-ADUser, 'Enabled' and 'CannotChangePassword' among them, come back
        # empty in a non elevated PowerShell session, most commonly seen when running directly on a domain
        # controller. This is a known ActiveDirectory module quirk, not something the function can work around.
        $isElevated = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

        if (-not $isElevated) {
            Write-Warning "[!] PowerShell is not running as administrator. 'Enabled', 'CannotChangePassword' and possibly other properties may come back empty. Re-run this from an elevated session if the results look incomplete."
        }

        if (-not $Server) {
            # the PDC emulator is the only DC holding an up to date badPwdCount and lockout state
            $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $Server = $domain.PdcRoleOwner.Name
            Write-Verbose "For accurate results, the domain controller with the PDC emulator role will be used: $Server"
        }

        $defautPasswordPolicyObject = Get-ADDefaultDomainPasswordPolicy -Server $Server
        $defautPasswordPolicyDays = $defautPasswordPolicyObject.MaxPasswordAge.Days

        # Get-ADUserResultantPasswordPolicy is one LDAP call per user: skip it entirely when the domain has no PSO
        $fineGrainedPasswordPolicyExists = [bool](Get-ADFineGrainedPasswordPolicy -Filter * -Server $Server -ErrorAction SilentlyContinue)

        if (-not $fineGrainedPasswordPolicyExists) {
            Write-Verbose 'No Fine Grained Password Policy in this domain, the default domain password policy applies to every user'
        }

        $attributes = 'DisplayName', 'msDS-UserPasswordExpiryTimeComputed', 'PasswordNeverExpires', 'pwdLastSet', 'Enabled', 'badPwdCount', 'badPasswordTime', 'LastLogonDate', 'PasswordNotRequired', 'CannotChangePassword', 'mail', 'UserPrincipalName'
    }

    process {
        if ($Identity) {
            $anyIdentityGiven = $true

            foreach ($id in $Identity) {
                # A user object piped in (Get-ADUser, Get-ADGroupMember, ...) is resolved by its DistinguishedName
                $resolvedId = if ($id -is [Microsoft.ActiveDirectory.Management.ADUser]) { $id.DistinguishedName } else { [string]$id }

                Write-Verbose "Processing user: $resolvedId"
                try {
                    $u = Get-ADUser -Identity $resolvedId -Properties $attributes -ErrorAction Stop -Server $Server
                }
                catch {
                    Write-Warning "$($_.Exception.Message)"
                    continue
                }

                $usersFound.Add($u)
            }
        }
    }

    end {
        if (-not $anyIdentityGiven) {
            Write-Verbose 'Processing all users'
            try {
                $usersFound = Get-ADUser -Filter * -Properties $attributes -ErrorAction Stop -Server $Server
            }
            catch {
                Write-Warning "$($_.Exception.Message)"
                return
            }
        }

    $i = 0
    foreach ($user in $usersFound) {
        $i++
        Write-Verbose "Processing user $i/$($usersFound.Count): $($user.SamAccountName)"
        $policy = $null
        $passwordPolicyMaxPasswordAge = $null

        if ($fineGrainedPasswordPolicyExists) {
            Write-Verbose "Getting resultant password policy for $($user.SamAccountName)"
            $fineGrainedPassword = Get-ADUserResultantPasswordPolicy -Identity $user.SamAccountName -Server $Server
        }
        else {
            $fineGrainedPassword = $null
        }

        switch ($fineGrainedPassword.Name) {
            $null {
                $policy = 'GPO or domain settings'
                $passwordPolicyMaxPasswordAge = $defautPasswordPolicyDays
                $lockoutDuration = $defautPasswordPolicyObject.LockoutDuration
                $lockoutObservationWindow = $defautPasswordPolicyObject.LockoutObservationWindow
                $lockoutThreshold = $defautPasswordPolicyObject.LockoutThreshold
                $passwordMinimumLength = $defautPasswordPolicyObject.MinPasswordLength
                $passwordComplexityEnabled = $defautPasswordPolicyObject.ComplexityEnabled
                $passwordHistoryCount = $defautPasswordPolicyObject.PasswordHistoryCount
                break
            }
            default {
                $policy = $fineGrainedPassword.Name + ' (Fine Grained Password)'
                $passwordPolicyMaxPasswordAge = $fineGrainedPassword.MaxPasswordAge.Days
                $lockoutDuration = $fineGrainedPassword.LockoutDuration
                $lockoutObservationWindow = $fineGrainedPassword.LockoutObservationWindow
                $lockoutThreshold = $fineGrainedPassword.LockoutThreshold
                $passwordMinimumLength = $fineGrainedPassword.MinPasswordLength
                $passwordComplexityEnabled = $fineGrainedPassword.ComplexityEnabled
                $passwordHistoryCount = $fineGrainedPassword.PasswordHistoryCount
                break
            }
        }

        if ($user.PasswordNotRequired) {
            $policy = 'None - User has "PasswordNotRequired" flag set. This setting allows a user in AD to bypass any password policy and set a blank password if they want to.'
        }

        if ($user.pwdLastSet -eq 0) {
            $pwdLastSet = $null
        }
        else {
            $convertedDate = [datetime]::FromFileTime($user.pwdLastSet).ToUniversalTime()
            if ($convertedDate -eq [datetime]::new(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)) {
                $pwdLastSet = $null
            }
            else {
                $pwdLastSet = $convertedDate
            }
        }

        if ($user.PasswordNeverExpires) {
            # Takes priority over msDS-UserPasswordExpiryTimeComputed, which is 0 (not "never") when the
            # account never had a password set, for instance a never logged in account.
            $expirationDate = "Never (configured as 'Never expires')"
            $daysLeft = '-'
        }
        elseif ($user.'msDS-UserPasswordExpiryTimeComputed' -eq 9223372036854775807) {
            $expirationDate = 'Never (no password policy in GPO or never set)'
            $daysLeft = '-'
        }
        elseif ($user.'msDS-UserPasswordExpiryTimeComputed' -eq 0) {
            if ($defautPasswordPolicyDays -eq 0) {
                $expirationDate = 'Never (no password policy in GPO)'
            }
            else {
                $expirationDate = "Password is set to be changed at 'next logon' so no way to calculate the password expiration date"
            }

            $daysLeft = '-'
        }
        else {
            $expirationDate = $([datetime]::FromFileTime($user.'msDS-UserPasswordExpiryTimeComputed').ToUniversalTime())

            if ($expirationDate -eq [datetime]::new(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)) {
                $expirationDate = $null
                $daysLeft = '-'
            }
            else {
                $daysLeft = New-TimeSpan (Get-Date).ToUniversalTime() $expirationDate

                if ($daysLeft -le 0 -and $null -ne $daysLeft) {
                    $daysLeft = 'Already expired'
                }
                else {
                    $daysLeft = $daysLeft.Days
                }
            }
        }

        if ($SimulatedMaxPasswordAgeDays -and $user.pwdLastSet -and $pwdLastSet -ne [datetime]::new(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)) {
            # Calculate simulated password expiration if SimulatedMaxPasswordAgeDays is provided
            $simulatedPasswordExpirationDateUTC = $null
            $simulatedPasswordExpired = $false
            $simulatedPasswordExpirationDateUTC = $pwdLastSet.AddDays($SimulatedMaxPasswordAgeDays)
            if ($pwdLastSet -lt (Get-Date).AddDays(-$SimulatedMaxPasswordAgeDays)) {
                $simulatedPasswordExpired = $true
            }
        }

        $object = [PSCustomObject][ordered]@{
            Identity                        = $user.SamAccountName
            DisplayName                     = $user.DisplayName
            Enabled                         = $user.Enabled
            PasswordNeverExpires            = $user.PasswordNeverExpires
            CannotChangePassword            = $user.CannotChangePassword
            UserPrincipalName               = $user.UserPrincipalName
            Mail                            = $user.mail
            PasswordLastSetUTCTime          = $pwdLastSet
            PasswordPolicy                  = $policy
            PasswordPolicyMaxPasswordAge    = $passwordPolicyMaxPasswordAge
            PasswordMinimumLength           = $passwordMinimumLength
            PasswordHistoryCount            = $passwordHistoryCount
            PasswordComplexityEnabled       = $passwordComplexityEnabled
            PasswordExpirationDateUTC       = $expirationDate
            DaysLeftBeforePasswordChangeUTC = $daysLeft
            PasswordExpired                 = if ($daysLeft -eq 'Already expired') { $true } else { $false }
            LockoutDuration                 = $lockoutDuration
            LockoutObservationWindow        = $lockoutObservationWindow
            LockoutThreshold                = $lockoutThreshold
            LastLogonDate                   = if ($user.LastLogonDate) { $user.LastLogonDate } else { 'Never logged in' }
            BadPwdCount                     = $user.BadPwdCount
            BadPasswordTime                 = if ($user.BadPasswordTime -eq 0 -or [datetime]::FromFileTimeUTC($user.BadPasswordTime) -eq [datetime]::new(1601, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)) { $null } else { [datetime]::FromFileTimeUTC($user.BadPasswordTime) }
            FromDomainController            = $Server
            DistinguishedName               = $user.DistinguishedName
        }

        if ($SimulatedMaxPasswordAgeDays) {
            $object | Add-Member -MemberType NoteProperty -Name 'SimulatedPasswordExpirationDateUTC' -Value $simulatedPasswordExpirationDateUTC
            $object | Add-Member -MemberType NoteProperty -Name 'SimulatedPasswordExpired' -Value $simulatedPasswordExpired
        }

        $passwordSettingsByUser.Add($object)
    }

        $passwordSettingsByUser | Sort-Object PasswordExpirationDate* -Descending
    }
}
