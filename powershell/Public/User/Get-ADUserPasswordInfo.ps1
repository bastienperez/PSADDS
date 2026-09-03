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

    .PARAMETER SamAccountName
    One or more sAMAccountNames. When omitted, every user of the domain is processed.

    .PARAMETER Server
    Domain controller to query. Defaults to the PDC emulator of the current domain.

    .PARAMETER SimulatedMaxPasswordAgeDays
    Simulates a different maximum password age, in days, and adds SimulatedPasswordExpirationDateUTC and
    SimulatedPasswordExpired to the output. Useful to measure the impact of a policy change before applying it.

    .EXAMPLE
    Get-ADUserPasswordInfo

    Reports the password state of every user of the domain.

    .EXAMPLE
    Get-ADUserPasswordInfo -SamAccountName 'jdoe', 'asmith'

    Reports the password state of two users only.

    .EXAMPLE
    Get-ADUserPasswordInfo -SimulatedMaxPasswordAgeDays 180 | Where-Object SimulatedPasswordExpired

    Lists the users whose password would already be expired if the maximum password age was set to 180 days.

    .LINK
    https://github.com/bastienperez/PSADDS
#>
function Get-ADUserPasswordInfo {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0)]
        [string[]]$SamAccountName,

        [Parameter(Mandatory = $false)]
        [Alias('DomainController')]
        [string]$Server,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$SimulatedMaxPasswordAgeDays
    )

    [System.Collections.Generic.List[PSObject]]$passwordSettingsByUser = @()

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

    if ($SamAccountName) {
        [System.Collections.Generic.List[PSObject]]$users = @()

        foreach ($sam in $SamAccountName) {
            Write-Verbose "Processing user: $sam"
            try {
                $u = Get-ADUser -Identity $sam -Properties $attributes -ErrorAction Stop -Server $Server
            }
            catch {
                Write-Warning "$($_.Exception.Message)"
                return
            }

            $users.Add($u)
        }
    }
    else {
        Write-Verbose 'Processing all users'
        try {
            $users = Get-ADUser -Filter * -Properties $attributes -ErrorAction Stop -Server $Server
        }
        catch {
            Write-Warning "$($_.Exception.Message)"
            return
        }
    }

    $i = 0
    foreach ($user in $users) {
        $i++
        Write-Verbose "Processing user $i/$($users.Count): $($user.SamAccountName)"
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
