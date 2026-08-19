<#
    .SYNOPSIS
    Restores the default owner and/or the default permissions of one or more computer accounts.

    .DESCRIPTION
    When a computer account is created through a delegation, the object owner becomes the account
    that created it, and specific ACE are granted to that same account. The mS-DS-CreatorSID
    attribute is also populated with the creator SID when ms-DS-MachineAccountQuota is not 0.

    Depending on the Scope parameter, this function resets the owner to the Domain Admins group,
    replaces the discretionary access control list with the default one defined in the schema for
    the computer class, or both.

    Resetting the permissions removes every explicit ACE from the object, including tier model
    delegations applied directly on the computer account. ACE inherited from the parent
    organizational unit are not stored on the object and are therefore preserved, unless
    inheritance is blocked on that object.

    Use Get-ADComputerJoinedByUser to find the computers that need to be remediated, its output can
    be piped directly to this function.

    .PARAMETER Identity
    Name, SamAccountName, distinguishedName, GUID or SID of the computer accounts to clean up.

    .PARAMETER Scope
    Part of the security descriptor to reset:
        Owner       Only the object owner.
        Permissions Only the discretionary access control list.
        All         Both, the permissions first, then the owner. This is the default value.

    .PARAMETER Owner
    Account or group to set as the new owner, in DOMAIN\Name or Name format.
    Defaults to the Domain Admins group of the target domain. Ignored when Scope is Permissions.

    .PARAMETER Server
    Domain controller or domain to query. Defaults to the one selected by the ActiveDirectory module.

    .PARAMETER EventLogSource
    Name of the event log source used to trace the operations in the Application log.
    Defaults to 'Reset-ADComputerAccountSecurity'. Set it to an empty string to disable event logging.

    .PARAMETER Force
    Applies the reset without comparing the current state to the expected one. By default, the
    owner is compared by SID and the explicit ACE are compared to the schema default ones, and the
    write is skipped when the object is already compliant.

    .PARAMETER Simulation
    Runs in read-only mode: targets are resolved and every action is reported, but no change is
    written to Active Directory and no entry is written to the event log.

    .INPUTS
    System.String. Computer identities can be piped to this function.

    .OUTPUTS
    System.Management.Automation.PSCustomObject. One result object per processed computer, with a
    cumulative ResultCode property:
        0   Success, or nothing to do
        1   Owner could not be modified
        10  Computer could not be read
        100 Permissions could not be reset

    .EXAMPLE
    Reset-ADComputerAccountSecurity -Identity 'SRV-APP01' -Scope Owner

    Resets only the owner of the SRV-APP01 computer account, leaving the permissions untouched.

    .EXAMPLE
    Reset-ADComputerAccountSecurity -Identity 'SRV-APP01' -Scope Permissions -Simulation -Verbose

    Reports the permission changes that would be applied, without modifying anything.

    .EXAMPLE
    Get-ADComputer -Filter { Name -like 'SRV-*' } |
        Reset-ADComputerAccountSecurity -Scope All |
        Where-Object -FilterScript { $_.ResultCode -ne 0 }

    Processes several computers and returns only the failures.

    .EXAMPLE
    $domainSID = (Get-ADDomain).DomainSID.Value
    Get-ADComputerJoinedByUser -SearchBy Owner |
        Where-Object { $_.OwnerSID.Value -notin @("$domainSID-512", 'S-1-5-32-544') } |
        Reset-ADComputerAccountSecurity -Scope Owner

    Audits the domain and resets the owner of every computer still owned by the account that created it.

    .NOTES
    Credits:
        https://blog.piservices.fr/post/2021/03/29/powershell-who-s-owner-of-my-ad-object
        https://blog.piservices.fr/post/2021/04/12/powershell-change-the-owner-of-my-ad-objects
#>

function Reset-ADComputerAccountSecurity {

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([PSCustomObject])]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('Name', 'SamAccountName', 'DistinguishedName')]
        [String[]]
        $Identity,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet('All', 'Owner', 'Permissions')]
        [String]
        $Scope = 'All',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Owner,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Server,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [String]
        $EventLogSource = 'Reset-ADComputerAccountSecurity',

        [Parameter(Mandatory = $false)]
        [Switch]
        $Force,

        [Parameter(Mandatory = $false)]
        [Alias('DryRun')]
        [Switch]
        $Simulation
    )

    begin {
        Set-StrictMode -Version Latest

        # Common parameters forwarded to every ActiveDirectory cmdlet call.
        $adParameters = @{ ErrorAction = 'Stop' }
        if ($PSBoundParameters.ContainsKey('Server')) {
            $adParameters.Add('Server', $Server)
        }

        $isSimulation      = $Simulation.IsPresent
        $isForced          = $Force.IsPresent
        $isLogEnabled      = -not [String]::IsNullOrWhiteSpace($EventLogSource)
        $isOwnerInScope    = $Scope -in @('All', 'Owner')
        $arePermsInScope   = $Scope -in @('All', 'Permissions')

        function Get-DaclFingerprint {
            <#
                .SYNOPSIS
                Builds a comparable signature of the explicit ACE of a security descriptor.

                .DESCRIPTION
                Inherited ACE are excluded, identities are expressed as SID and entries are sorted,
                so that two descriptors carrying the same explicit permissions in a different order
                produce the same signature.
            #>
            [CmdletBinding()]
            [OutputType([String])]
            Param(
                [Parameter(Mandatory = $true)]
                [System.DirectoryServices.ActiveDirectorySecurity]
                $SecurityDescriptor
            )

            $accessRules = $SecurityDescriptor.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier])

            $entries = foreach ($accessRule in $accessRules) {
                '{0}|{1}|{2}|{3}|{4}|{5}|{6}' -f $accessRule.IdentityReference.Value,
                                                 $accessRule.AccessControlType,
                                                 [Int]$accessRule.ActiveDirectoryRights,
                                                 $accessRule.ObjectType,
                                                 $accessRule.InheritedObjectType,
                                                 $accessRule.InheritanceType,
                                                 $accessRule.PropagationFlags
            }

            return (($entries | Sort-Object) -join "`n")
        }

        function Write-OperationLog {
            <#
                .SYNOPSIS
                Writes an entry to the Application event log, ignoring any logging failure.
            #>
            [CmdletBinding()]
            Param(
                [Parameter(Mandatory = $true)]
                [String]
                $Message,

                [Parameter(Mandatory = $false)]
                [System.Diagnostics.EventLogEntryType]
                $EntryType = [System.Diagnostics.EventLogEntryType]::SuccessAudit,

                [Parameter(Mandatory = $false)]
                [Int]
                $EventId = 0
            )

            if (-not $isLogEnabled) {
                return
            }

            if ($isSimulation) {
                Write-Verbose -Message "[SIMULATION] Event log entry skipped: $Message"
                return
            }

            try {
                Write-EventLog -LogName 'Application' -Source $EventLogSource -EntryType $EntryType -EventId $EventId -Category 0 -Message $Message
            } catch {
                Write-Warning -Message "Unable to write to the event log: $($_.Exception.Message)"
            }
        }

        if ($isSimulation) {
            Write-Warning -Message 'Simulation mode enabled: no change will be applied.'
        }

        # Register the event log source when missing (requires local administrative rights). Nothing is
        # written in simulation mode, so the event log is left alone entirely.
        if ($isLogEnabled -and -not $isSimulation) {

            # [System.Diagnostics.EventLog]::SourceExists() enumerates every event log, including Security,
            # which a standard user cannot read: it throws instead of answering. Looking the source up in the
            # registry gives the same answer without any privilege.
            $isSourceRegistered = $false
            $eventLogRootPath   = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog'

            foreach ($logKey in (Get-ChildItem -LiteralPath $eventLogRootPath -ErrorAction SilentlyContinue)) {
                if (Test-Path -LiteralPath (Join-Path -Path $logKey.PSPath -ChildPath $EventLogSource)) {
                    $isSourceRegistered = $true
                    break
                }
            }

            if (-not $isSourceRegistered) {
                try {
                    New-EventLog -LogName 'Application' -Source $EventLogSource -ErrorAction Stop
                    Write-Verbose -Message "Event log source '$EventLogSource' created in the Application log."
                } catch {
                    # Every later Write-EventLog would fail the same way, disable the tracing once and for all.
                    $isLogEnabled = $false
                    Write-Warning -Message "Unable to register the event log source '$EventLogSource', event log tracing is disabled for this run. Creating a source requires local administrative rights: $($_.Exception.Message)"
                }
            }
        }

        $domain = Get-ADDomain @adParameters

        # Resolve the target owner: Domain Admins of the target domain unless overridden.
        if ($isOwnerInScope) {
            if ($PSBoundParameters.ContainsKey('Owner')) {
                $targetOwner = $Owner
            } else {
                $targetOwner = '{0}\{1}' -f $domain.NetBIOSName, (Get-ADGroup -Identity ('{0}-512' -f $domain.DomainSID.Value) @adParameters).Name
            }

            # Fail fast when the owner cannot be translated into a SID.
            $targetOwnerAccount = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $targetOwner
            $targetOwnerSid     = $targetOwnerAccount.Translate([System.Security.Principal.SecurityIdentifier])

            Write-Verbose -Message "New owner resolved to '$targetOwner' ($($targetOwnerSid.Value))."
        } else {
            $targetOwner = $null
        }

        # Retrieve the default security descriptor of the computer class from the schema.
        if ($arePermsInScope) {
            $schemaNamingContext       = (Get-ADRootDSE @adParameters).schemaNamingContext
            $defaultSecurityDescriptor = Get-ADObject -Identity "CN=Computer,$schemaNamingContext" -Properties 'defaultSecurityDescriptor' @adParameters |
                                            Select-Object -ExpandProperty 'defaultSecurityDescriptor'

            # Reference signature used to detect objects already carrying the default permissions.
            $referenceDescriptor = New-Object -TypeName System.DirectoryServices.ActiveDirectorySecurity
            $referenceDescriptor.SetSecurityDescriptorSddlForm($defaultSecurityDescriptor, [System.Security.AccessControl.AccessControlSections]::Access)
            $referenceFingerprint = Get-DaclFingerprint -SecurityDescriptor $referenceDescriptor

            Write-Warning -Message 'Permissions are in scope: every explicit ACE set on the target objects will be removed.'
        }
    }

    process {
        foreach ($computerIdentity in $Identity) {

            # Retrieve the target computer account.
            try {
                $computerAccount = Get-ADComputer -Identity $computerIdentity -Properties 'nTSecurityDescriptor' @adParameters
            } catch {
                Write-OperationLog -Message "The computer '$computerIdentity' could not be retrieved from Active Directory." -EntryType Error -EventId 10
                Write-Error -Message "The computer '$computerIdentity' could not be retrieved: $($_.Exception.Message)" -ErrorAction Continue

                [PSCustomObject]@{
                    PSTypeName        = 'ComputerAccountSecurityResult'
                    Identity          = $computerIdentity
                    DistinguishedName = $null
                    Scope             = $Scope
                    PreviousOwner     = $null
                    NewOwner          = $targetOwner
                    OwnerCompliant    = $null
                    PermsCompliant    = $null
                    OwnerReset        = $false
                    PermissionsReset  = $false
                    Simulation        = $isSimulation
                    ResultCode        = 10
                }

                continue
            }

            $resultCode        = 0
            $isOwnerReset      = $false
            $arePermsReset     = $false
            $isOwnerCompliant  = $null
            $arePermsCompliant = $null
            $samAccountName    = $computerAccount.SamAccountName
            $distinguishedName = $computerAccount.DistinguishedName

            # Read the current owner once, as a SID and as an account name.
            $currentOwner    = Resolve-ADObjectOwner -SecurityDescriptor $computerAccount.nTSecurityDescriptor
            $currentOwnerSid = if ($null -ne $currentOwner) { $currentOwner.OwnerSID } else { $null }
            $previousOwner   = if ($null -ne $currentOwner) { $currentOwner.OwnerName } else { $null }

            # Reset the permissions first, so that the owner is applied last and cannot be overwritten.
            if ($arePermsInScope) {
                $currentFingerprint  = Get-DaclFingerprint -SecurityDescriptor $computerAccount.nTSecurityDescriptor
                $arePermsCompliant   = $currentFingerprint -eq $referenceFingerprint

                if ($arePermsCompliant -and -not $isForced) {
                    Write-Verbose -Message "Permissions of '$samAccountName' already match the schema default value, nothing to do."
                } elseif ($isSimulation) {
                    Write-Verbose -Message "[SIMULATION] '$distinguishedName': permissions would be replaced by the schema default value."
                    Write-Verbose -Message "[SIMULATION] Current DACL: $($computerAccount.nTSecurityDescriptor.GetSecurityDescriptorSddlForm('Access'))"
                    Write-Verbose -Message "[SIMULATION] Default SDDL: $defaultSecurityDescriptor"
                } elseif ($PSCmdlet.ShouldProcess($distinguishedName, 'Reset permissions to the schema default value')) {
                    try {
                        # Only the Access section is replaced, the owner and the audit entries are left as is.
                        $computerAccount.nTSecurityDescriptor.SetSecurityDescriptorSddlForm($defaultSecurityDescriptor, [System.Security.AccessControl.AccessControlSections]::Access)
                        Set-ADObject -Identity $distinguishedName -Replace @{ nTSecurityDescriptor = $computerAccount.nTSecurityDescriptor } -Confirm:$false @adParameters

                        $arePermsReset = $true
                        Write-OperationLog -Message "The computer '$samAccountName' permissions have been reset to their default value."
                        Write-Verbose -Message "Permissions of '$samAccountName' reset to their default value."
                    } catch {
                        $resultCode += 100
                        Write-OperationLog -Message "The computer '$samAccountName' permissions could not be reset." -EntryType FailureAudit -EventId 100
                        Write-Error -Message "Permissions of '$samAccountName' could not be reset: $($_.Exception.Message)" -ErrorAction Continue
                    }
                }
            }

            # Reset the object owner.
            if ($isOwnerInScope) {
                # The owner is compared by SID, the name form being unreliable for unresolvable principals.
                $isOwnerCompliant  = ($null -ne $currentOwnerSid) -and ($currentOwnerSid.Value -eq $targetOwnerSid.Value)

                if ($isOwnerCompliant -and -not $isForced) {
                    Write-Verbose -Message "Owner of '$samAccountName' is already '$targetOwner', nothing to do."
                } elseif ($isSimulation) {
                    Write-Verbose -Message "[SIMULATION] '$distinguishedName': owner would be changed from '$previousOwner' to '$targetOwner'."
                } elseif ($PSCmdlet.ShouldProcess($distinguishedName, "Set owner to '$targetOwner'")) {
                    $directoryEntry = $null
                    try {
                        $directoryEntry = [ADSI]"LDAP://$distinguishedName"

                        $directoryEntry.PSBase.ObjectSecurity.SetOwner($targetOwnerAccount)
                        $directoryEntry.PSBase.CommitChanges()

                        $isOwnerReset = $true
                        Write-OperationLog -Message "The computer '$samAccountName' owner has been changed from '$previousOwner' to '$targetOwner'."
                        Write-Verbose -Message "Owner of '$samAccountName' set to '$targetOwner'."
                    } catch {
                        $resultCode += 1
                        Write-OperationLog -Message "The computer '$samAccountName' owner could not be modified to '$targetOwner'." -EntryType FailureAudit -EventId 1
                        Write-Error -Message "Owner of '$samAccountName' could not be modified: $($_.Exception.Message)" -ErrorAction Continue
                    } finally {
                        if ($null -ne $directoryEntry) {
                            $directoryEntry.Dispose()
                        }
                    }
                }
            }

            [PSCustomObject]@{
                PSTypeName        = 'ComputerAccountSecurityResult'
                Identity          = $samAccountName
                DistinguishedName = $distinguishedName
                Scope             = $Scope
                PreviousOwner     = $previousOwner
                NewOwner          = $targetOwner
                OwnerCompliant    = $isOwnerCompliant
                PermsCompliant    = $arePermsCompliant
                OwnerReset        = $isOwnerReset
                PermissionsReset  = $arePermsReset
                Simulation        = $isSimulation
                ResultCode        = $resultCode
            }
        }
    }

    end {
    }
}
