<#
    .SYNOPSIS
    Check that every subnet declared in AD Sites and Services is covered by a DNS reverse lookup zone.

    .DESCRIPTION
    Reads the subnets of the forest (Get-ADReplicationSubnet) and the reverse lookup zones hosted by a DNS server
    (Get-DnsServerZone), then tells for each subnet whether its PTR records have a zone to live in.

    A reverse zone is always aligned on an octet for IPv4 (in-addr.arpa) and on a nibble for IPv6 (ip6.arpa). A
    subnet that is not aligned is split into aligned blocks: 10.1.2.0/23 becomes 2.1.10.in-addr.arpa and
    3.1.10.in-addr.arpa, 10.0.0.0/12 becomes the 16 blocks 0.10 to 15.10. Each block is covered by the most specific
    zone that contains it (1.10.in-addr.arpa or 10.in-addr.arpa both cover 2.1.10.in-addr.arpa).

    Status of each subnet:
    - 'Covered': every block has a reverse zone.
    - 'Partial': some blocks have a zone and others do not, or a missing block only has more specific zones beneath
      it (a /16 subnet with a few /24 zones): the addresses outside those zones have no reverse zone.
    - 'Missing': no reverse zone at all for this subnet.

    The zones automatically created by the DNS server (0, 127 and 255.in-addr.arpa) and the RFC 2317 classless
    delegation zones (name containing a '/') are ignored. Every other zone type counts as covering, conditional
    forwarders and stub zones included, since they make the reverse lookup resolve.

    .PARAMETER Site
    Only check the subnets associated with this site. Wildcards are supported.

    .PARAMETER DnsServer
    DNS server whose reverse zones are read. Defaults to the domain controller used by the ActiveDirectory module (or
    the one targeted by -Server), which must then host the DNS role. For AD integrated zones any DC with the DNS role
    returns the same result; for file backed zones, query the server that hosts them.

    .PARAMETER Server
    Domain controller or domain to query for the subnets. Defaults to the one selected by the ActiveDirectory module.

    .PARAMETER MissingOnly
    Only return the subnets whose status is 'Missing' or 'Partial'.

    .EXAMPLE
    Get-ADSubnetReverseZone | Format-Table -AutoSize

    Checks every subnet of the forest against the reverse zones of the default domain controller.

    .EXAMPLE
    Get-ADSubnetReverseZone -MissingOnly -DnsServer 'dc01.contoso.com'

    Returns only the subnets missing a reverse zone, read from the DNS server 'dc01'.

    .EXAMPLE
    Get-ADSubnetReverseZone -Site 'FR-*' | Sort-Object Status, Subnet

    Checks the subnets of the sites whose name starts with 'FR-'.

    .EXAMPLE
    Get-ADSubnetReverseZone -MissingOnly | ForEach-Object { $_.MissingZones -split ', ' } | Sort-Object -Unique

    Lists the reverse zones to create, one per line, ready to be fed to Add-DnsServerPrimaryZone.

    .EXAMPLE
    Get-ADSubnetReverseZone | Export-Csv -Path 'C:\temp\SubnetReverseZones.csv' -NoTypeInformation -Encoding UTF8 -Delimiter ';'

    Exports the report.

    .OUTPUTS
    System.Management.Automation.PSCustomObject, one per subnet, with Subnet, Site, AddressFamily, Status,
    CoveringZones (zones covering the subnet), MissingZones (zones to create), NestedZones (more specific zones
    found inside a missing block), Description, Location and DnsServer.

    .NOTES
    Requires the ActiveDirectory and DnsServer modules (RSAT AD DS and RSAT DNS Server tools).

    Version : 1.0 - November 2026
    Author : Bastien Perez - ITPro-Tips (https://itpro-tips.com)

    .LINK
    https://itpro-tips.com
#>

function Get-ADSubnetReverseZone {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param (
        [string]$Site,

        [string]$DnsServer,

        [string]$Server,

        [switch]$MissingOnly
    )

    if (-not (Get-Command -Name 'Get-DnsServerZone' -ErrorAction SilentlyContinue)) {
        throw 'Get-DnsServerZone is not available. Install the DNS Server tools (RSAT-DNS-Server feature or Rsat.Dns.Tools capability).'
    }

    # Common parameters forwarded to every ActiveDirectory cmdlet call
    $adParameters = @{ ErrorAction = 'Stop' }

    if ($PSBoundParameters.ContainsKey('Server')) {
        $adParameters.Add('Server', $Server)
    }

    # Without -DnsServer, use the DC that answers the AD queries: it usually hosts the DNS role too
    if ([string]::IsNullOrWhiteSpace($DnsServer)) {
        try {
            $DnsServer = (Get-ADDomainController @adParameters).HostName
        }
        catch {
            throw "Unable to find a domain controller to read the DNS zones from, use -DnsServer: $($_.Exception.Message)"
        }
    }

    Write-Verbose "[i] Read the reverse lookup zones from $DnsServer"

    try {
        $dnsZones = @(Get-DnsServerZone -ComputerName $DnsServer -ErrorAction Stop)
    }
    catch {
        throw "Unable to read the DNS zones from '$DnsServer': $($_.Exception.Message)"
    }

    # Zone names in lower case, compared as strings: a block is covered by a zone when it is the zone itself or
    # a name under it. The classless delegation zones (RFC 2317) do not follow the octet boundaries.
    $reverseZoneNames = @(
        $dnsZones |
            Where-Object { $_.IsReverseLookupZone -and -not $_.IsAutoCreated -and $_.ZoneName -notlike '*/*' } |
            ForEach-Object { $_.ZoneName.ToLowerInvariant() }
    )

    Write-Verbose "[i] $($reverseZoneNames.Count) reverse lookup zone(s) found"

    try {
        $subnets = @(Get-ADReplicationSubnet -Filter * -Properties Description, Location @adParameters)
    }
    catch {
        throw "Unable to read the AD subnets: $($_.Exception.Message)"
    }

    foreach ($subnet in ($subnets | Sort-Object -Property Name)) {

        $siteName = $null

        if ($subnet.Site) {
            # 'CN=Paris,CN=Sites,CN=Configuration,...', the name can hold an escaped comma
            $siteName = ($subnet.Site -split '(?<!\\),')[0] -replace '^CN=' -replace '\\,', ','
        }

        if ($PSBoundParameters.ContainsKey('Site') -and $siteName -notlike $Site) {
            continue
        }

        $address, $prefixText = $subnet.Name.Split('/')
        $ipAddress = $null
        $prefixLength = 0

        if (-not [System.Net.IPAddress]::TryParse($address, [ref]$ipAddress) -or -not [int]::TryParse($prefixText, [ref]$prefixLength)) {
            Write-Warning "Subnet '$($subnet.Name)' is not a valid prefix, skipped"
            continue
        }

        # Reverse zones are cut on octets for IPv4 and on nibbles for IPv6
        if ($ipAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            $addressFamily = 'IPv6'
            $labelBits = 4
            $zoneSuffix = 'ip6.arpa'
        }
        else {
            $addressFamily = 'IPv4'
            $labelBits = 8
            $zoneSuffix = 'in-addr.arpa'
        }

        $maxPrefixLength = $ipAddress.GetAddressBytes().Count * 8

        if ($prefixLength -lt 1 -or $prefixLength -gt $maxPrefixLength) {
            Write-Warning "Subnet '$($subnet.Name)' has an invalid prefix length, skipped"
            continue
        }

        $addressBits = -join ($ipAddress.GetAddressBytes() | ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') })

        # Round the prefix up to the next label boundary, at least one label: a /23 is split into two /24 blocks
        $blockLength = [math]::Max($labelBits, [math]::Ceiling($prefixLength / $labelBits) * $labelBits)
        $extraBits = $blockLength - $prefixLength
        $blockCount = [math]::Pow(2, $extraBits)

        $coveringZones = [System.Collections.Generic.List[string]]::new()
        $missingZones = [System.Collections.Generic.List[string]]::new()
        $nestedZones = [System.Collections.Generic.List[string]]::new()

        for ($blockIndex = 0; $blockIndex -lt $blockCount; $blockIndex++) {

            $blockBits = $addressBits.Substring(0, $prefixLength)

            if ($extraBits -gt 0) {
                $blockBits += [Convert]::ToString([int]$blockIndex, 2).PadLeft($extraBits, '0')
            }

            # Wrapped in an array: a single label would otherwise be a string, which [array]::Reverse rejects
            $labels = @(
                for ($offset = 0; $offset -lt $blockLength; $offset += $labelBits) {
                    $value = [Convert]::ToInt32($blockBits.Substring($offset, $labelBits), 2)

                    if ($addressFamily -eq 'IPv6') { '{0:x}' -f $value } else { [string]$value }
                }
            )

            [array]::Reverse($labels)
            $blockZone = ($labels -join '.') + '.' + $zoneSuffix

            # Most specific zone containing the block
            $coveringZone = $reverseZoneNames |
                Where-Object { $blockZone -eq $_ -or $blockZone.EndsWith(".$_") } |
                Sort-Object -Property Length -Descending |
                Select-Object -First 1

            if ($coveringZone) {
                if (-not $coveringZones.Contains($coveringZone)) {
                    $coveringZones.Add($coveringZone)
                }
            }
            else {
                $missingZones.Add($blockZone)

                # Zones more specific than the block only cover part of it
                foreach ($zoneName in ($reverseZoneNames | Where-Object { $_.EndsWith(".$blockZone") })) {
                    $nestedZones.Add($zoneName)
                }
            }
        }

        if ($missingZones.Count -eq 0) {
            $status = 'Covered'
        }
        elseif ($coveringZones.Count -eq 0 -and $nestedZones.Count -eq 0) {
            $status = 'Missing'
        }
        else {
            $status = 'Partial'
        }

        if ($MissingOnly -and $status -eq 'Covered') {
            continue
        }

        $object = [PSCustomObject][ordered]@{
            Subnet        = $subnet.Name
            Site          = $siteName
            AddressFamily = $addressFamily
            Status        = $status
            CoveringZones = $coveringZones -join ', '
            MissingZones  = $missingZones -join ', '
            NestedZones   = ($nestedZones | Sort-Object -Unique) -join ', '
            Description   = $subnet.Description
            Location      = $subnet.Location
            DnsServer     = $DnsServer
        }

        $object
    }
}
