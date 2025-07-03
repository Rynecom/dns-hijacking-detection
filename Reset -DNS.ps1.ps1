$trustedDNS = @("1.1.1.1", "8.8.8.8")

$adapters = Get-DnsClientServerAddress -AddressFamily IPv4

foreach ($adapter in $adapters) {
    $name = $adapter.InterfaceAlias
    $dnsServers = $adapter.ServerAddresses

    $needsReset = $false
    foreach ($dns in $dnsServers) {
        if ($trustedDNS -notcontains $dns) {
            Write-Host "Untrusted DNS found: $dns"
            $needsReset = $true
            break
        }
    }

    if ($needsReset) {
        Write-Host "Resetting DNS for adapter: $name"
        Set-DnsClientServerAddress -InterfaceAlias $name -ServerAddresses $trustedDNS
    } else {
        Write-Host "Adapter $name is already using trusted DNS."
    }
}
