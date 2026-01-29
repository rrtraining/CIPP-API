function Invoke-ListAction1Vulnerabilities {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.Action1.Read
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    
    $TenantFilter = $Request.Query.tenantFilter
    $Severity = $Request.Query.Severity
    if (-not $Severity) { $Severity = "all" }
    
    try {
        # Get Action1 configuration from CIPP extension settings
        $Table = Get-CIPPTable -TableName Extensionsconfig
        $Configuration = ((Get-CIPPAzDataTableEntity @Table).config | ConvertFrom-Json -ErrorAction Stop)
        $Action1Config = $Configuration.Action1
        
        if (-not $Action1Config -or -not $Action1Config.Enabled) {
            throw "Action1 integration not enabled. Please configure in CIPP Settings > Integrations."
        }
        
        $Action1ClientID = $Action1Config.ClientID
        
        if ([string]::IsNullOrEmpty($Action1ClientID)) {
            throw "Action1 Client ID not configured. Please configure in CIPP Settings > Integrations."
        }
        
        # Get tenant info to find the RowKey (customerId)
        $Tenants = Get-Tenants -IncludeErrors
        $Tenant = $Tenants | Where-Object { $_.defaultDomainName -eq $TenantFilter -or $_.customerId -eq $TenantFilter }
        
        if (-not $Tenant) {
            throw "Tenant $TenantFilter not found in CIPP."
        }
        
        $TenantRowKey = $Tenant.RowKey
        
        # Get tenant mapping to find the Action1 org for this tenant
        $ExtensionMappings = Get-ExtensionMapping -Extension 'Action1'
        $Mapping = $ExtensionMappings | Where-Object { $_.RowKey -eq $TenantRowKey }
        
        if (-not $Mapping -or -not $Mapping.IntegrationId) {
            throw "No Action1 organization mapped to tenant $TenantFilter. Please configure mapping in Integrations > Action1."
        }
        
        $OrgID = $Mapping.IntegrationId
        
        # Get Action1 API key securely from Key Vault
        $Action1ClientSecret = Get-ExtensionAPIKey -Extension 'Action1'
        
        if ([string]::IsNullOrEmpty($Action1ClientSecret)) {
            throw "Failed to retrieve Action1 API key"
        }
        
        # Get Action1 token
        $Token = Get-Action1Token -ClientID $Action1ClientID -ClientSecret $Action1ClientSecret
        
        if (-not $Token) {
            throw "Failed to authenticate with Action1 API"
        }
        
        # Get vulnerabilities from Action1
        $Response = Get-Action1Vulnerabilities -OrgID $OrgID -Token $Token -Severity $Severity
        
        # Transform data to match CIPP table expectations
        # Action1 API returns data in 'vulnerabilities' property
        $Results = @()
        $VulnData = $null
        
        if ($Response.vulnerabilities) {
            $VulnData = $Response.vulnerabilities
        }
        elseif ($Response -is [Array]) {
            $VulnData = $Response
        }
        
        if ($VulnData) {
            $Results = $VulnData | ForEach-Object {
                # Get first software product name
                $affectedProduct = ""
                if ($_.software -and $_.software.Count -gt 0) {
                    $affectedProduct = $_.software[0].product_name
                }
                
                [PSCustomObject]@{
                    id                  = $_.cve_id
                    cve_id              = $_.cve_id
                    title               = $_.cve_id
                    description         = "Affects: $affectedProduct"
                    severity            = if ($_.cvss_score -ge 9) { "Critical" } elseif ($_.cvss_score -ge 7) { "High" } elseif ($_.cvss_score -ge 4) { "Medium" } else { "Low" }
                    cvss_score          = $_.cvss_score
                    affected_product    = $affectedProduct
                    affected_endpoints  = $_.endpoints_count
                    published_date      = $_.published_date
                    remediation_status  = $_.remediation_status
                    cisa_kev            = $_.cisa_kev
                    tenant              = $TenantFilter
                }
            }
        }
        
        $StatusCode = [HttpStatusCode]::OK
        $Body = @($Results)
    }
    catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -API 'Action1' -message "Failed to list Action1 vulnerabilities: $ErrorMessage" -sev 'Error' -tenant $TenantFilter
        $StatusCode = [HttpStatusCode]::Forbidden
        $Body = $ErrorMessage
    }
    
    return ([HttpResponseContext]@{
        StatusCode = $StatusCode
        Body       = $Body
    })
}
