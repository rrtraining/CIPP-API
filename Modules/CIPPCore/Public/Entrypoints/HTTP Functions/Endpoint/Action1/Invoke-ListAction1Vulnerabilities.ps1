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
        
        # Get tenant mapping to find the Action1 org for this tenant
        $ExtensionMappings = Get-ExtensionMapping -Extension 'Action1'
        $Mapping = $ExtensionMappings | Where-Object { $_.RowKey -eq $TenantFilter }
        
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
        $Vulnerabilities = Get-Action1Vulnerabilities -OrgID $OrgID -Token $Token -Severity $Severity
        
        # Transform data to match CIPP table expectations
        $Results = @()
        if ($Vulnerabilities -and $Vulnerabilities.items) {
            $Results = $Vulnerabilities.items | ForEach-Object {
                [PSCustomObject]@{
                    id                  = $_.id
                    cve_id              = $_.cve_id
                    title               = $_.title
                    description         = $_.description
                    severity            = $_.severity
                    cvss_score          = $_.cvss_score
                    affected_product    = $_.affected_product
                    affected_endpoints  = $_.affected_endpoints_count
                    published_date      = $_.published_date
                    kb_article          = $_.kb_article
                    tenant              = $TenantFilter
                }
            }
        }
        elseif ($Vulnerabilities -is [Array]) {
            $Results = $Vulnerabilities | ForEach-Object {
                [PSCustomObject]@{
                    id                  = $_.id
                    cve_id              = $_.cve_id
                    title               = $_.title
                    description         = $_.description
                    severity            = $_.severity
                    cvss_score          = $_.cvss_score
                    affected_product    = $_.affected_product
                    affected_endpoints  = $_.affected_endpoints_count
                    published_date      = $_.published_date
                    kb_article          = $_.kb_article
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
