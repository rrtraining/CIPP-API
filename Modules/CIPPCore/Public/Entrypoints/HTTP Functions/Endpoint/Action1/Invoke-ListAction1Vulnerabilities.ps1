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
        # Get Action1 configuration from extension settings
        $ExtensionConfig = Get-CIPPAzDataTableEntity @{
            TableName    = 'ExtensionConfig'
            PartitionKey = 'Action1'
            RowKey       = 'Action1'
        }
        
        if (-not $ExtensionConfig -or -not $ExtensionConfig.ClientId) {
            throw "Action1 integration not configured. Please configure in CIPP Settings > Integrations."
        }
        
        # Get tenant mapping to find the Action1 org for this tenant
        $TenantMappings = Get-CIPPAzDataTableEntity @{
            TableName    = 'ExtensionMappings'
            PartitionKey = 'Action1'
        }
        
        $Mapping = $TenantMappings | Where-Object { $_.RowKey -eq $TenantFilter }
        
        if (-not $Mapping -or -not $Mapping.IntegrationId) {
            throw "No Action1 organization mapped to tenant $TenantFilter. Please configure mapping in Integrations > Action1."
        }
        
        $OrgID = $Mapping.IntegrationId
        
        # Get Action1 token
        $Token = Get-Action1Token -ClientId $ExtensionConfig.ClientId -ClientSecret $ExtensionConfig.ClientSecret
        
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
