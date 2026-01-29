function Invoke-ListAction1MissingUpdates {
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
    $EndpointID = $Request.Query.EndpointID
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
        
        # Build parameters for the request
        $params = @{
            OrgID = $OrgID
            Token = $Token
            Severity = $Severity
        }
        
        if ($EndpointID) {
            $params.EndpointID = $EndpointID
        }
        
        # Get missing updates from Action1
        $Updates = Get-Action1MissingUpdates @params
        
        # Transform data to match CIPP table expectations
        $Results = @()
        if ($Updates -and $Updates.items) {
            $Results = $Updates.items | ForEach-Object {
                [PSCustomObject]@{
                    id                  = $_.id
                    update_id           = $_.update_id
                    title               = $_.title
                    description         = $_.description
                    severity            = $_.severity
                    kb_article          = $_.kb_article
                    release_date        = $_.release_date
                    product             = $_.product
                    classification      = $_.classification
                    affected_endpoints  = $_.affected_endpoints_count
                    endpoint_name       = $_.endpoint_name
                    endpoint_id         = $_.endpoint_id
                    tenant              = $TenantFilter
                }
            }
        }
        elseif ($Updates -is [Array]) {
            $Results = $Updates | ForEach-Object {
                [PSCustomObject]@{
                    id                  = $_.id
                    update_id           = $_.update_id
                    title               = $_.title
                    description         = $_.description
                    severity            = $_.severity
                    kb_article          = $_.kb_article
                    release_date        = $_.release_date
                    product             = $_.product
                    classification      = $_.classification
                    affected_endpoints  = $_.affected_endpoints_count
                    endpoint_name       = $_.endpoint_name
                    endpoint_id         = $_.endpoint_id
                    tenant              = $TenantFilter
                }
            }
        }
        
        $StatusCode = [HttpStatusCode]::OK
        $Body = @($Results)
    }
    catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -API 'Action1' -message "Failed to list Action1 missing updates: $ErrorMessage" -sev 'Error' -tenant $TenantFilter
        $StatusCode = [HttpStatusCode]::Forbidden
        $Body = $ErrorMessage
    }
    
    return ([HttpResponseContext]@{
        StatusCode = $StatusCode
        Body       = $Body
    })
}
