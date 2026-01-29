function Invoke-ListAction1Endpoints {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.Action1.Read
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)
    
    $TenantFilter = $Request.Query.tenantFilter
    $Status = $Request.Query.Status
    if (-not $Status) { $Status = "all" }
    
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
        
        # Get endpoints from Action1
        $Endpoints = Get-Action1Endpoints -OrgID $OrgID -Token $Token -Status $Status
        
        # Transform data to match CIPP table expectations
        $Results = @()
        if ($Endpoints -and $Endpoints.items) {
            $Results = $Endpoints.items | ForEach-Object {
                [PSCustomObject]@{
                    id                  = $_.id
                    name                = $_.name
                    hostname            = $_.hostname
                    status              = $_.status
                    platform            = $_.platform
                    os_name             = $_.os_name
                    os_version          = $_.os_version
                    ip_address          = $_.ip_address
                    last_seen           = $_.last_seen
                    agent_version       = $_.agent_version
                    missing_updates     = $_.missing_updates_count
                    tenant              = $TenantFilter
                }
            }
        }
        elseif ($Endpoints -is [Array]) {
            $Results = $Endpoints | ForEach-Object {
                [PSCustomObject]@{
                    id                  = $_.id
                    name                = $_.name
                    hostname            = $_.hostname
                    status              = $_.status
                    platform            = $_.platform
                    os_name             = $_.os_name
                    os_version          = $_.os_version
                    ip_address          = $_.ip_address
                    last_seen           = $_.last_seen
                    agent_version       = $_.agent_version
                    missing_updates     = $_.missing_updates_count
                    tenant              = $TenantFilter
                }
            }
        }
        
        $StatusCode = [HttpStatusCode]::OK
        $Body = @($Results)
    }
    catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -API 'Action1' -message "Failed to list Action1 endpoints: $ErrorMessage" -sev 'Error' -tenant $TenantFilter
        $StatusCode = [HttpStatusCode]::Forbidden
        $Body = $ErrorMessage
    }
    
    return ([HttpResponseContext]@{
        StatusCode = $StatusCode
        Body       = $Body
    })
}
