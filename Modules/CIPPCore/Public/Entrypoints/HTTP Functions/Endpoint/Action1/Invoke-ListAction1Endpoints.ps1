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
