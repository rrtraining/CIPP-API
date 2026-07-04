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
        $Response = Get-Action1MissingUpdates @params
        
        # Transform data to match CIPP table expectations
        # Action1 API returns data in 'items' property (standard) or specific property names
        $Results = @()
        $UpdateData = $null
        
        if ($Response.items) {
            $UpdateData = $Response.items
        }
        elseif ($Response.updates) {
            $UpdateData = $Response.updates
        }
        elseif ($Response -is [Array]) {
            $UpdateData = $Response
        }
        
        if ($UpdateData) {
            $Results = $UpdateData | ForEach-Object {
                # Get security severity from versions if available
                $severity = "Unspecified"
                $releaseDate = ""
                $kbNumber = $_.kb_number
                
                if ($_.versions -and $_.versions.Count -gt 0) {
                    $latestVersion = $_.versions[0]
                    $severity = $latestVersion.security_severity
                    $releaseDate = $latestVersion.release_date
                }
                
                [PSCustomObject]@{
                    id                  = $_.id
                    update_id           = $_.id
                    title               = $_.name
                    description         = $_.description
                    severity            = $severity
                    kb_article          = $kbNumber
                    release_date        = $releaseDate
                    product             = $_.vendor
                    classification      = $_.classification
                    update_type         = $_.update_type
                    update_source       = $_.update_source
                    reboot_needed       = $_.reboot_needed
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
