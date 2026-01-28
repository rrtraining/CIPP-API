function Invoke-Action1TenantSync {
    <#
    .SYNOPSIS
        Synchronizes Action1 data for a specific tenant.
    
    .DESCRIPTION
        Fetches endpoints, vulnerabilities, and missing updates from Action1 
        and caches them for display in CIPP. This function is called by the
        orchestrator for each mapped tenant.
    
    .PARAMETER QueueItem
        The queue item containing tenant mapping information.
    
    .EXAMPLE
        Invoke-Action1TenantSync -QueueItem $QueueItem
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $QueueItem
    )
    
    try {
        $StartTime = Get-Date
        Write-Information "$(Get-Date) - Starting Action1 Sync"
        
        # Get mapping table
        $MappingTable = Get-CIPPTable -TableName CippMapping
        $CurrentMap = Get-CIPPAzDataTableEntity @MappingTable -Filter "PartitionKey eq 'Action1Mapping'"
        
        # Parse the tenant we are processing
        $MappedTenant = $QueueItem.MappedTenant
        $CurrentItem = $CurrentMap | Where-Object { $_.RowKey -eq $MappedTenant.RowKey }
        
        # Check for active sync (prevent concurrent runs)
        $StartDate = try { Get-Date($CurrentItem.lastStartTime) } catch { $Null }
        $EndDate = try { Get-Date($CurrentItem.lastEndTime) } catch { $Null }
        
        if (($null -ne $CurrentItem.lastStartTime) -and ($StartDate -gt (Get-Date).ToUniversalTime().AddMinutes(-10)) -and ($Null -eq $CurrentItem.lastEndTime -or ($StartDate -gt $EndDate))) {
            throw "Action1 Sync for Tenant $($MappedTenant.RowKey) is still running, please wait 10 minutes and try again."
        }
        
        # Update sync status
        $CurrentItem | Add-Member -NotePropertyName lastStartTime -NotePropertyValue ([string]$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))) -Force
        $CurrentItem | Add-Member -NotePropertyName lastStatus -NotePropertyValue 'Running' -Force
        if ($Null -ne $CurrentItem.lastEndTime -and $CurrentItem.lastEndTime -ne '') {
            $CurrentItem.lastEndTime = ([string]$(($CurrentItem.lastEndTime).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')))
        }
        Add-CIPPAzDataTableEntity @MappingTable -Entity $CurrentItem -Force
        
        # Get tenant info
        $Customer = Get-Tenants -IncludeErrors | Where-Object { $_.customerId -eq $MappedTenant.RowKey }
        
        if (($Customer | Measure-Object).count -ne 1) {
            throw "Unable to match tenant: $($MappedTenant.RowKey)"
        }
        
        Write-LogMessage -tenant $Customer.defaultDomainName -API 'Action1Sync' -message "Starting Action1 Sync for $($Customer.displayName)" -Sev 'Info'
        
        $Action1OrgId = $MappedTenant.IntegrationId
        
        # Get Action1 configuration from CIPP settings
        $Table = Get-CIPPTable -TableName Extensionsconfig
        $Configuration = ((Get-CIPPAzDataTableEntity @Table).config | ConvertFrom-Json -ErrorAction Stop)
        $Action1Config = $Configuration.Action1
        
        $Action1Enabled = [bool]$Action1Config.Enabled
        $Action1ClientID = $Action1Config.ClientID
        
        if (-not $Action1Enabled -or [string]::IsNullOrEmpty($Action1ClientID)) {
            throw "Action1 integration is not configured or enabled"
        }
        
        # Get Action1 API key securely from Key Vault
        $Action1ClientSecret = Get-ExtensionAPIKey -Extension 'Action1'
        
        if ([string]::IsNullOrEmpty($Action1ClientSecret)) {
            throw "Failed to retrieve Action1 API key from Key Vault"
        }
        
        # Get Action1 token
        $Token = Get-Action1Token -ClientID $Action1ClientID -ClientSecret $Action1ClientSecret
        
        if (-not $Token) {
            throw "Failed to obtain Action1 access token"
        }
        
        # Initialize cache tables
        $EndpointsTable = Get-CIPPTable -TableName CacheAction1Endpoints
        $VulnerabilitiesTable = Get-CIPPTable -TableName CacheAction1Vulnerabilities
        $MissingUpdatesTable = Get-CIPPTable -TableName CacheAction1MissingUpdates
        
        # Fetch Action1 Endpoints
        Write-Information "Fetching Action1 endpoints for org: $Action1OrgId"
        $Endpoints = $null
        try {
            $Endpoints = Get-Action1Endpoints -OrgID $Action1OrgId -Token $Token
            
            if ($Endpoints) {
                # Handle both array and single-item responses
                if ($Endpoints -isnot [array]) {
                    if ($Endpoints.items) {
                        $Endpoints = $Endpoints.items
                    } else {
                        $Endpoints = @($Endpoints)
                    }
                }
                
                # Clear old cached data for this tenant
                $OldEndpoints = Get-CIPPAzDataTableEntity @EndpointsTable -Filter "PartitionKey eq '$($Customer.customerId)'"
                if ($OldEndpoints) {
                    Remove-AzDataTableEntity -Force @EndpointsTable -Entity $OldEndpoints
                }
                
                # Cache new endpoint data
                foreach ($Endpoint in $Endpoints) {
                    $EndpointEntity = @{
                        PartitionKey = $Customer.customerId
                        RowKey       = $Endpoint.id
                        Data         = ($Endpoint | ConvertTo-Json -Depth 10 -Compress)
                    }
                    Add-CIPPAzDataTableEntity @EndpointsTable -Entity $EndpointEntity -Force
                }
                
                Write-Information "Cached $($Endpoints.Count) endpoints"
            }
        } catch {
            Write-LogMessage -tenant $Customer.defaultDomainName -API 'Action1Sync' -message "Failed to fetch endpoints: $($_.Exception.Message)" -Sev 'Warning'
        }
        
        # Fetch Action1 Vulnerabilities
        Write-Information "Fetching Action1 vulnerabilities for org: $Action1OrgId"
        $Vulnerabilities = $null
        try {
            $Vulnerabilities = Get-Action1Vulnerabilities -OrgID $Action1OrgId -Token $Token
            
            if ($Vulnerabilities) {
                # Handle both array and single-item responses
                if ($Vulnerabilities -isnot [array]) {
                    if ($Vulnerabilities.items) {
                        $Vulnerabilities = $Vulnerabilities.items
                    } else {
                        $Vulnerabilities = @($Vulnerabilities)
                    }
                }
                
                # Clear old cached data
                $OldVulns = Get-CIPPAzDataTableEntity @VulnerabilitiesTable -Filter "PartitionKey eq '$($Customer.customerId)'"
                if ($OldVulns) {
                    Remove-AzDataTableEntity -Force @VulnerabilitiesTable -Entity $OldVulns
                }
                
                # Cache new vulnerability data
                foreach ($Vuln in $Vulnerabilities) {
                    $VulnId = if ($Vuln.cve_id) { $Vuln.cve_id } else { $Vuln.id }
                    $VulnEntity = @{
                        PartitionKey = $Customer.customerId
                        RowKey       = ($VulnId -replace '[^a-zA-Z0-9-]', '_')
                        Data         = ($Vuln | ConvertTo-Json -Depth 10 -Compress)
                    }
                    Add-CIPPAzDataTableEntity @VulnerabilitiesTable -Entity $VulnEntity -Force
                }
                
                Write-Information "Cached $($Vulnerabilities.Count) vulnerabilities"
            }
        } catch {
            Write-LogMessage -tenant $Customer.defaultDomainName -API 'Action1Sync' -message "Failed to fetch vulnerabilities: $($_.Exception.Message)" -Sev 'Warning'
        }
        
        # Fetch Action1 Missing Updates
        Write-Information "Fetching Action1 missing updates for org: $Action1OrgId"
        $MissingUpdates = $null
        try {
            $MissingUpdates = Get-Action1MissingUpdates -OrgID $Action1OrgId -Token $Token
            
            if ($MissingUpdates) {
                # Handle both array and single-item responses
                if ($MissingUpdates -isnot [array]) {
                    if ($MissingUpdates.items) {
                        $MissingUpdates = $MissingUpdates.items
                    } else {
                        $MissingUpdates = @($MissingUpdates)
                    }
                }
                
                # Clear old cached data
                $OldUpdates = Get-CIPPAzDataTableEntity @MissingUpdatesTable -Filter "PartitionKey eq '$($Customer.customerId)'"
                if ($OldUpdates) {
                    Remove-AzDataTableEntity -Force @MissingUpdatesTable -Entity $OldUpdates
                }
                
                # Cache new missing updates data
                $UpdateIndex = 0
                foreach ($Update in $MissingUpdates) {
                    $UpdateEntity = @{
                        PartitionKey = $Customer.customerId
                        RowKey       = "update_$UpdateIndex"
                        Data         = ($Update | ConvertTo-Json -Depth 10 -Compress)
                    }
                    Add-CIPPAzDataTableEntity @MissingUpdatesTable -Entity $UpdateEntity -Force
                    $UpdateIndex++
                }
                
                Write-Information "Cached $($MissingUpdates.Count) missing updates"
            }
        } catch {
            Write-LogMessage -tenant $Customer.defaultDomainName -API 'Action1Sync' -message "Failed to fetch missing updates: $($_.Exception.Message)" -Sev 'Warning'
        }
        
        # Calculate summary stats
        $EndpointCount = if ($Endpoints) { ($Endpoints | Measure-Object).Count } else { 0 }
        $OnlineCount = if ($Endpoints) { ($Endpoints | Where-Object { $_.status -eq 'online' } | Measure-Object).Count } else { 0 }
        $VulnCount = if ($Vulnerabilities) { ($Vulnerabilities | Measure-Object).Count } else { 0 }
        $CriticalVulnCount = if ($Vulnerabilities) { ($Vulnerabilities | Where-Object { $_.severity -eq 'critical' } | Measure-Object).Count } else { 0 }
        $UpdateCount = if ($MissingUpdates) { ($MissingUpdates | Measure-Object).Count } else { 0 }
        
        # Store summary for quick access
        $SummaryTable = Get-CIPPTable -TableName CacheAction1Summary
        $SummaryEntity = @{
            PartitionKey            = $Customer.customerId
            RowKey                  = 'Summary'
            TotalEndpoints          = $EndpointCount
            OnlineEndpoints         = $OnlineCount
            TotalVulnerabilities    = $VulnCount
            CriticalVulnerabilities = $CriticalVulnCount
            MissingUpdates          = $UpdateCount
            LastSync                = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        }
        Add-CIPPAzDataTableEntity @SummaryTable -Entity $SummaryEntity -Force
        
        # Update sync completion status
        $EndTime = Get-Date
        $Duration = (New-TimeSpan -Start $StartTime -End $EndTime).TotalSeconds
        
        $CurrentItem | Add-Member -NotePropertyName lastEndTime -NotePropertyValue ([string]$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))) -Force
        $CurrentItem | Add-Member -NotePropertyName lastStatus -NotePropertyValue 'Completed' -Force
        Add-CIPPAzDataTableEntity @MappingTable -Entity $CurrentItem -Force
        
        Write-LogMessage -tenant $Customer.defaultDomainName -API 'Action1Sync' -message "Completed Action1 Sync for $($Customer.displayName). Endpoints: $EndpointCount, Vulnerabilities: $VulnCount, Missing Updates: $UpdateCount. Duration: $Duration seconds" -Sev 'Info'
        
        return @{
            Success         = $true
            Tenant          = $Customer.displayName
            Endpoints       = $EndpointCount
            Vulnerabilities = $VulnCount
            MissingUpdates  = $UpdateCount
            Duration        = $Duration
        }
        
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-Error "Failed Action1 Sync for $($Customer.displayName): $ErrorMessage"
        Write-LogMessage -tenant $Customer.defaultDomainName -API 'Action1Sync' -message "Failed Action1 Sync: $ErrorMessage" -Sev 'Error'
        
        # Update status to failed
        if ($CurrentItem) {
            $CurrentItem | Add-Member -NotePropertyName lastEndTime -NotePropertyValue ([string]$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ'))) -Force
            $CurrentItem | Add-Member -NotePropertyName lastStatus -NotePropertyValue 'Failed' -Force
            Add-CIPPAzDataTableEntity @MappingTable -Entity $CurrentItem -Force
        }
        
        return @{
            Success = $false
            Error   = $ErrorMessage
        }
    }
}
