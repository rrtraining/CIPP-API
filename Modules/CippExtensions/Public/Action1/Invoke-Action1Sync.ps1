function Invoke-Action1Sync {
    <#
    .SYNOPSIS
        Initiates Action1 synchronization for all mapped tenants.
    
    .DESCRIPTION
        Queues Action1 data sync for all M365 tenants that have been mapped to an Action1 organization.
        This function is called when the Sync button is clicked in CIPP.
    
    .EXAMPLE
        Invoke-Action1Sync
    #>
    [CmdletBinding()]
    param()
    
    try {
        $Table = Get-CIPPTable -TableName Action1Settings
        
        # Get tenants that have Action1 mapping configured
        $CIPPMapping = Get-CIPPTable -TableName CippMapping
        $Filter = "PartitionKey eq 'Action1Mapping'"
        $TenantsToProcess = Get-CIPPAzDataTableEntity @CIPPMapping -Filter $Filter | Where-Object { $Null -ne $_.IntegrationId -and $_.IntegrationId -ne '' }
        
        # Create batch jobs for each mapped tenant
        $Batch = foreach ($Tenant in $TenantsToProcess) {
            [PSCustomObject]@{
                'Action1Action' = 'SyncTenant'
                'MappedTenant'  = $Tenant
                'FunctionName'  = 'Action1Queue'
            }
        }
        
        if (($Batch | Measure-Object).Count -gt 0) {
            $InputObject = [PSCustomObject]@{
                OrchestratorName = 'Action1Orchestrator'
                Batch            = @($Batch)
            }
            
            $InstanceId = Start-NewOrchestration -FunctionName 'CIPPOrchestrator' -InputObject ($InputObject | ConvertTo-Json -Depth 5 -Compress)
            Write-Host "Started Action1 sync orchestration with ID = '$InstanceId'"
        }
        
        # Record last sync time
        $AddObject = @{
            PartitionKey   = 'Action1Config'
            RowKey         = 'Action1LastRunTime'
            'SettingValue' = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffK')
        }
        
        Add-AzDataTableEntity @Table -Entity $AddObject -Force
        
        $TenantCount = ($TenantsToProcess | Measure-Object).Count
        Write-LogMessage -API 'Action1Sync' -tenant 'CIPP' -message "Action1 Synchronization Queued for $TenantCount Tenants" -Sev 'Info'
        
        return @{
            Success = $true
            Message = "Action1 sync queued for $TenantCount tenants"
            TenantsProcessed = $TenantCount
        }
        
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-LogMessage -API 'Action1Sync' -tenant 'CIPP' -message "Could not start Action1 Sync: $ErrorMessage" -Sev 'Error'
        
        return @{
            Success = $false
            Message = "Failed to start Action1 sync: $ErrorMessage"
        }
    }
}
