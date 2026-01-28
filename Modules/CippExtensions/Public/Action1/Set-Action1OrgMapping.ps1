function Set-Action1OrgMapping {
    <#
    .SYNOPSIS
        Saves Action1 organization to M365 tenant mapping.
    
    .DESCRIPTION
        Stores the mapping between an M365 tenant and an Action1 organization
        in the CIPP mapping table. This mapping is used during sync to know
        which Action1 org to pull data for each tenant.
    
    .PARAMETER TenantId
        The M365 tenant ID (customerId/RowKey).
    
    .PARAMETER IntegrationId
        The Action1 organization ID to map to.
    
    .PARAMETER IntegrationName
        The Action1 organization name for display purposes.
    
    .EXAMPLE
        Set-Action1OrgMapping -TenantId "abc-123" -IntegrationId "e19dcf73-9ca7-5df8-fad5-04d17e61715c" -IntegrationName "My Org"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$IntegrationId,
        
        [Parameter(Mandatory = $false)]
        [string]$IntegrationName = ''
    )
    
    try {
        $MappingTable = Get-CIPPTable -TableName CippMapping
        
        # Create or update the mapping entity
        $MappingEntity = @{
            PartitionKey    = 'Action1Mapping'
            RowKey          = $TenantId
            IntegrationId   = $IntegrationId
            IntegrationName = $IntegrationName
        }
        
        Add-AzDataTableEntity @MappingTable -Entity $MappingEntity -Force
        
        Write-LogMessage -API 'Action1OrgMapping' -tenant $TenantId -message "Mapped tenant to Action1 organization: $IntegrationName ($IntegrationId)" -Sev 'Info'
        
        return @{
            Success = $true
            Message = "Successfully mapped tenant to Action1 organization"
            TenantId = $TenantId
            IntegrationId = $IntegrationId
        }
        
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-LogMessage -API 'Action1OrgMapping' -tenant $TenantId -message "Failed to save Action1 mapping: $ErrorMessage" -Sev 'Error'
        
        return @{
            Success = $false
            Message = "Failed to save mapping: $ErrorMessage"
        }
    }
}
