function Set-Action1OrgMapping {
    <#
    .SYNOPSIS
        Saves Action1 organization to M365 tenant mappings.
    
    .DESCRIPTION
        Stores the mapping between M365 tenants and Action1 organizations
        in the CIPP mapping table. This mapping is used during sync to know
        which Action1 org to pull data for each tenant.
    
    .PARAMETER CIPPMapping
        The CIPP mapping table reference.
    
    .PARAMETER APIName
        The API name for logging.
    
    .PARAMETER Request
        The HTTP request containing the mapping data in the body.
    
    .EXAMPLE
        Set-Action1OrgMapping -CIPPMapping $Table -APIName $APIName -Request $Request
    #>
    [CmdletBinding()]
    param (
        $CIPPMapping,
        $APIName,
        $Request
    )

    # Clear existing Action1 mappings
    Get-CIPPAzDataTableEntity @CIPPMapping -Filter "PartitionKey eq 'Action1Mapping'" | ForEach-Object {
        Remove-AzDataTableEntity -Force @CIPPMapping -Entity $_
    }
    
    # Add new mappings from request body
    foreach ($Mapping in $Request.Body) {
        if ($Mapping.TenantId) {
            $AddObject = @{
                PartitionKey    = 'Action1Mapping'
                RowKey          = "$($Mapping.TenantId)"
                IntegrationId   = "$($Mapping.IntegrationId)"
                IntegrationName = "$($Mapping.IntegrationName)"
            }
            Add-CIPPAzDataTableEntity @CIPPMapping -Entity $AddObject -Force
            Write-LogMessage -API $APIName -headers $Request.Headers -message "Added Action1 mapping for $($Mapping.IntegrationName)." -Sev 'Info'
        }
    }
    
    $Result = [pscustomobject]@{'Results' = 'Successfully edited Action1 mapping table.' }

    Return $Result
}
