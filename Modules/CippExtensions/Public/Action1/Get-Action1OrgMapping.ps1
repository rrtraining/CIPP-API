function Get-Action1OrgMapping {
    <#
    .SYNOPSIS
        Gets Action1 organization mapping data for CIPP tenant mapping UI.
    
    .DESCRIPTION
        Retrieves available Action1 organizations and existing tenant mappings.
        Used by CIPP to display the mapping interface where users associate
        M365 tenants with Action1 organizations.
    
    .EXAMPLE
        Get-Action1OrgMapping
    #>
    [CmdletBinding()]
    param()
    
    try {
        # Get all CIPP tenants
        $Tenants = Get-Tenants -IncludeErrors
        
        # Get existing Action1 extension mappings
        $ExtensionMappings = Get-ExtensionMapping -Extension 'Action1'
        
        # Build current mappings list
        $Mappings = foreach ($Mapping in $ExtensionMappings) {
            $Tenant = $Tenants | Where-Object { $_.RowKey -eq $Mapping.RowKey }
            if ($Tenant) {
                [PSCustomObject]@{
                    TenantId        = $Tenant.customerId
                    Tenant          = $Tenant.displayName
                    TenantDomain    = $Tenant.defaultDomainName
                    IntegrationId   = $Mapping.IntegrationId
                    IntegrationName = $Mapping.IntegrationName
                }
            }
        }
        
        # Get Action1 configuration from CIPP settings
        $Table = Get-CIPPTable -TableName Extensionsconfig
        $Configuration = ((Get-CIPPAzDataTableEntity @Table).config | ConvertFrom-Json -ErrorAction Stop)
        $Action1Config = $Configuration.Action1
        
        # Check if Action1 is enabled
        $Action1Enabled = [bool]$Action1Config.Enabled
        $Action1ClientID = $Action1Config.ClientID
        $Action1OrgID = $Action1Config.OrgID
        
        if (-not $Action1Enabled -or [string]::IsNullOrEmpty($Action1ClientID)) {
            $Action1Orgs = @([PSCustomObject]@{ 
                name  = 'Action1 integration not configured. Please configure API credentials first.'
                value = '-1' 
            })
        } else {
            try {
                # Get Action1 API key securely from Key Vault
                $Action1ClientSecret = Get-ExtensionAPIKey -Extension 'Action1'
                
                if ([string]::IsNullOrEmpty($Action1ClientSecret)) {
                    throw "Failed to retrieve Action1 API key from Key Vault"
                }
                
                # Get Action1 token using credentials
                $Token = Get-Action1Token -ClientID $Action1ClientID -ClientSecret $Action1ClientSecret
                
                if (-not $Token) {
                    throw "Failed to obtain Action1 access token"
                }
                
                # Get organizations from Action1 API
                $OrgResponse = Invoke-Action1Request -Endpoint '/organizations' -Method 'GET' -Token $Token
                
                if ($OrgResponse -and $OrgResponse.items) {
                    $Action1Orgs = $OrgResponse.items | ForEach-Object {
                        [PSCustomObject]@{
                            name  = $_.name
                            value = $_.id
                        }
                    }
                } elseif ($OrgResponse -and $OrgResponse.id) {
                    # Single org response
                    $Action1Orgs = @([PSCustomObject]@{
                        name  = $OrgResponse.name
                        value = $OrgResponse.id
                    })
                } elseif (-not [string]::IsNullOrEmpty($Action1OrgID)) {
                    # Fall back to configured OrgID if no orgs returned from API
                    $Action1Orgs = @([PSCustomObject]@{
                        name  = "Configured Organization ($Action1OrgID)"
                        value = $Action1OrgID
                    })
                } else {
                    $Action1Orgs = @([PSCustomObject]@{ 
                        name  = 'No organizations found in Action1'
                        value = '-1' 
                    })
                }
            } catch {
                $ErrorMessage = if ($_.ErrorDetails.Message) {
                    Get-NormalizedError -Message $_.ErrorDetails.Message
                } else {
                    $_.Exception.Message
                }
                
                Write-LogMessage -API 'Action1OrgMapping' -tenant 'CIPP' -message "Failed to get Action1 organizations: $ErrorMessage" -Sev 'Warning'
                
                # Fall back to configured OrgID if API call fails
                if (-not [string]::IsNullOrEmpty($Action1OrgID)) {
                    $Action1Orgs = @([PSCustomObject]@{
                        name  = "Configured Organization ($Action1OrgID)"
                        value = $Action1OrgID
                    })
                } else {
                    $Action1Orgs = @([PSCustomObject]@{ 
                        name  = "Could not get Action1 Orgs: $ErrorMessage"
                        value = '-1' 
                    })
                }
            }
        }
        
        $MappingObj = [PSCustomObject]@{
            Companies = @($Action1Orgs | Sort-Object name)
            Mappings  = @($Mappings)
        }
        
        return $MappingObj
        
    } catch {
        $ErrorMessage = $_.Exception.Message
        Write-LogMessage -API 'Action1OrgMapping' -tenant 'CIPP' -message "Error in Get-Action1OrgMapping: $ErrorMessage" -Sev 'Error'
        
        return [PSCustomObject]@{
            Companies = @([PSCustomObject]@{ name = "Error: $ErrorMessage"; value = '-1' })
            Mappings  = @()
        }
    }
}
