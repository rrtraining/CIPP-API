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
        
        # Get Action1 configuration
        $Configuration = Get-Action1Configuration
        
        if (-not $Configuration -or -not $Configuration.Enabled) {
            $Action1Orgs = @(@{ 
                name  = 'Action1 integration not configured. Please configure API credentials first.'
                value = '-1' 
            })
        } else {
            try {
                # Get Action1 token
                $Token = Get-Action1Token -Configuration $Configuration
                
                # Get organizations from Action1
                # Note: Action1 API returns organizations the API key has access to
                $OrgResponse = Invoke-Action1Request -Endpoint 'organizations' -Method 'GET' -Configuration $Configuration
                
                if ($OrgResponse -and $OrgResponse.items) {
                    $Action1Orgs = $OrgResponse.items | ForEach-Object {
                        [PSCustomObject]@{
                            name  = $_.name
                            value = $_.id
                        }
                    }
                } else {
                    # If no orgs returned, use the configured OrgID as the default
                    $Action1Orgs = @([PSCustomObject]@{
                        name  = "Default Organization ($($Configuration.OrgID))"
                        value = $Configuration.OrgID
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
                if ($Configuration.OrgID) {
                    $Action1Orgs = @([PSCustomObject]@{
                        name  = "Configured Organization ($($Configuration.OrgID))"
                        value = $Configuration.OrgID
                    })
                } else {
                    $Action1Orgs = @(@{ 
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
            Companies = @(@{ name = "Error: $ErrorMessage"; value = '-1' })
            Mappings  = @()
        }
    }
}
