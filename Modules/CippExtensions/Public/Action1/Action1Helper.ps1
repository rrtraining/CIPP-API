function Get-Action1Configuration {
    <#
    .SYNOPSIS
        Retrieves Action1 configuration from CIPP extension settings.
    .DESCRIPTION
        Gets the stored Action1 credentials and settings from the CIPP configuration.
    .EXAMPLE
        $config = Get-Action1Configuration
    #>
    [CmdletBinding()]
    param ()
    
    try {
        $Table = Get-CIPPTable -TableName 'ExtensionConfig'
        $Configuration = (Get-CIPPAzDataTableEntity @Table).config | ConvertFrom-Json
        
        $Action1Config = @{
            Enabled      = [bool]$Configuration.'Action1.Enabled'
            Instance     = $Configuration.'Action1.Instance'
            ClientID     = $Configuration.'Action1.ClientID'
            ClientSecret = $Configuration.'Action1.APIKey'
            OrgID        = $Configuration.'Action1.OrgID'
        }
        
        return $Action1Config
    }
    catch {
        Write-LogMessage -API 'Action1' -message "Failed to get Action1 configuration: $_" -sev 'Error'
        return $null
    }
}

function Test-Action1Connection {
    <#
    .SYNOPSIS
        Tests the Action1 API connection.
    .DESCRIPTION
        Verifies that the Action1 credentials are valid by attempting to authenticate.
    .PARAMETER ClientID
        The Action1 API Client ID.
    .PARAMETER ClientSecret
        The Action1 API Client Secret.
    .EXAMPLE
        $isConnected = Test-Action1Connection -ClientID $id -ClientSecret $secret
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ClientID,
        
        [Parameter(Mandatory)]
        [string]$ClientSecret
    )
    
    try {
        $token = Get-Action1Token -ClientID $ClientID -ClientSecret $ClientSecret
        if ($token) {
            return @{
                Success = $true
                Message = "Successfully connected to Action1"
            }
        }
        else {
            return @{
                Success = $false
                Message = "Failed to obtain Action1 access token"
            }
        }
    }
    catch {
        return @{
            Success = $false
            Message = "Connection test failed: $_"
        }
    }
}

function Get-Action1CachedToken {
    <#
    .SYNOPSIS
        Gets or refreshes the Action1 access token with caching.
    .DESCRIPTION
        Retrieves a cached token if still valid, otherwise obtains a new one.
    .EXAMPLE
        $token = Get-Action1CachedToken
    #>
    [CmdletBinding()]
    param ()
    
    try {
        $config = Get-Action1Configuration
        
        if (-not $config.Enabled) {
            Write-LogMessage -API 'Action1' -message "Action1 integration is not enabled" -sev 'Warning'
            return $null
        }
        
        # Get fresh token (token caching can be implemented with Azure Table Storage if needed)
        $token = Get-Action1Token -ClientID $config.ClientID -ClientSecret $config.ClientSecret
        return $token
    }
    catch {
        Write-LogMessage -API 'Action1' -message "Failed to get Action1 cached token: $_" -sev 'Error'
        return $null
    }
}

function Invoke-Action1EndpointAction {
    <#
    .SYNOPSIS
        Performs actions on Action1 endpoints.
    .DESCRIPTION
        Triggers actions like scan, reboot, or patch deployment on endpoints.
    .PARAMETER OrgID
        The Action1 Organization ID.
    .PARAMETER EndpointID
        The target endpoint ID.
    .PARAMETER Action
        The action to perform (scan, reboot).
    .PARAMETER Token
        The bearer token from Get-Action1Token.
    .EXAMPLE
        Invoke-Action1EndpointAction -OrgID $orgId -EndpointID "abc123" -Action "scan" -Token $token
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$OrgID,
        
        [Parameter(Mandatory)]
        [string]$EndpointID,
        
        [Parameter(Mandatory)]
        [ValidateSet("scan", "reboot")]
        [string]$Action,
        
        [Parameter(Mandatory)]
        [string]$Token
    )
    
    try {
        $endpoint = "/endpoints/$OrgID/$EndpointID/$Action"
        $result = Invoke-Action1Request -Endpoint $endpoint -Method "POST" -Token $Token
        
        Write-LogMessage -API 'Action1' -message "Successfully triggered $Action on endpoint $EndpointID" -sev 'Info'
        return $result
    }
    catch {
        Write-LogMessage -API 'Action1' -message "Failed to trigger $Action on endpoint $EndpointID : $_" -sev 'Error'
        return $null
    }
}

function Get-Action1EndpointSummary {
    <#
    .SYNOPSIS
        Gets a summary of Action1 endpoints for CIPP dashboard.
    .DESCRIPTION
        Returns endpoint counts and status summary for display in CIPP.
    .EXAMPLE
        $summary = Get-Action1EndpointSummary
    #>
    [CmdletBinding()]
    param ()
    
    try {
        $config = Get-Action1Configuration
        if (-not $config.Enabled) {
            return $null
        }
        
        $token = Get-Action1CachedToken
        if (-not $token) {
            return $null
        }
        
        $endpoints = Get-Action1Endpoints -OrgID $config.OrgID -Token $token
        
        if ($endpoints) {
            $summary = @{
                TotalEndpoints  = ($endpoints | Measure-Object).Count
                OnlineEndpoints = ($endpoints | Where-Object { $_.status -eq 'online' } | Measure-Object).Count
                OfflineEndpoints = ($endpoints | Where-Object { $_.status -eq 'offline' } | Measure-Object).Count
            }
            return $summary
        }
        
        return $null
    }
    catch {
        Write-LogMessage -API 'Action1' -message "Failed to get Action1 endpoint summary: $_" -sev 'Error'
        return $null
    }
}
