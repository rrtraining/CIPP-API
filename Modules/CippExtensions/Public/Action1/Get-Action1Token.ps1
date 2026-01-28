function Get-Action1Token {
    <#
    .SYNOPSIS
        Retrieves an OAuth2 access token from Action1 API.
    .DESCRIPTION
        Authenticates with Action1 using client credentials and returns a bearer token.
    .PARAMETER ClientID
        The Action1 API Client ID.
    .PARAMETER ClientSecret
        The Action1 API Client Secret.
    .EXAMPLE
        $token = Get-Action1Token -ClientID "your-client-id" -ClientSecret "your-secret"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$ClientID,
        
        [Parameter(Mandatory)]
        [string]$ClientSecret
    )
    
    $tokenUrl = "https://app.action1.com/api/3.0/oauth2/token"
    $body = @{
        grant_type    = "client_credentials"
        client_id     = $ClientID
        client_secret = $ClientSecret
    }
    
    try {
        $response = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    }
    catch {
        Write-LogMessage -API 'Action1' -message "Failed to get Action1 token: $_" -sev 'Error'
        return $null
    }
}
