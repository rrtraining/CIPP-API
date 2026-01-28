function Invoke-Action1Request {
    <#
    .SYNOPSIS
        Makes authenticated requests to the Action1 API.
    .DESCRIPTION
        Generic wrapper for Action1 API calls with bearer token authentication.
    .PARAMETER Endpoint
        The API endpoint path (e.g., "/endpoints/{org_id}").
    .PARAMETER Method
        HTTP method (GET, POST, PUT, DELETE). Defaults to GET.
    .PARAMETER Body
        Optional hashtable for request body (POST/PUT requests).
    .PARAMETER Token
        The bearer token from Get-Action1Token.
    .EXAMPLE
        $endpoints = Invoke-Action1Request -Endpoint "/endpoints/$OrgID" -Token $token
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Endpoint,
        
        [ValidateSet("GET", "POST", "PUT", "DELETE", "PATCH")]
        [string]$Method = "GET",
        
        [hashtable]$Body,
        
        [Parameter(Mandatory)]
        [string]$Token
    )
    
    $baseUrl = "https://app.action1.com/api/3.0"
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
        "Accept"        = "application/json"
    }
    
    $params = @{
        Uri     = "$baseUrl$Endpoint"
        Method  = $Method
        Headers = $headers
    }
    
    if ($Body -and $Method -in @("POST", "PUT", "PATCH")) {
        $params.Body = ($Body | ConvertTo-Json -Depth 10)
    }
    
    try {
        $response = Invoke-RestMethod @params
        return $response
    }
    catch {
        $errorMessage = $_.Exception.Message
        if ($_.ErrorDetails.Message) {
            $errorMessage = $_.ErrorDetails.Message
        }
        Write-LogMessage -API 'Action1' -message "Action1 API request failed for $Endpoint : $errorMessage" -sev 'Error'
        return $null
    }
}
