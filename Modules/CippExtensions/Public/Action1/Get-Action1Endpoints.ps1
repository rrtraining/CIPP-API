function Get-Action1Endpoints {
    <#
    .SYNOPSIS
        Retrieves all managed endpoints from Action1.
    .DESCRIPTION
        Lists all endpoints (devices) managed by Action1 for the specified organization.
    .PARAMETER OrgID
        The Action1 Organization ID.
    .PARAMETER Token
        The bearer token from Get-Action1Token.
    .PARAMETER EndpointID
        Optional. Specific endpoint ID to retrieve details for.
    .PARAMETER Status
        Optional. Filter by status (online, offline, all). Defaults to all.
    .EXAMPLE
        $endpoints = Get-Action1Endpoints -OrgID $orgId -Token $token
    .EXAMPLE
        $endpoint = Get-Action1Endpoints -OrgID $orgId -Token $token -EndpointID "abc123"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$OrgID,
        
        [Parameter(Mandatory)]
        [string]$Token,
        
        [string]$EndpointID,
        
        [ValidateSet("online", "offline", "all")]
        [string]$Status = "all"
    )
    
    try {
        if ($EndpointID) {
            # Get specific endpoint details
            $endpoint = "/endpoints/$OrgID/$EndpointID"
            $result = Invoke-Action1Request -Endpoint $endpoint -Token $Token
        }
        else {
            # List all endpoints
            $endpoint = "/endpoints/$OrgID"
            $queryParams = @()
            
            if ($Status -ne "all") {
                $queryParams += "status=$Status"
            }
            
            if ($queryParams.Count -gt 0) {
                $endpoint += "?" + ($queryParams -join "&")
            }
            
            $result = Invoke-Action1Request -Endpoint $endpoint -Token $Token
        }
        
        return $result
    }
    catch {
        Write-LogMessage -API 'Action1' -message "Failed to get Action1 endpoints: $_" -sev 'Error'
        return $null
    }
}
