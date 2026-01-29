function Get-Action1MissingUpdates {
    <#
    .SYNOPSIS
        Retrieves missing updates/patches from Action1.
    .DESCRIPTION
        Lists updates that need to be installed on endpoints in the organization.
    .PARAMETER OrgID
        The Action1 Organization ID.
    .PARAMETER Token
        The bearer token from Get-Action1Token.
    .PARAMETER EndpointID
        Optional. Filter missing updates for a specific endpoint.
    .PARAMETER Severity
        Optional. Filter by update severity (critical, important, moderate, low, all). Defaults to all.
    .EXAMPLE
        $updates = Get-Action1MissingUpdates -OrgID $orgId -Token $token
    .EXAMPLE
        $endpointUpdates = Get-Action1MissingUpdates -OrgID $orgId -Token $token -EndpointID "abc123"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$OrgID,
        
        [Parameter(Mandatory)]
        [string]$Token,
        
        [string]$EndpointID,
        
        [ValidateSet("critical", "important", "moderate", "low", "all")]
        [string]$Severity = "all"
    )
    
    try {
        $endpoint = "/organizations/$OrgID/missing-updates"
        $queryParams = @()
        
        if ($EndpointID) {
            $queryParams += "endpoint_id=$EndpointID"
        }
        
        if ($Severity -ne "all") {
            $queryParams += "severity=$Severity"
        }
        
        if ($queryParams.Count -gt 0) {
            $endpoint += "?" + ($queryParams -join "&")
        }
        
        $result = Invoke-Action1Request -Endpoint $endpoint -Token $Token
        return $result
    }
    catch {
        Write-LogMessage -API 'Action1' -message "Failed to get Action1 missing updates: $_" -sev 'Error'
        return $null
    }
}
