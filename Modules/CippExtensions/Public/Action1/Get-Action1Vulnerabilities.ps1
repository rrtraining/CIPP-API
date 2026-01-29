function Get-Action1Vulnerabilities {
    <#
    .SYNOPSIS
        Retrieves vulnerability/CVE data from Action1.
    .DESCRIPTION
        Lists known vulnerabilities affecting endpoints in the organization with optional severity filtering.
    .PARAMETER OrgID
        The Action1 Organization ID.
    .PARAMETER Token
        The bearer token from Get-Action1Token.
    .PARAMETER Severity
        Optional. Filter by severity (critical, high, medium, low, all). Defaults to all.
    .PARAMETER CVEID
        Optional. Specific CVE ID to retrieve details for.
    .EXAMPLE
        $vulns = Get-Action1Vulnerabilities -OrgID $orgId -Token $token
    .EXAMPLE
        $criticalVulns = Get-Action1Vulnerabilities -OrgID $orgId -Token $token -Severity "critical"
    .EXAMPLE
        $cve = Get-Action1Vulnerabilities -OrgID $orgId -Token $token -CVEID "CVE-2024-1234"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$OrgID,
        
        [Parameter(Mandatory)]
        [string]$Token,
        
        [ValidateSet("critical", "high", "medium", "low", "all")]
        [string]$Severity = "all",
        
        [string]$CVEID
    )
    
    try {
        if ($CVEID) {
            # Get specific CVE details
            $endpoint = "/organizations/$OrgID/vulnerabilities/$CVEID"
            $result = Invoke-Action1Request -Endpoint $endpoint -Token $Token
        }
        else {
            # List all vulnerabilities
            $endpoint = "/organizations/$OrgID/vulnerabilities"
            $queryParams = @()
            
            if ($Severity -ne "all") {
                $queryParams += "severity=$Severity"
            }
            
            if ($queryParams.Count -gt 0) {
                $endpoint += "?" + ($queryParams -join "&")
            }
            
            $result = Invoke-Action1Request -Endpoint $endpoint -Token $Token
        }
        
        return $result
    }
    catch {
        Write-LogMessage -API 'Action1' -message "Failed to get Action1 vulnerabilities: $_" -sev 'Error'
        return $null
    }
}
