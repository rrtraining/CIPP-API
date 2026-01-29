Function Invoke-ExecInfrastructureQuery {
    <#
    .SYNOPSIS
        Query infrastructure systems via n8n MCP integration
    .DESCRIPTION
        Routes infrastructure queries to n8n webhook which forwards to appropriate MCP servers
        (Proxmox, FortiGate, Action1)
    .FUNCTIONALITY
        Entrypoint,AnyTenant
    .ROLE
        CIPP.Extension.ReadWrite
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    # Get parameters from query string or body
    $System = $Request.Query.system ?? $Request.Body.system
    $Action = $Request.Query.action ?? $Request.Body.action
    
    # Get additional parameters (exclude system and action)
    $AdditionalParams = @{}
    if ($Request.Query) {
        $Request.Query.PSObject.Properties | Where-Object { $_.Name -notin @('system', 'action') } | ForEach-Object {
            $AdditionalParams[$_.Name] = $_.Value
        }
    }
    if ($Request.Body) {
        $Request.Body.PSObject.Properties | Where-Object { $_.Name -notin @('system', 'action') } | ForEach-Object {
            $AdditionalParams[$_.Name] = $_.Value
        }
    }

    # Validate required parameters
    if (-not $System -or -not $Action) {
        return ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = @{
                error   = 'Missing required parameters'
                message = 'Both system and action parameters are required'
                example = '?system=proxmox&action=list_vms'
            }
        })
    }

    # Get n8n webhook URL from environment variable
    $N8nWebhookUrl = $env:N8N_INFRASTRUCTURE_WEBHOOK
    
    if (-not $N8nWebhookUrl) {
        Write-LogMessage -API 'ExecInfrastructureQuery' -message 'N8N_INFRASTRUCTURE_WEBHOOK environment variable not configured' -Sev 'Error'
        return ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::InternalServerError
            Body       = @{
                error   = 'Configuration error'
                message = 'Infrastructure integration not configured. N8N_INFRASTRUCTURE_WEBHOOK environment variable is missing.'
            }
        })
    }

    # Build request body for n8n
    $RequestBody = @{
        system    = $System
        action    = $Action
        params    = $AdditionalParams
        timestamp = (Get-Date).ToUniversalTime().ToString('o')
        source    = 'CIPP'
    } | ConvertTo-Json -Depth 10 -Compress

    Write-LogMessage -API 'ExecInfrastructureQuery' -message "Querying $System with action $Action" -Sev 'Info'

    try {
        # Call n8n webhook
        $Response = Invoke-RestMethod -Uri $N8nWebhookUrl `
            -Method Post `
            -Body $RequestBody `
            -ContentType 'application/json' `
            -TimeoutSec 30

        Write-LogMessage -API 'ExecInfrastructureQuery' -message "Successfully queried $System" -Sev 'Info'

        return ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = $Response
        })
    }
    catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -API 'ExecInfrastructureQuery' -message "Failed to query $System : $ErrorMessage" -Sev 'Error'
        
        return ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::InternalServerError
            Body       = @{
                error   = 'Infrastructure query failed'
                message = $ErrorMessage
                system  = $System
                action  = $Action
            }
        })
    }
}
