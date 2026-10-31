param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter(Mandatory)]
    [string[]]$PolicyAssignmentNames,

    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

try {

    Write-Host "========================================"
    Write-Host "Azure Policy Tag Remediation"
    Write-Host "Mode: $(if ($DryRun) { 'DRY RUN' } else { 'LIVE' })"
    Write-Host "========================================"

    # -------------------------------------------------
    # Verify Azure Login
    # -------------------------------------------------
    $context = Get-AzContext

    if (-not $context) {
        throw "Not signed in to Azure. Run Connect-AzAccount first."
    }

    # -------------------------------------------------
    # Validate Subscription
    # -------------------------------------------------
    $subscription = Get-AzSubscription `
        -SubscriptionId $SubscriptionId `
        -ErrorAction SilentlyContinue

    if (-not $subscription) {
        throw "Subscription '$SubscriptionId' was not found."
    }

    # -------------------------------------------------
    # Set Subscription Context
    # -------------------------------------------------
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

    $context = Get-AzContext

    Write-Host ""
    Write-Host "Authenticated Subscription:"
    Write-Host "Name : $($context.Subscription.Name)"
    Write-Host "Id   : $($context.Subscription.Id)"

    # -------------------------------------------------
    # Validate Resource Group
    # -------------------------------------------------
    $rg = Get-AzResourceGroup `
        -Name $ResourceGroupName `
        -ErrorAction SilentlyContinue

    if (-not $rg) {
        throw "Resource Group '$ResourceGroupName' was not found."
    }

    $scope = $rg.ResourceId

    Write-Host ""
    Write-Host "Resource Group Found:"
    Write-Host "Name  : $($rg.ResourceGroupName)"
    Write-Host "Scope : $scope"

    # -------------------------------------------------
    # Remove Duplicate Assignment Names
    # -------------------------------------------------
    $assignmentsToProcess = $PolicyAssignmentNames | Select-Object -Unique

    $index = 0

    foreach ($assignmentName in $assignmentsToProcess) {

        Write-Host ""
        Write-Host "----------------------------------------"
        Write-Host "Checking Assignment: $assignmentName"
        Write-Host "----------------------------------------"

        $assignment = Get-AzPolicyAssignment `
            -Name $assignmentName `
            -Scope $scope `
            -ErrorAction SilentlyContinue

        if (-not $assignment) {
            throw "Assignment '$assignmentName' was not found at Resource Group scope."
        }

        if ($assignment.Scope.TrimEnd('/') -ne $scope.TrimEnd('/')) {
            throw "Assignment '$assignmentName' is not directly assigned to this Resource Group."
        }

        Write-Host "Display Name : $($assignment.DisplayName)"
        Write-Host "AssignmentId : $($assignment.Id)"
        Write-Host "Scope Check  : Passed"

        $suffix = [guid]::NewGuid().ToString('N').Substring(0,8)

        $remediationName = "tag-remed-$((Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'))-$index-$suffix"

        $index++

        if ($DryRun) {

            Write-Host ""
            Write-Host "[DRY RUN]"
            Write-Host "Would start remediation:"
            Write-Host "Assignment : $assignmentName"
            Write-Host "Policy     : $($assignment.DisplayName)"
            Write-Host "Task Name  : $remediationName"

            continue
        }

        $result = Start-AzPolicyRemediation `
            -Name $remediationName `
            -PolicyAssignmentId $assignment.Id `
            -ResourceGroupName $ResourceGroupName `
            -ResourceDiscoveryMode ReEvaluateCompliance `
            -NoWait

        Write-Host ""
        Write-Host "Remediation submitted successfully."
        Write-Host "Task Name : $remediationName"
        Write-Host "Task Id   : $($result.Id)"
    }

    Write-Host ""
    Write-Host "========================================"
    Write-Host "Script completed successfully."
    Write-Host "========================================"
}
catch {
    Write-Error "Script failed: $($_.Exception.Message)"
    throw
}