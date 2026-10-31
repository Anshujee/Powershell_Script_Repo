
# ============================================
# Azure Policy Tag Inheritance Remediation
# Initial test: DRY RUN ONLY
# ============================================

$ErrorActionPreference = 'Stop'

# 1. Configure these values
$SubscriptionId = "6a6cb5d4-9c05-4211-b604-b4a53fed3284"
$ResourceGroupName = "RemediationTestRG"

$PolicyAssignmentNames = @(
    "5e69befddc2c57e69009a2b2"
    "81f530973a0555b9a3b23957"
)

# Keep this true for the initial test.
$DryRun = $true

try {
    Write-Host "========================================"
    Write-Host "Azure Policy Tag Remediation"
    Write-Host "Mode: $(if ($DryRun) { 'DRY RUN' } else { 'LIVE' })"
    Write-Host "========================================"

    # 2. Validate configuration
    if ($SubscriptionId -match '^<.*>$' -or
        $ResourceGroupName -match '^<.*>$') {
        throw "Replace the subscription and resource group placeholders first."
    }

    if ($PolicyAssignmentNames.Count -eq 0 -or
        @($PolicyAssignmentNames | Where-Object {
            $_ -match '^<.*>$'
        }).Count -gt 0) {
        throw "Replace all policy assignment placeholders first."
    }

    # 3. Verify Azure authentication
    $context = Get-AzContext

    if (-not $context) {
        throw "Not signed in to Azure. Run Connect-AzAccount -DeviceCode first."
    }

    # 4. Select the intended subscription
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

    $context = Get-AzContext
    Write-Host "Authenticated subscription: $($context.Subscription.Name)"

    # 5. Check the resource group
    $rg = Get-AzResourceGroup -Name $ResourceGroupName

    if (-not $rg) {
        throw "Resource group '$ResourceGroupName' was not found."
    }

    $scope = $rg.ResourceId
    Write-Host "Resource group found: $($rg.ResourceGroupName)"
    Write-Host "Scope: $scope"

    # 6. Check each assignment and prepare remediation
    $names = @(
        $PolicyAssignmentNames |
        Select-Object -Unique
    )

    $index = 0

    foreach ($assignmentName in $names) {
        Write-Host ""
        Write-Host "Checking assignment: $assignmentName"

        $assignment = Get-AzPolicyAssignment `
            -Name $assignmentName `
            -Scope $scope

        if (-not $assignment) {
            throw "Assignment '$assignmentName' was not found at this resource-group scope."
        }

        if ($assignment.Scope.TrimEnd('/') -ne $scope.TrimEnd('/')) {
            throw "Assignment '$assignmentName' is not directly assigned to this resource group."
        }

        Write-Host "Assignment found: $($assignment.DisplayName)"
        Write-Host "Assignment ID: $($assignment.Id)"
        Write-Host "Assignment scope verified."

        # This is a planning step only.
        # No remediation task is started in dry-run mode.
        $suffix = [guid]::NewGuid().ToString('N').Substring(0, 8)

        $remediationName = "tag-remed-$(
            (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
        )-$index-$suffix"

        $index++

        if ($DryRun) {
            Write-Host "[DRY RUN] Would start remediation."
            Write-Host "  Assignment: $assignmentName"
            Write-Host "  Task name: $remediationName"
            continue
        }

        # LIVE MODE: this starts remediation.
        $result = Start-AzPolicyRemediation `
            -Name $remediationName `
            -PolicyAssignmentId $assignment.Id `
            -ResourceGroupName $ResourceGroupName `
            -ResourceDiscoveryMode ReEvaluateCompliance `
            -NoWait

        Write-Host "Remediation submitted: $remediationName"
        Write-Host "Task ID: $($result.Id)"
    }

    Write-Host ""
    Write-Host "Script completed successfully."
    Write-Host "Review all output before enabling live remediation."
}
catch {
    Write-Error "Script failed: $($_.Exception.Message)"
    throw
}
