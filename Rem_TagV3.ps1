
# ==================================================
# Azure Policy Tag Remediation - V3
#
# Features:
#   1. Auto-discover Tag Policies
#   2. Resource Group-specific Compliance Check
#   3. CSV Reporting
#   4. Dry Run Support
#   5. Unique Remediation Task Names
#   6. Safe Error Handling
# ==================================================

$ErrorActionPreference = 'Stop'

# ==================================================
# Configuration
# ==================================================

$SubscriptionId    = "6a6cb5d4-9c05-4211-b604-b4a53fed3284"
$ResourceGroupName = "remediationtag"

# Keep TRUE during testing
$DryRun = $true

# Report location
$ReportPath = ".\TagRemediationReport.csv"

# ==================================================
# Initialize Report Collection
# ==================================================

$report = @()

try {

    Write-Host ""
    Write-Host "========================================="
    Write-Host " Azure Policy Tag Remediation - V3"
    Write-Host " Mode: $(if ($DryRun) { 'DRY RUN' } else { 'LIVE' })"
    Write-Host "========================================="
    Write-Host ""

    # ==================================================
    # Verify Azure Login
    # ==================================================

    $context = Get-AzContext

    if (-not $context) {
        throw "Not connected to Azure. Run Connect-AzAccount first."
    }

    # ==================================================
    # Set Subscription
    # ==================================================

    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

    $context = Get-AzContext

    Write-Host "Subscription:"
    Write-Host $context.Subscription.Name
    Write-Host ""

    # ==================================================
    # Verify Resource Group
    # ==================================================

    $rg = Get-AzResourceGroup -Name $ResourceGroupName

    if (-not $rg) {
        throw "Resource Group '$ResourceGroupName' does not exist."
    }

    $scope = $rg.ResourceId

    Write-Host "Resource Group Found:"
    Write-Host $rg.ResourceGroupName
    Write-Host ""

    # ==================================================
    # Auto Discover Tag Policies
    # ==================================================

    Write-Host "Searching for Tag Related Policy Assignments..."
    Write-Host ""

    $assignments = @(
        Get-AzPolicyAssignment -Scope $scope |
        Where-Object {
            $_.DisplayName -match "Tag"
        }
    )

    if ($assignments.Count -eq 0) {
        throw "No Tag related policy assignments found."
    }

    Write-Host "Assignments Found:"
    $assignments | Select-Object Name, DisplayName |
        Format-Table -AutoSize

    # ==================================================
    # Process Each Policy Assignment
    # ==================================================

    $index = 0

    foreach ($assignment in $assignments) {

        $index++

        Write-Host ""
        Write-Host "----------------------------------------"
        Write-Host "Policy: $($assignment.DisplayName)"
        Write-Host "Assignment: $($assignment.Name)"
        Write-Host "----------------------------------------"

        # ==================================================
        # Compliance Check
        # ==================================================

        $querySucceeded = $false
        $count = "Unknown"
        $nonCompliantResources = @()

        try {

            Write-Host "Checking policy compliance..."

            # Retrieve policy states for this Resource Group
            # and this specific Policy Assignment.

            $policyStates = @(
                Get-AzPolicyState `
                    -ResourceGroupName $ResourceGroupName `
                    -PolicyAssignmentName $assignment.Name
            )

            # Filter NonCompliant records locally.

            $nonCompliantResources = @(
                $policyStates |
                Where-Object {
                    $_.ComplianceState -eq "NonCompliant"
                }
            )

            $count = $nonCompliantResources.Count
            $querySucceeded = $true

        }
        catch {

            Write-Warning "Unable to retrieve compliance information."
            Write-Warning $_.Exception.Message

        }

        Write-Host "Non-Compliant Resources : $count"

        # Display affected resources

        if ($querySucceeded -and $count -gt 0) {

            Write-Host ""
            Write-Host "Non-Compliant Resources Found:"

            $nonCompliantResources |
                Select-Object ResourceId, ComplianceState |
                Format-Table -AutoSize
        }

        # ==================================================
        # Generate Unique Remediation Name
        # ==================================================

        $timestamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss")

        $uniqueId = [guid]::NewGuid().ToString("N").Substring(0, 6)

        $remediationName = "tag-remed-$timestamp-$index-$uniqueId"

        # ==================================================
        # Add Report Entry
        # ==================================================

        $report += [PSCustomObject]@{

            Subscription      = $context.Subscription.Name
            ResourceGroup     = $ResourceGroupName
            PolicyName        = $assignment.DisplayName
            PolicyAssignment  = $assignment.Name
            NonCompliantCount = $count
            QueryStatus       = if ($querySucceeded) { "Success" } else { "Failed" }
            DryRun            = $DryRun
            RemediationName   = $remediationName
            ExecutionTime     = Get-Date

        }

        # ==================================================
        # Skip If Compliance Query Failed
        # ==================================================

        if (-not $querySucceeded) {

            Write-Warning "Skipping remediation because compliance status is Unknown."
            continue

        }

        # ==================================================
        # Skip If No NonCompliant Resources
        # ==================================================

        if ($count -eq 0) {

            Write-Host "No remediation required."
            continue

        }

        # ==================================================
        # Dry Run Mode
        # ==================================================

        if ($DryRun) {

            Write-Host ""
            Write-Host "[DRY RUN]"
            Write-Host "Would start remediation task:"
            Write-Host $remediationName
            Write-Host "Actual remediation task NOT created."

            continue

        }

        # ==================================================
        # Live Remediation
        # ==================================================

        Write-Host ""
        Write-Host "Starting Azure Policy Remediation..."

        $result = Start-AzPolicyRemediation `
            -Name $remediationName `
            -PolicyAssignmentId $assignment.Id `
            -ResourceGroupName $ResourceGroupName `
            -ResourceDiscoveryMode ReEvaluateCompliance `
            -NoWait

        Write-Host "Remediation Started"
        Write-Host "Task ID:"
        Write-Host $result.Id

    }

    # ==================================================
    # Export CSV Report
    # ==================================================

    $report |
        Export-Csv `
            -Path $ReportPath `
            -NoTypeInformation

    Write-Host ""
    Write-Host "========================================="
    Write-Host "Execution Completed"
    Write-Host "Report Saved:"
    Write-Host $ReportPath
    Write-Host "========================================="

}
catch {

    Write-Error $_.Exception.Message
    throw

}
