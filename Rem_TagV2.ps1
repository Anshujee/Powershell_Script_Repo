
# ==================================================
# Azure Policy Tag Remediation - V2
# Features:
#   1. Auto-discover Tag Policies
#   2. Compliance Check
#   3. CSV Reporting
#   4. Dry Run Support
# ==================================================

$ErrorActionPreference = 'Stop'

# ==================================================
# Configuration
# ==================================================
$SubscriptionId    = "6a6cb5d4-9c05-4211-b604-b4a53fed3284"
$ResourceGroupName = "TestRGRemeWorkOrNot"

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
    Write-Host " Azure Policy Tag Remediation - V2"
    Write-Host " Mode: $(if ($DryRun) { 'DRY RUN' } else { 'LIVE' })"
    Write-Host "========================================="
    Write-Host ""

    # ==================================================
    # Verify Login
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

    $assignments = Get-AzPolicyAssignment -Scope $scope |
        Where-Object { $_.DisplayName -match "Tag" }

    if (-not $assignments) {
        throw "No Tag related policy assignments found."
    }

    Write-Host "Assignments Found:"
    $assignments | Select-Object Name, DisplayName

    foreach ($assignment in $assignments) {

        Write-Host ""
        Write-Host "----------------------------------------"
        Write-Host "Policy: $($assignment.DisplayName)"
        Write-Host "----------------------------------------"

        # ==================================================
        # Compliance Check
        # ==================================================
        try {
            $nonCompliantResources = Get-AzPolicyState `
                -PolicyAssignmentName $assignment.Name `
                -Filter "ComplianceState eq 'NonCompliant'"

            $count = @($nonCompliantResources).Count
        }
        catch {
            Write-Warning "Unable to retrieve compliance information."
            $count = "Unknown"
        }

        Write-Host "Non-Compliant Resources : $count"

        # ==================================================
        # Generate Remediation Name
        # ==================================================
        $remediationName = "tag-remed-$((Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'))"

        # ==================================================
        # Add Report Entry
        # ==================================================
        $report += [PSCustomObject]@{
            Subscription      = $context.Subscription.Name
            ResourceGroup     = $ResourceGroupName
            PolicyName        = $assignment.DisplayName
            PolicyAssignment  = $assignment.Name
            NonCompliantCount = $count
            DryRun            = $DryRun
            RemediationName   = $remediationName
            ExecutionTime     = Get-Date
        }

        # ==================================================
        # Skip If Compliant
        # ==================================================
        if ($count -eq 0) {
            Write-Host "No remediation required."
            continue
        }

        # ==================================================
        # Dry Run Mode
        # ==================================================
        if ($DryRun) {
            Write-Host "[DRY RUN]"
            Write-Host "Would start remediation task:"
            Write-Host $remediationName
            continue
        }

        # ==================================================
        # Live Remediation
        # ==================================================
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
    # Export Report
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