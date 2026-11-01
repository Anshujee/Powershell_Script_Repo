
# ============================================================
# Azure Policy Tag Remediation - V4
#
# Features:
# 1. Discover all accessible Azure subscriptions
# 2. Discover all Resource Groups
# 3. Discover Tag Inheritance policy assignments
# 4. Identify Resource Groups with missing assignments
# 5. Check policy compliance
# 6. DryRun and Live remediation
# 7. Sequential remediation execution
# 8. Wait for remediation completion
# 9. Consolidated CSV reporting
# 10. Error handling
# ============================================================

$ErrorActionPreference = "Stop"

# ============================================================
# CONFIGURATION
# ============================================================

# Keep TRUE during initial testing
$DryRun = $true

# Built-in Azure Policy:
# Inherit a tag from the resource group

$PolicyDefinitionGuid = "cd3aa116-8754-49c9-a813-ad46512ece54"

# Remediation waiting configuration
$WaitForCompletion = $true
$MaxWaitMinutes = 30
$PollIntervalSeconds = 15

# Generate unique report name
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

$ReportPath = ".\AzurePolicyTagRemediation_V4_$Timestamp.csv"

# ============================================================
# INITIALIZE
# ============================================================

$report = @()

$PolicyDefinitionId = "/providers/Microsoft.Authorization/policyDefinitions/$PolicyDefinitionGuid"

try {

    Write-Host ""
    Write-Host "================================================"
    Write-Host " AZURE POLICY TAG REMEDIATION - V4"
    Write-Host " Mode: $(if ($DryRun) { 'DRY RUN' } else { 'LIVE' })"
    Write-Host "================================================"
    Write-Host ""

    # ========================================================
    # VERIFY AZURE LOGIN
    # ========================================================

    $context = Get-AzContext

    if (-not $context) {
        throw "Azure login not found. Run Connect-AzAccount."
    }

    Write-Host "Azure Account:"
    Write-Host $context.Account.Id
    Write-Host ""

    # ========================================================
    # DISCOVER ALL ACCESSIBLE SUBSCRIPTIONS
    # ========================================================

    Write-Host "Discovering Azure subscriptions..."

    $subscriptions = @(
        Get-AzSubscription |
        Where-Object {
            $_.State -eq "Enabled"
        }
    )

    if ($subscriptions.Count -eq 0) {
        throw "No enabled subscriptions found."
    }

    Write-Host "Total subscriptions found: $($subscriptions.Count)"

    # ========================================================
    # PROCESS EACH SUBSCRIPTION
    # ========================================================

    foreach ($subscription in $subscriptions) {

        Write-Host ""
        Write-Host "================================================"
        Write-Host "SUBSCRIPTION: $($subscription.Name)"
        Write-Host "SUBSCRIPTION ID: $($subscription.Id)"
        Write-Host "================================================"

        try {

            # Switch subscription automatically

            Set-AzContext `
                -SubscriptionId $subscription.Id `
                -TenantId $subscription.TenantId `
                -ErrorAction Stop | Out-Null

            # =================================================
            # DISCOVER RESOURCE GROUPS
            # =================================================

            $resourceGroups = @(
                Get-AzResourceGroup -ErrorAction Stop
            )

            Write-Host "Resource Groups Found: $($resourceGroups.Count)"

            # =================================================
            # PROCESS EACH RESOURCE GROUP
            # =================================================

            foreach ($rg in $resourceGroups) {

                Write-Host ""
                Write-Host "----------------------------------------"
                Write-Host "Resource Group: $($rg.ResourceGroupName)"
                Write-Host "----------------------------------------"

                try {

                    # -----------------------------------------
                    # DISCOVER POLICY ASSIGNMENTS
                    # -----------------------------------------

                    $assignments = @(
                        Get-AzPolicyAssignment `
                            -Scope $rg.ResourceId `
                            -ErrorAction Stop |
                        Where-Object {
                            $_.PolicyDefinitionId -match
                            [regex]::Escape($PolicyDefinitionGuid)
                        }
                    )

                    # -----------------------------------------
                    # CHECK MISSING POLICY ASSIGNMENT
                    # -----------------------------------------

                    if ($assignments.Count -eq 0) {

                        Write-Warning "Tag inheritance policy assignment NOT found."

                        $report += [PSCustomObject]@{

                            Subscription       = $subscription.Name
                            SubscriptionId     = $subscription.Id
                            ResourceGroup      = $rg.ResourceGroupName
                            PolicyName         = "Inherit a tag from the resource group"
                            PolicyAssignment   = "Not Assigned"
                            TagName            = ""
                            TotalPolicyStates  = 0
                            NonCompliantCount  = 0
                            CompliantCount     = 0
                            QueryStatus        = "Not Checked"
                            AssignmentStatus   = "Missing"
                            RemediationStatus  = "Not Started"
                            RemediationName    = ""
                            ExecutionMode      = if ($DryRun) { "DRY RUN" } else { "LIVE" }
                            ExecutionTime      = Get-Date
                        }

                        continue
                    }

                    Write-Host "Tag Policy Assignments Found: $($assignments.Count)"

                    # Used to avoid starting another remediation
                    # if the previous task times out.

                    $skipRemainingAssignments = $false

                    # =========================================
                    # PROCESS EACH POLICY ASSIGNMENT
                    # =========================================

                    foreach ($assignment in $assignments) {

                        if ($skipRemainingAssignments) {

                            $report += [PSCustomObject]@{

                                Subscription       = $subscription.Name
                                SubscriptionId     = $subscription.Id
                                ResourceGroup      = $rg.ResourceGroupName
                                PolicyName         = $assignment.DisplayName
                                PolicyAssignment   = $assignment.Name
                                TagName            = ""
                                TotalPolicyStates  = 0
                                NonCompliantCount  = 0
                                CompliantCount     = 0
                                QueryStatus        = "Not Checked"
                                AssignmentStatus   = "Found"
                                RemediationStatus  = "SkippedAfterTimeout"
                                RemediationName    = ""
                                ExecutionMode      = if ($DryRun) { "DRY RUN" } else { "LIVE" }
                                ExecutionTime      = Get-Date
                            }

                            continue
                        }

                        Write-Host ""
                        Write-Host "Policy: $($assignment.DisplayName)"
                        Write-Host "Assignment: $($assignment.Name)"

                        # -------------------------------------
                        # EXTRACT TAG NAME
                        # -------------------------------------

                        $tagName = $null

                        if ($assignment.Parameter -and
                            $assignment.Parameter.tagName) {

                            $tagName = $assignment.Parameter.tagName.value
                        }

                        # -------------------------------------
                        # COMPLIANCE CHECK
                        # -------------------------------------

                        $querySucceeded = $false
                        $policyStates = @()
                        $nonCompliantResources = @()

                        try {

                            Write-Host "Checking compliance..."

                            $policyStates = @(
                                Get-AzPolicyState `
                                    -ResourceGroupName $rg.ResourceGroupName `
                                    -PolicyAssignmentName $assignment.Name `
                                    -ErrorAction Stop
                            )

                            $nonCompliantResources = @(
                                $policyStates |
                                Where-Object {
                                    $_.ComplianceState -eq "NonCompliant"
                                }
                            )

                            $querySucceeded = $true

                        }
                        catch {

                            Write-Warning "Compliance query failed."
                            Write-Warning $_.Exception.Message

                        }

                        $totalStates = $policyStates.Count
                        $nonCompliantCount = $nonCompliantResources.Count

                        $compliantCount = @(
                            $policyStates |
                            Where-Object {
                                $_.ComplianceState -eq "Compliant"
                            }
                        ).Count

                        Write-Host "Tag Name: $tagName"
                        Write-Host "Total Policy States: $totalStates"
                        Write-Host "Non-Compliant Resources: $nonCompliantCount"
                        Write-Host "Compliant Resources: $compliantCount"

                        if (-not $querySucceeded) {

                            $queryStatus = "Failed"
                            $remediationStatus = "Skipped"

                        }
                        elseif ($totalStates -eq 0) {

                            $queryStatus = "NoComplianceData"
                            $remediationStatus = "Not Started"

                        }
                        elseif ($nonCompliantCount -eq 0) {

                            $queryStatus = "Success"
                            $remediationStatus = "Not Required"

                        }
                        else {

                            $queryStatus = "Success"
                            $remediationStatus = "Pending"

                        }

                        # -------------------------------------
                        # DISPLAY NON-COMPLIANT RESOURCES
                        # -------------------------------------

                        if ($nonCompliantCount -gt 0) {

                            $nonCompliantResources |
                                Select-Object ResourceId, ComplianceState |
                                Format-Table -AutoSize
                        }

                        # -------------------------------------
                        # GENERATE UNIQUE REMEDIATION NAME
                        # -------------------------------------

                        $uniqueId = [guid]::NewGuid().ToString("N").Substring(0, 8)

                        $remediationName = "tagrem-$Timestamp-$uniqueId"

                        # -------------------------------------
                        # DRY RUN
                        # -------------------------------------

                        if (-not $querySucceeded -or
                            $totalStates -eq 0 -or
                            $nonCompliantCount -eq 0) {

                            Write-Host "No remediation task will be submitted."

                        }
                        elseif ($DryRun) {

                            Write-Host ""
                            Write-Host "[DRY RUN]"
                            Write-Host "Would start remediation:"
                            Write-Host $remediationName

                            $remediationStatus = "DryRun-WouldRemediate"

                        }
                        else {

                            # ---------------------------------
                            # LIVE REMEDIATION
                            # ---------------------------------

                            try {

                                Write-Host ""
                                Write-Host "Starting remediation..."

                                $result = Start-AzPolicyRemediation `
                                    -Name $remediationName `
                                    -PolicyAssignmentId $assignment.Id `
                                    -ResourceGroupName $rg.ResourceGroupName `
                                    -ResourceDiscoveryMode ReEvaluateCompliance `
                                    -NoWait `
                                    -ErrorAction Stop

                                Write-Host "Remediation submitted:"
                                Write-Host $result.Id

                                $remediationStatus = "Submitted"

                                # ---------------------------------
                                # WAIT FOR TASK COMPLETION
                                # ---------------------------------

                                if ($WaitForCompletion) {

                                    $deadline = (Get-Date).AddMinutes($MaxWaitMinutes)

                                    do {

                                        Start-Sleep -Seconds $PollIntervalSeconds

                                        $task = Get-AzPolicyRemediation `
                                            -ResourceGroupName $rg.ResourceGroupName `
                                            -Name $remediationName `
                                            -IncludeDetail `
                                            -ErrorAction Stop

                                        $taskStatus = [string]$task.ProvisioningState

                                        Write-Host "Remediation status: $taskStatus"

                                    }
                                    while (
                                        $taskStatus -notin @("Succeeded", "Failed", "Canceled") -and
                                        (Get-Date) -lt $deadline
                                    )

                                    if ($taskStatus -in @("Succeeded", "Failed", "Canceled")) {

                                        $remediationStatus = $taskStatus

                                    }
                                    else {

                                        $remediationStatus = "TimedOut"
                                        $skipRemainingAssignments = $true

                                        Write-Warning "Remediation timed out. Skipping remaining assignments in this resource group."

                                    }
                                }

                            }
                            catch {

                                Write-Warning "Remediation failed."
                                Write-Warning $_.Exception.Message

                                $remediationStatus = "Failed"
                            }
                        }

                        # -------------------------------------
                        # ADD REPORT ENTRY
                        # -------------------------------------

                        $report += [PSCustomObject]@{

                            Subscription       = $subscription.Name
                            SubscriptionId     = $subscription.Id
                            ResourceGroup      = $rg.ResourceGroupName
                            PolicyName         = $assignment.DisplayName
                            PolicyAssignment   = $assignment.Name
                            TagName            = $tagName
                            TotalPolicyStates  = $totalStates
                            NonCompliantCount  = $nonCompliantCount
                            CompliantCount     = $compliantCount
                            QueryStatus        = $queryStatus
                            AssignmentStatus   = "Found"
                            RemediationStatus  = $remediationStatus
                            RemediationName    = $remediationName
                            ExecutionMode      = if ($DryRun) { "DRY RUN" } else { "LIVE" }
                            ExecutionTime      = Get-Date

                        }

                    } # End assignment loop

                }
                catch {

                    Write-Warning "Unable to process Resource Group: $($rg.ResourceGroupName)"
                    Write-Warning $_.Exception.Message

                    $report += [PSCustomObject]@{

                        Subscription       = $subscription.Name
                        SubscriptionId     = $subscription.Id
                        ResourceGroup      = $rg.ResourceGroupName
                        PolicyName         = ""
                        PolicyAssignment   = ""
                        TagName            = ""
                        TotalPolicyStates  = 0
                        NonCompliantCount  = 0
                        CompliantCount     = 0
                        QueryStatus        = "Failed"
                        AssignmentStatus   = "ScanFailed"
                        RemediationStatus  = "Not Started"
                        RemediationName    = ""
                        ExecutionMode      = if ($DryRun) { "DRY RUN" } else { "LIVE" }
                        ExecutionTime      = Get-Date
                    }

                }

            } # End Resource Group loop

        }
        catch {

            Write-Warning "Unable to process subscription: $($subscription.Name)"
            Write-Warning $_.Exception.Message

            $report += [PSCustomObject]@{

                Subscription       = $subscription.Name
                SubscriptionId     = $subscription.Id
                ResourceGroup      = ""
                PolicyName         = ""
                PolicyAssignment   = ""
                TagName            = ""
                TotalPolicyStates  = 0
                NonCompliantCount  = 0
                CompliantCount     = 0
                QueryStatus        = "Failed"
                AssignmentStatus   = "SubscriptionScanFailed"
                RemediationStatus  = "Not Started"
                RemediationName    = ""
                ExecutionMode      = if ($DryRun) { "DRY RUN" } else { "LIVE" }
                ExecutionTime      = Get-Date
            }

        }

    } # End Subscription loop

    # ========================================================
    # EXPORT CONSOLIDATED CSV REPORT
    # ========================================================

    Write-Host ""
    Write-Host "Exporting consolidated report..."

    if ($report.Count -gt 0) {

        $report |
            Export-Csv `
                -Path $ReportPath `
                -NoTypeInformation

    }

    # ========================================================
    # FINAL SUMMARY
    # ========================================================

    Write-Host ""
    Write-Host "================================================"
    Write-Host " V4 EXECUTION COMPLETED"
    Write-Host "================================================"

    Write-Host "Subscriptions Scanned: $($subscriptions.Count)"
    Write-Host "Report Records: $($report.Count)"
    Write-Host "Report Location: $ReportPath"

    Write-Host ""
    Write-Host "Execution Mode: $(if ($DryRun) { 'DRY RUN' } else { 'LIVE' })"

    Write-Host "================================================"

}
catch {

    Write-Error $_.Exception.Message
    throw

}
