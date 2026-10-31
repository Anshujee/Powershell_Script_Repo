#Requires -Modules Az.Accounts, Az.Resources, Az.PolicyInsights
<#
.SYNOPSIS
  Starts remediation for tag-inheritance policy assignments on ONE resource group.
  DRY RUN by default. Nothing changes unless you add -Live.

.EXAMPLE
  # Dry run (safe)
  ./Reme-TagV1.ps1 `
      -SubscriptionId "6a6cb5d4-9c05-4211-b604-b4a53fed3284" `
      -ResourceGroupName "RemediationTestRG" `
      -PolicyAssignmentNames "5e69befddc2c57e69009a2b2","81f530973a0555b9a3b23957" `
      - dryrun

.EXAMPLE
  # Live run (starts remediation tasks)
  ./Reme-TagV1.ps1 `
      -SubscriptionId "6a6cb5d4-9c05-4211-b604-b4a53fed3284" `
      -ResourceGroupName "RemediationTestRG" `
      -PolicyAssignmentNames "5e69befddc2c57e69009a2b2","81f530973a0555b9a3b23957" `
      - Live
#>