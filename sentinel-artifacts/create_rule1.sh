#!/bin/bash
# Creates the "RDP Brute Force Attempt Detected" Sentinel Analytics Rule.
# Run from Azure Cloud Shell (or anywhere with `az` logged in and the
# `sentinel` extension installed: az extension add -n sentinel -y).
#
# See README.md section 3.8 for why this uses inline key=value shorthand
# syntax rather than --scheduled-alert-rule @rule1.json (the @file form
# fails with "Required property 'properties' not found in JSON" for this
# command, even when the file is wrapped in a properties/kind object).
az sentinel alert-rule create \
  -g sentinel-lab-rg \
  --workspace-name sentinel-lab-workspace \
  --rule-id "rdp-brute-force-detected" \
  --scheduled-alert-rule \
    display-name="RDP Brute Force Attempt Detected" \
    description="Fires when a single source IP racks up 10+ failed RDP logons (Event ID 4625) against the honeypot within a 5-minute window." \
    severity="Medium" \
    enabled=true \
    query="SecurityEvent | where EventID == 4625 | where LogonType in (3, 10) | summarize FailedAttempts = count(), TargetAccounts = make_set(Account) by IpAddress, bin(TimeGenerated, 5m) | where FailedAttempts >= 10 | project TimeGenerated, IpAddress, FailedAttempts, TargetAccounts" \
    query-frequency="PT5M" \
    query-period="PT5M" \
    trigger-operator="GreaterThan" \
    trigger-threshold=0 \
    suppression-duration="PT1H" \
    suppression-enabled=false \
    tactics="CredentialAccess" \
  -o json
