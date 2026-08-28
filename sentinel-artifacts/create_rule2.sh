#!/bin/bash
# Creates the "Possible Successful Brute Force (4625 -> 4624)" Sentinel
# Analytics Rule. Same shorthand-syntax approach as create_rule1.sh —
# see README.md section 3.8. Note "tactics" is repeated once per value;
# this CLI's shorthand syntax does not accept a comma-separated list here.
az sentinel alert-rule create \
  -g sentinel-lab-rg \
  --workspace-name sentinel-lab-workspace \
  --rule-id "rdp-brute-force-success" \
  --scheduled-alert-rule \
    display-name="Possible Successful Brute Force (4625 -> 4624)" \
    description="High-severity correlation: an IP with a burst of failed logons (4625) followed by a SUCCESSFUL logon (4624) from that same IP within 10 minutes." \
    severity="High" \
    enabled=true \
    query="let FailedLogons = SecurityEvent | where EventID == 4625 | summarize FailedAttempts = count() by IpAddress, bin(TimeGenerated, 10m) | where FailedAttempts >= 10; let SuccessfulLogons = SecurityEvent | where EventID == 4624 | where LogonType in (3, 10) | project SuccessTime = TimeGenerated, IpAddress, Account, Computer; FailedLogons | join kind=inner SuccessfulLogons on IpAddress | where SuccessTime between (TimeGenerated .. TimeGenerated + 10m) | project TimeGenerated, IpAddress, FailedAttempts, SuccessTime, Account, Computer" \
    query-frequency="PT10M" \
    query-period="PT10M" \
    trigger-operator="GreaterThan" \
    trigger-threshold=0 \
    suppression-duration="PT1H" \
    suppression-enabled=false \
    tactics="CredentialAccess" \
    tactics="InitialAccess" \
  -o json
