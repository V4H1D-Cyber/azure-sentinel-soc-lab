#!/bin/bash
# Consolidated AMA ingestion diagnostic — run from Cloud Shell.
# Bundles everything needed to find why Heartbeat/SecurityEvent are still empty
# despite MonAgentHost/MonAgentLauncher/MonAgentManager confirmed running.
set -x

echo "=== 1. Does the VM have a managed identity? (AMA needs one to auth to the DCR) ==="
az vm identity show -g sentinel-lab-rg -n Sentinel-Windows-VM -o json

echo "=== 2. In-guest: IMDS managed-identity token test for the monitor.azure.com resource ==="
az vm run-command invoke -g sentinel-lab-rg -n Sentinel-Windows-VM \
  --command-id RunPowerShellScript \
  --scripts 'try { $r = Invoke-RestMethod -Headers @{Metadata="true"} -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://monitor.azure.com/" -Method GET -TimeoutSec 5; "TOKEN_OK: " + $r.token_type + " expires_in=" + $r.expires_in } catch { "TOKEN_FAILED: " + $_.Exception.Message }' \
  -o json

echo "=== 3. Outbound connectivity from VM to Azure Monitor ingestion control plane ==="
az vm run-command invoke -g sentinel-lab-rg -n Sentinel-Windows-VM \
  --command-id RunPowerShellScript \
  --scripts 'Test-NetConnection -ComputerName global.handler.control.monitor.azure.com -Port 443 | Select-Object ComputerName,TcpTestSucceeded; Test-NetConnection -ComputerName eastus.handler.control.monitor.azure.com -Port 443 | Select-Object ComputerName,TcpTestSucceeded' \
  -o json

echo "=== 4. AMA on-disk logs (the real source of truth AMA writes to, not the Windows event log) ==="
az vm run-command invoke -g sentinel-lab-rg -n Sentinel-Windows-VM \
  --command-id RunPowerShellScript \
  --scripts 'Get-ChildItem -Path "C:\Resources","C:\WindowsAzure\Logs" -Recurse -Include *.log -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 15 FullName,LastWriteTime | Format-Table -AutoSize | Out-String -Width 250' \
  -o json

echo "=== 5. Re-check ingestion after all of the above ==="
WSID=$(az monitor log-analytics workspace show -g sentinel-lab-rg -n sentinel-lab-workspace --query customerId -o tsv)
az monitor log-analytics query -w "$WSID" --analytics-query "union Heartbeat, SecurityEvent | where TimeGenerated > ago(3h) | summarize Count=count() by Type" -o table
