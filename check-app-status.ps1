$commands = @(
    "pm2 list",
    "pm2 logs git-captain --lines 50 --nostream"
)

$cmdId = aws ssm send-command `
    --instance-ids i-0784fd62b72496655 `
    --document-name "AWS-RunShellScript" `
    --parameters ("commands=" + ($commands | ConvertTo-Json -Compress)) `
    --region us-east-2 `
    --query CommandId `
    --output text

Write-Host "Command ID: $cmdId"
Write-Host "Waiting for results..."
Start-Sleep -Seconds 5

$output = aws ssm get-command-invocation `
    --command-id $cmdId `
    --instance-id i-0784fd62b72496655 `
    --region us-east-2 `
    --query StandardOutputContent `
    --output text

Write-Host "`n=== Application Status ==="
Write-Host $output
