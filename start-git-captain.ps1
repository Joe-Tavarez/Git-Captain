$commands = @(
    "cd /opt/git-captain",
    "cp .env.example .env",
    "touch controllers/theKey.key controllers/theCert.cert",
    "pm2 start controllers/server.js --name git-captain",
    "sleep 2",
    "pm2 list"
)

$response = aws ssm send-command `
    --instance-ids i-0784fd62b72496655 `
    --document-name "AWS-RunShellScript" `
    --parameters ("commands=" + ($commands | ConvertTo-Json -Compress)) `
    --region us-east-2 `
    --output json | ConvertFrom-Json

Write-Host "Command ID: $($response.Command.CommandId)"

Start-Sleep -Seconds 10

$result = aws ssm get-command-invocation `
    --command-id $response.Command.CommandId `
    --instance-id i-0784fd62b72496655 `
    --region us-east-2 `
    --output json | ConvertFrom-Json

Write-Host "`nStatus: $($result.Status)"
Write-Host "`nOutput:"
Write-Host $result.StandardOutputContent

if ($result.StandardErrorContent) {
    Write-Host "`nErrors:"
    Write-Host $result.StandardErrorContent
}
