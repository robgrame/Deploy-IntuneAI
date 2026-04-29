# Example: Analyze a script-based package
.\Deploy-IntuneAI.ps1 `
    -SourcePath "C:\Apps\UpdateComplianceScript" `
    -Mode Analyze `
    -NoAI

# Example: Analyze with AI using GPT-5.4 via Entra ID
$env:AZURE_OPENAI_ENDPOINT = "https://your-instance.openai.azure.com"
$env:AZURE_OPENAI_DEPLOYMENT = "gpt-5.4"
.\Deploy-IntuneAI.ps1 `
    -SourcePath "C:\Apps\UpdateComplianceScript" `
    -Mode Analyze

# Example: Full deploy of an MSI app
.\Deploy-IntuneAI.ps1 `
    -SourcePath "C:\Apps\7-Zip" `
    -Mode Assign `
    -AssignTo AllDevices `
    -NoAI

# Example: Package only, deploy later
.\Deploy-IntuneAI.ps1 `
    -SourcePath "C:\Apps\CustomTool" `
    -Mode Package `
    -OutputPath "C:\IntunePackages\CustomTool"

# Example: Deploy to a specific Azure AD group
.\Deploy-IntuneAI.ps1 `
    -SourcePath "C:\Apps\MyApp" `
    -Mode Assign `
    -AssignTo "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
