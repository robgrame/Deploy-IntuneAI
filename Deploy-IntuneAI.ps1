<#
.SYNOPSIS
    AI-powered universal Intune Win32 app packager and deployer.

.DESCRIPTION
    Analyzes a source folder, uses local heuristics + Azure OpenAI to determine
    install/uninstall commands, detection rules, and requirements, then packages
    and deploys to Intune via Microsoft Graph.

.PARAMETER SourcePath
    Path to the folder containing the application files.

.PARAMETER Mode
    Execution mode:
      Analyze     - Inspect and generate manifest only (default)
      Package     - Analyze + create .intunewin
      Deploy      - Analyze + Package + upload to Intune
      Assign      - Full pipeline including assignment

.PARAMETER OutputPath
    Where to save .intunewin and manifest. Defaults to .\IntunePackage

.PARAMETER AssignTo
    Assignment target: AllDevices, AllUsers, or a Group Object ID. Only used with -Mode Assign.

.PARAMETER AzureOpenAIEndpoint
    Azure OpenAI endpoint URL (e.g. https://myinstance.openai.azure.com)

.PARAMETER AzureOpenAIKey
    API key for Azure OpenAI. Can also use env var AZURE_OPENAI_KEY.

.PARAMETER AzureOpenAIDeployment
    Deployment name for the chat model (e.g. gpt-4o)

.PARAMETER NoAI
    Skip AI analysis, use only local heuristics.

.EXAMPLE
    .\Deploy-IntuneAI.ps1 -SourcePath "C:\Apps\7zip" -Mode Analyze
    .\Deploy-IntuneAI.ps1 -SourcePath "C:\Apps\7zip" -Mode Deploy
    .\Deploy-IntuneAI.ps1 -SourcePath "C:\Apps\MyScript" -Mode Assign -AssignTo AllDevices
#>

param(
    [Parameter(Mandatory)]
    [string]$SourcePath,

    [ValidateSet("Analyze","Package","Deploy","Assign")]
    [string]$Mode = "Analyze",

    [string]$OutputPath = ".\IntunePackage",

    [ValidatePattern("^(AllDevices|AllUsers|[0-9a-f-]{36})$")]
    [string]$AssignTo = "AllDevices",

    [string]$AzureOpenAIEndpoint = $env:AZURE_OPENAI_ENDPOINT,
    [string]$AzureOpenAIKey = $env:AZURE_OPENAI_KEY,
    [string]$AzureOpenAIDeployment = ($env:AZURE_OPENAI_DEPLOYMENT, "gpt-4o" -ne $null)[0],

    [switch]$NoAI
)

$ErrorActionPreference = "Stop"
$script:Manifest = $null

#region ===== UTILITY FUNCTIONS =====

function Write-Step { param([string]$Step, [string]$Message, [string]$Color = "Cyan")
    Write-Host "`n[$Step] $Message" -ForegroundColor $Color
}

function Write-Detail { param([string]$Message, [string]$Color = "Gray")
    Write-Host "  $Message" -ForegroundColor $Color
}

function Write-OK { param([string]$Message)
    Write-Host "  $Message" -ForegroundColor Green
}

function Write-Warn { param([string]$Message)
    Write-Host "  WARNING: $Message" -ForegroundColor Yellow
}

#endregion

#region ===== PHASE 1: LOCAL ANALYSIS =====

function Get-FileInventory {
    param([string]$Path)
    
    $files = Get-ChildItem -Path $Path -Recurse -File
    $inventory = @{
        AllFiles      = @()
        MSIs          = @()
        EXEs          = @()
        Scripts       = @()  # ps1, bat, cmd, vbs
        Configs       = @()  # xml, json, ini, cfg
        TotalSizeMB   = [math]::Round(($files | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
    }

    foreach ($f in $files) {
        $rel = $f.FullName.Replace($Path, "").TrimStart("\")
        $entry = @{ Name = $f.Name; RelPath = $rel; Extension = $f.Extension.ToLower(); SizeKB = [math]::Round($f.Length / 1KB, 1) }
        $inventory.AllFiles += $entry
        
        switch ($f.Extension.ToLower()) {
            ".msi"  { $inventory.MSIs += $entry }
            ".exe"  { $inventory.EXEs += $entry }
            { $_ -in ".ps1",".bat",".cmd",".vbs" } { $inventory.Scripts += $entry }
            { $_ -in ".xml",".json",".ini",".cfg",".config" } { $inventory.Configs += $entry }
        }
    }
    return $inventory
}

function Get-MSIProperties {
    param([string]$MsiPath)
    
    try {
        $windowsInstaller = New-Object -ComObject WindowsInstaller.Installer
        $database = $windowsInstaller.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $windowsInstaller, @($MsiPath, 0))
        
        $props = @{}
        foreach ($propName in @("ProductCode","UpgradeCode","ProductVersion","ProductName","Manufacturer","ProductLanguage")) {
            try {
                $query = "SELECT Value FROM Property WHERE Property = '$propName'"
                $view = $database.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $database, @($query))
                $view.GetType().InvokeMember("Execute", "InvokeMethod", $null, $view, $null)
                $record = $view.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $view, $null)
                if ($record) {
                    $props[$propName] = $record.GetType().InvokeMember("StringData", "GetProperty", $null, $record, @(1))
                }
                $view.GetType().InvokeMember("Close", "InvokeMethod", $null, $view, $null)
            } catch {}
        }
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($database) | Out-Null
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($windowsInstaller) | Out-Null
        return $props
    } catch {
        Write-Warn "Could not read MSI properties: $($_.Exception.Message)"
        return @{}
    }
}

function Get-EXEMetadata {
    param([string]$ExePath)
    
    try {
        $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ExePath)
        return @{
            ProductName    = $versionInfo.ProductName
            FileVersion    = $versionInfo.FileVersion
            ProductVersion = $versionInfo.ProductVersion
            CompanyName    = $versionInfo.CompanyName
            Description    = $versionInfo.FileDescription
            OriginalName   = $versionInfo.OriginalFilename
        }
    } catch { return @{} }
}

function Get-ScriptAnalysis {
    param([string]$ScriptPath)

    $content = Get-Content $ScriptPath -Raw -ErrorAction SilentlyContinue
    if (-not $content -or $content.Length -gt 50000) { return @{ TooLarge = $true } }

    # Extract key patterns without sending full content to AI
    $analysis = @{
        HasMsiExec       = $content -match "msiexec"
        HasStartProcess  = $content -match "Start-Process"
        HasRegistryWrite = $content -match "(Set-ItemProperty|New-ItemProperty|reg add|HKLM|HKCU)"
        HasServiceCreate = $content -match "(New-Service|sc\.exe create|Install-Service)"
        HasFileCopy      = $content -match "(Copy-Item|xcopy|robocopy)"
        HasUninstall     = $content -match "(uninstall|remove|cleanup)"
        ReferencedPaths  = @()
        ReferencedRegKeys = @()
    }

    # Extract registry paths
    $regMatches = [regex]::Matches($content, '(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)[:\\\/][^\s"'']+')
    $analysis.ReferencedRegKeys = @($regMatches | ForEach-Object { $_.Value } | Select-Object -Unique | Select-Object -First 10)

    # Extract file paths that look like install targets
    $pathMatches = [regex]::Matches($content, '(?:C:\\Program Files[^"'']*|C:\\Windows[^"'']*|%ProgramFiles%[^"'']*)')
    $analysis.ReferencedPaths = @($pathMatches | ForEach-Object { $_.Value } | Select-Object -Unique | Select-Object -First 10)

    return $analysis
}

function Build-LocalManifest {
    param([string]$SourcePath, [hashtable]$Inventory)
    
    $manifest = @{
        Metadata = @{ DisplayName = ""; Publisher = ""; Description = ""; Version = "" }
        Install = @{ SetupFile = ""; CommandLine = ""; UninstallCommandLine = "" }
        Detection = @{ Type = ""; Rules = @() }
        Requirements = @{ Architecture = "x64"; MinOS = "v10_1903" }
        Confidence = "low"
        Source = "heuristic"
    }

    # === MSI-based detection (highest confidence) ===
    if ($Inventory.MSIs.Count -eq 1) {
        $msiFile = $Inventory.MSIs[0]
        $msiPath = Join-Path $SourcePath $msiFile.RelPath
        $msiProps = Get-MSIProperties -MsiPath $msiPath
        
        $manifest.Install.SetupFile = $msiFile.Name
        $manifest.Install.CommandLine = "msiexec /i `"$($msiFile.Name)`" /qn /norestart"
        
        if ($msiProps.ProductCode) {
            $manifest.Install.UninstallCommandLine = "msiexec /x $($msiProps.ProductCode) /qn /norestart"
            $manifest.Detection = @{
                Type = "msi"
                Rules = @(@{
                    "@odata.type"     = "#microsoft.graph.win32LobAppProductCodeRule"
                    ruleType          = "detection"
                    productCode       = $msiProps.ProductCode
                    productVersionOperator = "greaterThanOrEqual"
                    productVersion    = $msiProps.ProductVersion
                })
            }
            $manifest.Confidence = "high"
        }

        if ($msiProps.ProductName) { $manifest.Metadata.DisplayName = $msiProps.ProductName }
        if ($msiProps.Manufacturer) { $manifest.Metadata.Publisher = $msiProps.Manufacturer }
        if ($msiProps.ProductVersion) { $manifest.Metadata.Version = $msiProps.ProductVersion }
        $manifest.Metadata.Description = "Installs $($msiProps.ProductName) $($msiProps.ProductVersion)"

        Write-OK "MSI detected: $($msiProps.ProductName) ($($msiProps.ProductCode))"
        return $manifest
    }

    # === EXE-based detection (only if no scripts that look like the main entry point) ===
    $mainScript = $Inventory.Scripts | Where-Object { $_.Name -match "(?i)^(runconfig|run|install|setup|deploy)\.(bat|cmd|ps1)$" } | Select-Object -First 1
    if (-not $mainScript) {
        $mainScript = $Inventory.Scripts | Where-Object { $_.Name -match "(?i)(runconfig|install|setup|deploy|config)\.(bat|cmd|ps1)$" } | Select-Object -First 1
    }
    if ($Inventory.EXEs.Count -ge 1 -and -not $mainScript) {
        # Rank: setup.exe > install.exe > largest exe > first exe
        $setupExe = $Inventory.EXEs | Where-Object { $_.Name -match "(?i)(setup|install)" } | Select-Object -First 1
        if (-not $setupExe) { $setupExe = $Inventory.EXEs | Sort-Object SizeKB -Descending | Select-Object -First 1 }
        
        $exePath = Join-Path $SourcePath $setupExe.RelPath
        $exeMeta = Get-EXEMetadata -ExePath $exePath
        
        $manifest.Install.SetupFile = $setupExe.Name
        $manifest.Install.CommandLine = "`"$($setupExe.Name)`" /S /SILENT /VERYSILENT /NORESTART"
        $manifest.Install.UninstallCommandLine = "`"$($setupExe.Name)`" /UNINSTALL /S"
        
        if ($exeMeta.ProductName) { $manifest.Metadata.DisplayName = $exeMeta.ProductName }
        if ($exeMeta.CompanyName) { $manifest.Metadata.Publisher = $exeMeta.CompanyName }
        if ($exeMeta.ProductVersion) { $manifest.Metadata.Version = $exeMeta.ProductVersion }
        $manifest.Metadata.Description = "Installs $($exeMeta.ProductName)"
        $manifest.Confidence = "medium"

        # Detection: file existence
        $manifest.Detection = @{
            Type = "file"
            Rules = @(@{
                "@odata.type"         = "#microsoft.graph.win32LobAppFileSystemRule"
                ruleType              = "detection"
                path                  = "C:\Program Files\$($exeMeta.ProductName)"
                fileOrFolderName      = $setupExe.Name
                check32BitOn64System  = $false
                operationType         = "exists"
            })
        }
        
        Write-OK "EXE detected: $($setupExe.Name) ($($exeMeta.ProductName))"
        return $manifest
    }

    # === Script-based detection (bat/ps1/cmd) ===
    if ($Inventory.Scripts.Count -ge 1) {
        # Rank: batch runner > runconfig > install > setup > deploy > first
        $scriptFile = $Inventory.Scripts | Where-Object { $_.Name -match "(?i)^(runconfig|run|install|setup)\.(bat|cmd)$" } | Select-Object -First 1
        if (-not $scriptFile) { $scriptFile = $Inventory.Scripts | Where-Object { $_.Name -match "(?i)(runconfig|install|setup|deploy|config)" } | Select-Object -First 1 }
        if (-not $scriptFile) { $scriptFile = $Inventory.Scripts[0] }
        
        $scriptPath = Join-Path $SourcePath $scriptFile.RelPath
        $analysis = Get-ScriptAnalysis -ScriptPath $scriptPath
        
        $manifest.Install.SetupFile = $scriptFile.Name
        if ($scriptFile.Extension -in ".bat",".cmd") {
            $manifest.Install.CommandLine = $scriptFile.Name
            $manifest.Install.UninstallCommandLine = "cmd /c echo uninstall"
        } else {
            $manifest.Install.CommandLine = "powershell.exe -ExecutionPolicy Bypass -File `"$($scriptFile.Name)`""
            $manifest.Install.UninstallCommandLine = "powershell.exe -ExecutionPolicy Bypass -Command `"echo uninstall`""
        }
        
        $manifest.Metadata.DisplayName = [System.IO.Path]::GetFileNameWithoutExtension($scriptFile.Name)
        $manifest.Metadata.Publisher = "IT Department"
        $manifest.Metadata.Description = "Configuration script: $($scriptFile.Name)"
        $manifest.Confidence = "low"

        # Use first referenced registry key as detection if available
        if ($analysis.ReferencedRegKeys.Count -gt 0) {
            $regKey = $analysis.ReferencedRegKeys[0] -replace "^HKLM:\\?", "HKEY_LOCAL_MACHINE\" -replace "^HKCU:\\?", "HKEY_CURRENT_USER\"
            $parts = $regKey -split "\\"
            $valueName = $parts[-1]
            $keyPath = ($parts[0..($parts.Length-2)]) -join "\"
            $manifest.Detection = @{
                Type = "registry"
                Rules = @(@{
                    "@odata.type"        = "#microsoft.graph.win32LobAppRegistryRule"
                    ruleType             = "detection"
                    check32BitOn64System = $false
                    keyPath              = $keyPath
                    valueName            = $valueName
                    operationType        = "exists"
                })
            }
        } else {
            $manifest.Detection = @{
                Type = "script"
                Rules = @(@{
                    "@odata.type" = "#microsoft.graph.win32LobAppPowerShellScriptRule"
                    ruleType = "detection"
                    displayName = "Detect $($scriptFile.Name)"
                    enforceSignatureCheck = $false
                    runAs32Bit = $false
                    scriptContent = ""
                })
                NeedsAI = $true
            }
        }
        
        Write-OK "Script detected: $($scriptFile.Name)"
        return $manifest
    }

    Write-Warn "No recognizable installer found"
    return $manifest
}

#endregion

#region ===== PHASE 2: AI PIPELINE (Plan → Code → Rubber Duck → Sanity Check) =====

function Get-AIAuthHeaders {
    $headers = @{ "Content-Type" = "application/json" }
    if ($AzureOpenAIKey) {
        $headers["api-key"] = $AzureOpenAIKey
    } else {
        try {
            $token = (az account get-access-token --resource "https://cognitiveservices.azure.com" --query "accessToken" -o tsv 2>$null)
            if ($token) { $headers["Authorization"] = "Bearer $token" }
        } catch {}
    }
    return $headers
}

function Invoke-AICall {
    param([string]$SystemPrompt, [string]$UserPrompt, [int]$MaxTokens = 3000)

    $authHeaders = Get-AIAuthHeaders
    $aiBody = @{
        messages = @(
            @{ role = "system"; content = $SystemPrompt }
            @{ role = "user"; content = $UserPrompt }
        )
        temperature = 0.1
    }
    if ($AzureOpenAIDeployment -match "gpt-5|o4|codex") {
        $aiBody["max_completion_tokens"] = $MaxTokens
    } else {
        $aiBody["max_tokens"] = $MaxTokens
    }
    $aiBody = $aiBody | ConvertTo-Json -Depth 5

    $apiVersion = if ($AzureOpenAIDeployment -match "gpt-5|o4|codex") { "2025-04-01-preview" } else { "2024-02-15-preview" }
    $uri = "$AzureOpenAIEndpoint/openai/deployments/$AzureOpenAIDeployment/chat/completions?api-version=$apiVersion"

    $response = Invoke-RestMethod -Uri $uri -Method POST -Headers $authHeaders -Body $aiBody -TimeoutSec 120
    return $response.choices[0].message.content
}

function Get-PackageContext {
    param([string]$SourcePath, [hashtable]$Inventory)

    $fileList = ($Inventory.AllFiles | ForEach-Object { "$($_.RelPath) ($($_.SizeKB)KB)" }) -join "`n"

    # Collect scripts with priority ordering and budget
    $scriptSummaries = @()
    $orderedScripts = @()
    $orderedScripts += $Inventory.Scripts | Where-Object { $_.Name -match "(?i)(runconfig|install|setup|deploy)" }
    $orderedScripts += $Inventory.Scripts | Where-Object { $_.Name -match "(?i)(config|main|start)" -and $_ -notin $orderedScripts }
    $orderedScripts += $Inventory.Scripts | Where-Object { $_ -notin $orderedScripts }

    $totalChars = 0
    $maxTotalChars = 15000
    foreach ($s in $orderedScripts) {
        $path = Join-Path $SourcePath $s.RelPath
        $content = Get-Content $path -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        $safe = $content -replace '(?i)(password|secret|key|token|apikey)\s*[:=]\s*[^\s]+', '$1=<REDACTED>'
        $safe = $safe -replace '[A-Za-z0-9+/]{40,}={0,2}', '<BASE64_REDACTED>'
        $remaining = $maxTotalChars - $totalChars
        if ($remaining -le 500) { break }
        if ($safe.Length -gt $remaining) {
            $safe = $safe.Substring(0, $remaining) + "`n... [TRUNCATED at $remaining chars, total $($content.Length) chars]"
        }
        $scriptSummaries += "--- $($s.RelPath) ($($content.Length) chars) ---`n$safe"
        $totalChars += $safe.Length
    }

    return @{
        FileList = $fileList
        ScriptContent = ($scriptSummaries -join "`n`n")
    }
}

# ---- STEP 2A: PLAN ----
function Invoke-AIPlan {
    param([string]$SourcePath, [hashtable]$Inventory, [hashtable]$Manifest)

    $ctx = Get-PackageContext -SourcePath $SourcePath -Inventory $Inventory

    $systemPrompt = @"
You are a senior Intune packaging engineer. Your task is to PLAN how to package this application.
Do NOT produce the final configuration yet. Instead, analyze the package and create a structured plan.
Think step by step. Be thorough.
"@

    $userPrompt = @"
Analyze this package and create a packaging PLAN. Do NOT produce final commands yet.

## Files in package:
$($ctx.FileList)

## Script/file contents:
$($ctx.ScriptContent)

## Current heuristic analysis:
$($Manifest | ConvertTo-Json -Depth 5)

## Create a plan covering:

1. **Package Type Classification**: What kind of package is this? (MSI installer, EXE installer, configuration script, remediation script, driver package, other)

2. **Execution Flow Analysis**: Trace the complete execution flow. Which file is the entry point? What does it call? In what context does it run? What dependencies does it need?

3. **Registry/File Artifacts**: List ALL registry keys and file paths that this package creates, modifies, or checks. For each, note whether it's an INPUT (prerequisite) or OUTPUT (result of installation).

4. **Install Command Strategy**: What is the correct way to silently invoke this package? Consider: execution context (user vs system), 64-bit vs 32-bit, dependencies on other files in the package.

5. **Uninstall Strategy**: Does the package include an uninstall routine? If not, can the changes be reversed? What would an uninstall look like?

6. **Detection Strategy**: Which OUTPUT artifact (from step 3) is the BEST proof that this package ran successfully? Rank candidates by reliability. Explain why each candidate is good or bad.

7. **Risk Factors**: What could go wrong? Are there hard-coded paths? Does it require network access? Reboot? Admin rights beyond SYSTEM?

Return your plan as a JSON object:
{
  "packageType": "string",
  "executionFlow": "step-by-step description",
  "artifacts": {
    "inputs": [{"type": "registry|file", "path": "...", "description": "..."}],
    "outputs": [{"type": "registry|file", "path": "...", "valueName": "...", "expectedValue": "...", "description": "...", "detectionReliability": "high|medium|low"}]
  },
  "installStrategy": "description of approach",
  "uninstallStrategy": "description or 'none'",
  "detectionCandidates": [
    {"artifact": "registry or file path", "valueName": "if registry", "why": "justification", "reliability": "high|medium|low", "falsePositiveRisk": "description", "falseNegativeRisk": "description"}
  ],
  "risks": ["risk1", "risk2"],
  "openQuestions": ["question1", "question2"]
}
"@

    $planText = Invoke-AICall -SystemPrompt $systemPrompt -UserPrompt $userPrompt -MaxTokens 3000
    if ($planText -match '```json\s*([\s\S]*?)\s*```') { $planText = $Matches[1] }
    return ($planText | ConvertFrom-Json)
}

# ---- STEP 2B: CODE (generate manifest from plan) ----
function Invoke-AICoding {
    param([hashtable]$Plan, [hashtable]$Manifest)

    # Load detection library for the AI to reference
    $libPath = Join-Path (Split-Path $PSCommandPath) "lib\detection-library.json"
    $detectionLibrary = ""
    if (Test-Path $libPath) {
        $detectionLibrary = Get-Content $libPath -Raw
    }

    $systemPrompt = @"
You are a senior Intune packaging engineer. Based on the analysis plan provided, produce the FINAL packaging configuration.

## DETECTION RULES LIBRARY — Use these exact templates and valid values:
$detectionLibrary

## Rules:
- Pick the template that best matches the detection strategy from the plan
- Fill in the template placeholders with actual values from the package analysis
- Use ONLY the valid operationType and operator values listed in the library
- keyPath must use full format: HKEY_LOCAL_MACHINE\... (not HKLM:\...)
- For configuration scripts with no native artifact: use "registry-custom-marker" or "script-config-validation" template
- For MSI packages: always prefer "msi-product-code" template
- For EXE installers: prefer "file-version-gte" or "registry-uninstall-key" template

## Install command rules:
- .bat/.cmd → cmd.exe /c <filename>
- .ps1 → powershell.exe -ExecutionPolicy Bypass -File <filename>
- .msi → msiexec /i <filename> /qn /norestart
- If a .bat launcher calls a .ps1 script, the .bat is the entry point

## Uninstall rules:
- If no uninstall exists: cmd.exe /c echo No uninstall available
- Never invent an uninstall that doesn't exist
"@

    $userPrompt = @"
Based on this analysis plan, produce the final Intune Win32 app configuration.

## Analysis Plan:
$($Plan | ConvertTo-Json -Depth 5)

## Current heuristic manifest (starting point):
$($Manifest | ConvertTo-Json -Depth 5)

## Return ONLY a JSON object:
{
  "displayName": "Human-friendly app name",
  "publisher": "Publisher name",
  "description": "What this package does (1-2 sentences)",
  "installCommandLine": "Exact silent install command",
  "uninstallCommandLine": "Exact uninstall command or placeholder",
  "detectionType": "registry|file|productCode|script",
  "detectionTemplateName": "Name of the template from the library that was used (e.g. registry-integer-equal)",
  "detectionRules": [
    {
      "type": "registry|file|productCode",
      "keyPath": "HKEY_LOCAL_MACHINE\\full\\path",
      "valueName": "ValueName",
      "operator": "exists|equal|greaterThanOrEqual",
      "comparisonValue": "if applicable"
    }
  ],
  "detectionScript": "If detectionType is script, the full PowerShell detection script content. null otherwise.",
  "minOS": "v10_1803|v10_1903|v10_21H2|v10_22H2|w11_22H2",
  "architecture": "x64|x86|arm64|all",
  "customRequirements": ["disk-space|dotnet-framework|domain-joined|aad-joined or null"],
  "confidence": "high|medium|low",
  "selectedDetectionJustification": "Why this detection rule and template was chosen over alternatives"
}
"@

    $codeText = Invoke-AICall -SystemPrompt $systemPrompt -UserPrompt $userPrompt -MaxTokens 2000
    if ($codeText -match '```json\s*([\s\S]*?)\s*```') { $codeText = $Matches[1] }
    return ($codeText | ConvertFrom-Json)
}

# ---- STEP 2C: RUBBER DUCK (self-critique) ----
function Invoke-AIRubberDuck {
    param([hashtable]$Plan, $CodeResult, [hashtable]$Manifest)

    $systemPrompt = @"
You are a skeptical senior Intune engineer reviewing a colleague's packaging work. Your job is to find problems BEFORE this package is deployed to thousands of devices.

Be critical. Challenge every assumption. Look for:
- Detection rules that could cause false positives (app appears installed when it's not)
- Detection rules that could cause false negatives (app IS installed but not detected → re-installs on every sync)
- Install commands that could fail silently
- Missing dependencies or prerequisites
- Security concerns
"@

    $userPrompt = @"
Review this Intune Win32 app packaging decision.

## Analysis Plan:
$($Plan | ConvertTo-Json -Depth 5)

## Proposed Configuration:
$($CodeResult | ConvertTo-Json -Depth 5)

## Review checklist:
1. Is the detection rule actually created by THIS script/installer? Or does it already exist on most machines?
2. Will the install command work when run as SYSTEM by the Intune Management Extension? (no user context, no GUI, no network drives)
3. Is the uninstall command appropriate?
4. Are the OS requirements correct?
5. Could this package conflict with existing GPO/MDM policies?

## Return a JSON object:
{
  "approved": true|false,
  "issues": [
    {
      "severity": "critical|warning|info",
      "field": "which field has the issue (detection, install, uninstall, requirements)",
      "problem": "what's wrong",
      "suggestion": "how to fix it"
    }
  ],
  "correctedConfig": {
    "only include fields that need to be changed, or null if approved"
  },
  "overallAssessment": "Summary of the review"
}
"@

    $reviewText = Invoke-AICall -SystemPrompt $systemPrompt -UserPrompt $userPrompt -MaxTokens 2000
    if ($reviewText -match '```json\s*([\s\S]*?)\s*```') { $reviewText = $Matches[1] }
    return ($reviewText | ConvertFrom-Json)
}

# ---- STEP 2D: SANITY CHECK (validate Graph API compatibility) ----
function Invoke-SanityCheck {
    param([hashtable]$Manifest)

    $issues = @()

    # Validate detection rules
    foreach ($rule in $Manifest.Detection.Rules) {
        if ($rule.'@odata.type' -eq '#microsoft.graph.win32LobAppRegistryRule') {
            $validOps = @('notConfigured','exists','doesNotExist','string','integer','version')
            if ($rule.operationType -and $rule.operationType -notin $validOps) {
                $issues += "Invalid operationType '$($rule.operationType)'. Valid: $($validOps -join ', ')"
            }
            $validOperators = @('notConfigured','equal','notEqual','greaterThan','greaterThanOrEqual','lessThan','lessThanOrEqual')
            if ($rule.operator -and $rule.operator -notin $validOperators) {
                $issues += "Invalid operator '$($rule.operator)'. Valid: $($validOperators -join ', ')"
            }
            if ($rule.keyPath -match '^HKLM\\') {
                $issues += "keyPath uses short format '$($rule.keyPath)'. Must use HKEY_LOCAL_MACHINE\\"
                # Auto-fix
                $rule.keyPath = $rule.keyPath -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\'
            }
            if (-not $rule.keyPath -or -not $rule.valueName) {
                $issues += "Detection rule missing keyPath or valueName"
            }
        }
    }

    # Validate install command
    if (-not $Manifest.Install.CommandLine) { $issues += "Install command line is empty" }
    if (-not $Manifest.Install.SetupFile) { $issues += "Setup file is not specified" }

    # Validate metadata
    if (-not $Manifest.Metadata.DisplayName -or $Manifest.Metadata.DisplayName.Length -lt 3) { $issues += "Display name too short or empty" }
    if (-not $Manifest.Metadata.Publisher) { $issues += "Publisher is empty" }

    return $issues
}

# ---- ORCHESTRATOR: Run the full AI pipeline ----
function Invoke-AIAnalysis {
    param([string]$SourcePath, [hashtable]$Inventory, [hashtable]$Manifest)

    if ($NoAI) { return $Manifest }

    $authHeaders = Get-AIAuthHeaders
    if (-not $AzureOpenAIEndpoint) {
        Write-Warn "Azure OpenAI not configured. Set AZURE_OPENAI_ENDPOINT."
        return $Manifest
    }
    if (-not $authHeaders.ContainsKey("api-key") -and -not $authHeaders.ContainsKey("Authorization")) {
        Write-Warn "No Azure OpenAI credentials. Set AZURE_OPENAI_KEY or login with 'az login'."
        return $Manifest
    }

    try {
        # ===== STEP A: PLAN =====
        Write-Detail "Step 1/4: Planning — analyzing package structure and execution flow..."
        $plan = Invoke-AIPlan -SourcePath $SourcePath -Inventory $Inventory -Manifest $Manifest
        Write-OK "Plan complete: $($plan.packageType) — $($plan.detectionCandidates.Count) detection candidates identified"

        # ===== STEP B: CODE =====
        Write-Detail "Step 2/4: Coding — generating Intune configuration from plan..."
        $codeResult = Invoke-AICoding -Plan $plan -Manifest $Manifest
        Write-OK "Configuration generated (confidence: $($codeResult.confidence))"

        # ===== STEP C: RUBBER DUCK =====
        Write-Detail "Step 3/4: Rubber Duck — reviewing configuration for issues..."
        $review = Invoke-AIRubberDuck -Plan $plan -CodeResult $codeResult -Manifest $Manifest

        $criticalIssues = @($review.issues | Where-Object { $_.severity -eq "critical" })
        $warnings = @($review.issues | Where-Object { $_.severity -eq "warning" })
        
        if ($criticalIssues.Count -gt 0) {
            Write-Warn "Rubber Duck found $($criticalIssues.Count) critical issue(s):"
            foreach ($issue in $criticalIssues) {
                Write-Detail "  CRITICAL [$($issue.field)]: $($issue.problem)" 
                Write-Detail "  FIX: $($issue.suggestion)"
            }
            # Apply corrections if provided
            if ($review.correctedConfig) {
                Write-Detail "Applying Rubber Duck corrections..."
                $corrected = $review.correctedConfig
                if ($corrected.installCommandLine) { $codeResult.installCommandLine = $corrected.installCommandLine }
                if ($corrected.uninstallCommandLine) { $codeResult.uninstallCommandLine = $corrected.uninstallCommandLine }
                if ($corrected.detectionRules) { $codeResult.detectionRules = $corrected.detectionRules }
            }
        }
        if ($warnings.Count -gt 0) {
            Write-Warn "Rubber Duck raised $($warnings.Count) warning(s):"
            foreach ($w in $warnings) { Write-Detail "  WARNING [$($w.field)]: $($w.problem)" }
        }
        if ($review.approved) {
            Write-OK "Rubber Duck approved: $($review.overallAssessment)"
        } else {
            Write-Warn "Rubber Duck flagged issues but proceeding with corrections applied"
        }

        # ===== MERGE INTO MANIFEST =====
        if ($Manifest.Confidence -ne "high") {
            if ($codeResult.displayName) { $Manifest.Metadata.DisplayName = $codeResult.displayName }
            if ($codeResult.publisher) { $Manifest.Metadata.Publisher = $codeResult.publisher }
            if ($codeResult.installCommandLine) { $Manifest.Install.CommandLine = $codeResult.installCommandLine }
            if ($codeResult.uninstallCommandLine) { $Manifest.Install.UninstallCommandLine = $codeResult.uninstallCommandLine }
        }
        if ($codeResult.description) { $Manifest.Metadata.Description = $codeResult.description }

        # Map AI detection rules to Graph API format
        if ($Manifest.Confidence -eq "low" -and $codeResult.detectionRules) {
            $graphRules = @()
            foreach ($r in $codeResult.detectionRules) {
                switch ($r.type) {
                    "registry" {
                        $graphRules += @{
                            "@odata.type"        = "#microsoft.graph.win32LobAppRegistryRule"
                            ruleType             = "detection"
                            check32BitOn64System = $false
                            keyPath              = $r.keyPath
                            valueName            = $r.valueName
                            operationType        = if ($r.operator -eq "exists") { "exists" } elseif ($r.operator -match "greaterThan|lessThan|equal") { "integer" } else { "exists" }
                            operator             = switch ($r.operator) { "exists" { "notConfigured" } "equal" { "equal" } "greaterThanOrEqual" { "greaterThanOrEqual" } "greaterThan" { "greaterThan" } "lessThanOrEqual" { "lessThanOrEqual" } "lessThan" { "lessThan" } "notEqual" { "notEqual" } default { "notConfigured" } }
                            comparisonValue      = if ($r.comparisonValue) { "$($r.comparisonValue)" } else { $null }
                        }
                    }
                    "file" {
                        $graphRules += @{
                            "@odata.type"        = "#microsoft.graph.win32LobAppFileSystemRule"
                            ruleType             = "detection"
                            path                 = $r.path
                            fileOrFolderName     = $r.fileOrFolderName
                            check32BitOn64System = $false
                            operationType        = "exists"
                        }
                    }
                    "productCode" {
                        $graphRules += @{
                            "@odata.type"              = "#microsoft.graph.win32LobAppProductCodeRule"
                            ruleType                   = "detection"
                            productCode                = $r.productCode
                            productVersionOperator     = "greaterThanOrEqual"
                            productVersion             = $r.productVersion
                        }
                    }
                }
            }
            if ($graphRules.Count -gt 0) {
                $Manifest.Detection = @{ Type = $codeResult.detectionType; Rules = $graphRules }
            }
        }

        $Manifest.Confidence = $codeResult.confidence
        $Manifest.Source = "ai-enhanced"

        # ===== STEP D: SANITY CHECK =====
        Write-Detail "Step 4/4: Sanity Check — validating Graph API compatibility..."
        $sanityIssues = Invoke-SanityCheck -Manifest $Manifest
        if ($sanityIssues.Count -gt 0) {
            Write-Warn "Sanity check found $($sanityIssues.Count) issue(s):"
            foreach ($si in $sanityIssues) { Write-Detail "  - $si" }
        } else {
            Write-OK "Sanity check passed — manifest is Graph API compatible"
        }

        # Store pipeline context for report generation
        $Manifest._PipelineContext = @{
            Plan = $plan
            CodeResult = $codeResult
            Review = $review
            SanityIssues = $sanityIssues
        }

        return $Manifest

    } catch {
        Write-Warn "AI pipeline failed: $($_.Exception.Message)"
        Write-Detail "Continuing with heuristic results only"
        return $Manifest
    }
}

# ---- REPORT GENERATION ----
function New-PackagingReport {
    param([string]$SourcePath, [hashtable]$Inventory, [hashtable]$Manifest, [string]$OutputPath)

    if ($NoAI -or -not $AzureOpenAIEndpoint -or -not $Manifest._PipelineContext) {
        $report = Build-HeuristicReport -SourcePath $SourcePath -Inventory $Inventory -Manifest $Manifest
    } else {
        $report = Build-AIReport -SourcePath $SourcePath -Inventory $Inventory -Manifest $Manifest
    }

    $reportPath = Join-Path $OutputPath "PackagingReport.md"
    $report | Set-Content -Path $reportPath -Encoding UTF8
    Write-OK "Packaging report saved: $reportPath"
    return $reportPath
}

function Build-HeuristicReport {
    param([string]$SourcePath, [hashtable]$Inventory, [hashtable]$Manifest)

    $detectionDetail = ($Manifest.Detection.Rules | ForEach-Object {
        if ($_.keyPath) { "- Registry: ``$($_.keyPath)\$($_.valueName)`` (operationType: $($_.operationType))" }
        elseif ($_.path) { "- File: ``$($_.path)\$($_.fileOrFolderName)`` (exists)" }
        elseif ($_.productCode) { "- MSI ProductCode: ``$($_.productCode)`` (version >= $($_.productVersion))" }
    }) -join "`n"

    return @"
# Intune Win32 App — Packaging Report

**Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
**Source:** $SourcePath
**Analysis mode:** Heuristic only (no AI)

---

## 1. Package Contents

| Metric | Value |
|--------|-------|
| Total files | $($Inventory.AllFiles.Count) |
| MSI installers | $($Inventory.MSIs.Count) |
| EXE files | $($Inventory.EXEs.Count) |
| Scripts (ps1/bat/cmd/vbs) | $($Inventory.Scripts.Count) |
| Config files | $($Inventory.Configs.Count) |
| Total size | $($Inventory.TotalSizeMB) MB |

### File listing
``````
$( ($Inventory.AllFiles | ForEach-Object { "$($_.RelPath) ($($_.SizeKB) KB)" }) -join "`n" )
``````

## 2. Entry Point Selection

**Selected setup file:** ``$($Manifest.Install.SetupFile)``

**How it was chosen:** Heuristic file ranking based on filename patterns. Priority order:
1. Batch/CMD files matching ``run*``, ``install*``, ``setup*``
2. PowerShell scripts matching ``install*``, ``setup*``, ``deploy*``, ``config*``
3. Largest EXE (if no matching scripts found)

## 3. Install Command

**Command:** ``$($Manifest.Install.CommandLine)``

**Rationale:** Determined by file extension of the entry point:
- ``.bat/.cmd`` → direct execution
- ``.ps1`` → ``powershell.exe -ExecutionPolicy Bypass -File``
- ``.msi`` → ``msiexec /i /qn /norestart``
- ``.exe`` → common silent switches (``/S /SILENT /VERYSILENT``)

## 4. Uninstall Command

**Command:** ``$($Manifest.Install.UninstallCommandLine)``

**Rationale:** No uninstall routine was detected in the package. Placeholder command used.

## 5. Detection Rules

**Type:** $($Manifest.Detection.Type)
**Confidence:** $($Manifest.Confidence)

$detectionDetail

**How detection was determined:** The script content was parsed for registry writes (``Set-ItemProperty``, ``New-ItemProperty``, ``reg add``) and file copy operations. The first relevant registry key found was selected as the detection rule.

## 6. Requirements

| Requirement | Value |
|------------|-------|
| Architecture | $($Manifest.Requirements.Architecture) |
| Minimum OS | $($Manifest.Requirements.MinOS) |

---

*Report generated by Deploy-IntuneAI (heuristic mode)*
"@
}

function Build-AIReport {
    param([string]$SourcePath, [hashtable]$Inventory, [hashtable]$Manifest)

    $fileList = ($Inventory.AllFiles | ForEach-Object { "$($_.RelPath) ($($_.SizeKB)KB)" }) -join "`n"
    
    # Get pipeline context for rich reporting
    $pipelineCtx = $Manifest._PipelineContext
    $planJson = if ($pipelineCtx.Plan) { try { $pipelineCtx.Plan | ConvertTo-Json -Depth 3 -Compress } catch { "Plan serialization failed" } } else { "Not available" }
    $codeJson = if ($pipelineCtx.CodeResult) { try { $pipelineCtx.CodeResult | ConvertTo-Json -Depth 3 -Compress } catch { "Code serialization failed" } } else { "Not available" }
    $reviewJson = if ($pipelineCtx.Review) { try { $pipelineCtx.Review | ConvertTo-Json -Depth 3 -Compress } catch { "Review serialization failed" } } else { "Not available" }
    $sanityText = if ($pipelineCtx.SanityIssues -and $pipelineCtx.SanityIssues.Count -gt 0) { $pipelineCtx.SanityIssues -join "; " } else { "All checks passed" }

    # Build a clean manifest without internal fields
    $cleanManifest = $Manifest.Clone()
    $cleanManifest.Remove('_PipelineContext')
    $manifestJson = $cleanManifest | ConvertTo-Json -Depth 5

    $reportPrompt = @"
You are a senior technical writer creating a packaging decision report for an Intune Win32 app.

This report documents the COMPLETE AI pipeline that was used to analyze and package this application. An IT admin will use this report to understand every decision, verify correctness, and troubleshoot issues.

## Source Path:
$SourcePath

## Files in package:
$fileList

## PIPELINE STEP 1 — PLAN (package analysis):
$planJson

## PIPELINE STEP 2 — CODING (configuration generation):
$codeJson

## PIPELINE STEP 3 — RUBBER DUCK REVIEW (self-critique):
$reviewJson

## PIPELINE STEP 4 — SANITY CHECK (Graph API validation):
$sanityText

## FINAL MANIFEST (what will be deployed):
$manifestJson

## Generate a detailed Markdown report with ALL of these sections:

# [App Name] — Intune Win32 App Packaging Report

## 1. Executive Summary
What this package does, who published it, one paragraph overview.

## 2. Package Contents Analysis
Table of ALL files with columns: File | Size | Role (entry point / helper / config / tool / diagnostic) | Notes.

## 3. Execution Flow
Step-by-step trace: what happens when the install command runs. Which file calls which, in what context, with what parameters. Use a numbered list.

## 4. Install Command
- The exact command chosen
- WHY this format (cmd.exe /c vs direct, etc.)
- How exit codes are propagated
- What the Intune Management Extension will see

## 5. Uninstall Command
- The exact command
- Whether a real uninstall exists or it's a placeholder
- What artifacts remain after "uninstall"

## 6. Detection Rules — Decision Process
For EACH detection candidate that was considered:
- What artifact it checks
- Why it was SELECTED or REJECTED
- False positive risk
- False negative risk
Show the final selected rule with full registry path/value.

## 7. Requirements
- OS version and why
- Architecture and why
- Any other dependencies

## 8. Rubber Duck Review Results
- Issues found (critical/warning/info)
- Corrections applied
- Overall assessment

## 9. Sanity Check Results
- Graph API validation results
- Any schema corrections applied

## 10. Risk Assessment & Testing Recommendations
- Confidence level and what drives it
- What could go wrong in production
- Recommended testing steps before broad deployment

## 11. Troubleshooting Guide
- Common failure scenarios and resolution steps
- How to verify the detection rule manually
- Log locations

Write the COMPLETE Markdown document. Be specific — reference actual file names, registry paths, command lines, and pipeline data.
"@

    try {
        $reportText = Invoke-AICall -SystemPrompt "You are a senior technical writer specializing in Microsoft Intune and endpoint management. Write comprehensive, precise, actionable Markdown reports. Include every detail from the pipeline data provided." -UserPrompt $reportPrompt -MaxTokens 5000

        # Strip markdown code fences if the model wrapped it
        $reportText = $reportText -replace '^```markdown\s*', '' -replace '\s*```$', ''

        # Append metadata footer
        $reportText += @"


---

## Metadata

| Field | Value |
|-------|-------|
| Generated | $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") |
| AI Model | $AzureOpenAIDeployment |
| AI Endpoint | $AzureOpenAIEndpoint |
| Analysis Source | $($Manifest.Source) |
| Confidence | $($Manifest.Confidence) |
| Tool | Deploy-IntuneAI |

*This report was auto-generated by [Deploy-IntuneAI](https://github.com/robgrame/Deploy-IntuneAI)*
"@
        return $reportText

    } catch {
        Write-Warn "AI report generation failed: $($_.Exception.Message). Falling back to heuristic report."
        return (Build-HeuristicReport -SourcePath $SourcePath -Inventory $Inventory -Manifest $Manifest)
    }
}

#endregion

#region ===== PHASE 3: PACKAGING =====

function New-IntuneWinPackage {
    param([string]$SourcePath, [hashtable]$Manifest, [string]$OutputPath)

    # Find or download IntuneWinAppUtil
    $iwau = Get-Command "IntuneWinAppUtil.exe" -ErrorAction SilentlyContinue
    if (-not $iwau) { $iwau = Get-Item ".\IntuneWinAppUtil.exe" -ErrorAction SilentlyContinue }
    if (-not $iwau) { $iwau = Get-Item "$env:USERPROFILE\IntuneWinAppUtil.exe" -ErrorAction SilentlyContinue }
    
    if (-not $iwau) {
        Write-Detail "Downloading IntuneWinAppUtil.exe..."
        $iwauPath = Join-Path $OutputPath "IntuneWinAppUtil.exe"
        Invoke-WebRequest -Uri "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/raw/master/IntuneWinAppUtil.exe" -OutFile $iwauPath -UseBasicParsing
        $iwau = Get-Item $iwauPath
    }

    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    $setupFile = $Manifest.Install.SetupFile

    Write-Detail "Packaging '$setupFile' from '$SourcePath'..."
    & $iwau.FullName -c $SourcePath -s $setupFile -o $OutputPath -q 2>&1 | Out-Null

    $intunewinFile = Join-Path $OutputPath ($setupFile -replace '\.[^.]+$', '.intunewin')
    if (-not (Test-Path $intunewinFile)) {
        throw "IntuneWinAppUtil failed to create package"
    }

    $size = [math]::Round((Get-Item $intunewinFile).Length / 1KB, 1)
    Write-OK "Package created: $intunewinFile ($size KB)"
    return $intunewinFile
}

#endregion

#region ===== PHASE 4: DEPLOY TO INTUNE =====

function Deploy-ToIntune {
    param([string]$IntuneWinFile, [hashtable]$Manifest)

    # Authenticate
    Write-Detail "Authenticating to Microsoft Graph..."
    Connect-MgGraph -Scopes "DeviceManagementApps.ReadWrite.All" -NoWelcome -ErrorAction Stop
    $ctx = Get-MgContext
    Write-OK "Authenticated as $($ctx.Account)"

    # Create app
    $appBody = @{
        "@odata.type"                   = "#microsoft.graph.win32LobApp"
        displayName                     = $Manifest.Metadata.DisplayName
        description                     = $Manifest.Metadata.Description
        publisher                       = $Manifest.Metadata.Publisher
        fileName                        = [System.IO.Path]::GetFileName($IntuneWinFile)
        setupFilePath                   = $Manifest.Install.SetupFile
        installCommandLine              = $Manifest.Install.CommandLine
        uninstallCommandLine            = $Manifest.Install.UninstallCommandLine
        installExperience               = @{ runAsAccount = "system"; deviceRestartBehavior = "suppress" }
        minimumSupportedOperatingSystem  = @{ $Manifest.Requirements.MinOS = $true }
        rules                           = $Manifest.Detection.Rules
        returnCodes = @(
            @{ returnCode = 0; type = "success" }
            @{ returnCode = 3010; type = "softReboot" }
            @{ returnCode = 1641; type = "hardReboot" }
            @{ returnCode = 1618; type = "retry" }
        )
    } | ConvertTo-Json -Depth 10

    $app = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps" -Body $appBody -ContentType "application/json"
    $appId = $app.id
    Write-OK "App created: $($Manifest.Metadata.DisplayName) (ID: $appId)"

    # Create content version
    $cv = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions" -Body "{}" -ContentType "application/json"
    $cvId = $cv.id

    # Extract .intunewin metadata
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::OpenRead($IntuneWinFile)
    $sr = New-Object System.IO.StreamReader(($zip.Entries | Where-Object { $_.FullName -match "Detection.xml" }).Open())
    $xml = [xml]$sr.ReadToEnd(); $sr.Close()
    $encInfo = $xml.ApplicationInfo.EncryptionInfo
    $fileSize = [long]$xml.ApplicationInfo.UnencryptedContentSize

    # Extract encrypted content to temp
    $tmpFile = [System.IO.Path]::GetTempFileName()
    $ce = $zip.Entries | Where-Object { $_.FullName -match "IntunePackage.intunewin" }
    $es = $ce.Open(); $fs = [System.IO.File]::Create($tmpFile); $es.CopyTo($fs); $fs.Close(); $es.Close(); $zip.Dispose()
    $encSize = (Get-Item $tmpFile).Length

    # Create content file
    $cfBody = @{
        "@odata.type"  = "#microsoft.graph.mobileAppContentFile"
        name           = $Manifest.Install.SetupFile
        size           = [int64]$fileSize
        sizeEncrypted  = [int64]$encSize
        isDependency   = $false
    } | ConvertTo-Json
    $cf = Invoke-MgGraphRequest -Method POST `
        -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions/$cvId/files" `
        -Body $cfBody -ContentType "application/json"
    $cfId = $cf.id

    # Wait for SAS URI
    Write-Detail "Waiting for Azure Storage URI..."
    $w = 0
    do { Start-Sleep 5; $w += 5
        $fst = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions/$cvId/files/$cfId"
    } while ($fst.uploadState -eq "azureStorageUriRequestPending" -and $w -lt 60)
    if ($fst.uploadState -ne "azureStorageUriRequestSuccess") { throw "SAS URI failed: $($fst.uploadState)" }

    # Upload in chunks
    Write-Detail "Uploading package..."
    $sasUri = $fst.azureStorageUri
    $chunkSize = 6MB; $bytes = [System.IO.File]::ReadAllBytes($tmpFile); $total = $bytes.Length
    $chunks = [Math]::Ceiling($total / $chunkSize); $blockIds = @()
    for ($i = 0; $i -lt $chunks; $i++) {
        $bid = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("block-{0:D6}" -f $i)); $blockIds += $bid
        $start = $i * $chunkSize; $len = [Math]::Min($chunkSize, $total - $start)
        $chunk = New-Object byte[] $len; [Array]::Copy($bytes, $start, $chunk, 0, $len)
        Invoke-RestMethod -Uri "$($sasUri)&comp=block&blockid=$([Uri]::EscapeDataString($bid))" -Method PUT -Headers @{"x-ms-blob-type"="BlockBlob"} -Body $chunk -ContentType "application/octet-stream" | Out-Null
    }
    $blXml = '<?xml version="1.0" encoding="utf-8"?><BlockList>' + (($blockIds | ForEach-Object { "<Latest>$_</Latest>" }) -join '') + '</BlockList>'
    Invoke-RestMethod -Uri "$($sasUri)&comp=blocklist" -Method PUT -Body $blXml -ContentType "application/xml" | Out-Null
    Write-OK "Upload complete ($chunks blocks)"

    # Commit encryption info
    $commitBody = @{ fileEncryptionInfo = @{
        encryptionKey=$encInfo.EncryptionKey; macKey=$encInfo.MacKey; initializationVector=$encInfo.InitializationVector
        mac=$encInfo.Mac; profileIdentifier=$encInfo.ProfileIdentifier; fileDigest=$encInfo.FileDigest; fileDigestAlgorithm=$encInfo.FileDigestAlgorithm
    }} | ConvertTo-Json -Depth 5
    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions/$cvId/files/$cfId/commit" -Body $commitBody -ContentType "application/json"

    Write-Detail "Waiting for commit..."
    $w = 0
    do { Start-Sleep 5; $w += 5
        $fst2 = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId/microsoft.graph.win32LobApp/contentVersions/$cvId/files/$cfId"
    } while ($fst2.uploadState -eq "commitFilePending" -and $w -lt 120)
    Write-OK "Commit: $($fst2.uploadState)"

    # Set committed version
    Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$appId" `
        -Body (@{"@odata.type"="#microsoft.graph.win32LobApp"; committedContentVersion=$cvId} | ConvertTo-Json) -ContentType "application/json"

    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
    return $appId
}

#endregion

#region ===== PHASE 5: ASSIGNMENT =====

function Set-IntuneAppAssignment {
    param([string]$AppId, [string]$Target)

    $targetObj = switch ($Target) {
        "AllDevices" { @{ "@odata.type" = "#microsoft.graph.allDevicesAssignmentTarget"; deviceAndAppManagementAssignmentFilterType = "none" } }
        "AllUsers"   { @{ "@odata.type" = "#microsoft.graph.allLicensedUsersAssignmentTarget"; deviceAndAppManagementAssignmentFilterType = "none" } }
        default      { @{ "@odata.type" = "#microsoft.graph.groupAssignmentTarget"; groupId = $Target; deviceAndAppManagementAssignmentFilterType = "none" } }
    }

    $body = @{ mobileAppAssignments = @(@{
        "@odata.type" = "#microsoft.graph.mobileAppAssignment"
        intent = "required"
        target = $targetObj
        settings = @{ "@odata.type" = "#microsoft.graph.win32LobAppAssignmentSettings"; notifications = "showAll"; deliveryOptimizationPriority = "notConfigured" }
    })} | ConvertTo-Json -Depth 10

    Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$AppId/assign" -Body $body -ContentType "application/json"
    Write-OK "Assigned to: $Target (Required)"
}

#endregion

#region ===== MAIN EXECUTION =====

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Intune Win32 AI Deployer                   " -ForegroundColor Cyan
Write-Host "  Mode: $Mode                                " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

if (-not (Test-Path $SourcePath)) { throw "Source path not found: $SourcePath" }

# Phase 1: Local Analysis
Write-Step "1/5" "Analyzing package contents..."
$inventory = Get-FileInventory -Path $SourcePath
Write-Detail "Files: $($inventory.AllFiles.Count) | MSI: $($inventory.MSIs.Count) | EXE: $($inventory.EXEs.Count) | Scripts: $($inventory.Scripts.Count) | Size: $($inventory.TotalSizeMB) MB"

$manifest = Build-LocalManifest -SourcePath $SourcePath -Inventory $inventory

# Phase 2: AI Pipeline (Plan → Code → Rubber Duck → Sanity Check)
Write-Step "2/5" "AI pipeline..."
$manifest = Invoke-AIAnalysis -SourcePath $SourcePath -Inventory $inventory -Manifest $manifest

# Show results and ask for confirmation
Write-Step "REVIEW" "Proposed configuration:" "Yellow"
Write-Host ""
Write-Host "  App Name:     $($manifest.Metadata.DisplayName)" -ForegroundColor White
Write-Host "  Publisher:    $($manifest.Metadata.Publisher)" -ForegroundColor White
Write-Host "  Description:  $($manifest.Metadata.Description)" -ForegroundColor White
Write-Host "  Setup File:   $($manifest.Install.SetupFile)" -ForegroundColor White
Write-Host "  Install:      $($manifest.Install.CommandLine)" -ForegroundColor White
Write-Host "  Uninstall:    $($manifest.Install.UninstallCommandLine)" -ForegroundColor White
Write-Host "  Detection:    $($manifest.Detection.Type) ($($manifest.Detection.Rules.Count) rule(s))" -ForegroundColor White
Write-Host "  Architecture: $($manifest.Requirements.Architecture)" -ForegroundColor White
Write-Host "  Confidence:   $($manifest.Confidence)" -ForegroundColor $(if($manifest.Confidence -eq "high"){"Green"}elseif($manifest.Confidence -eq "medium"){"Yellow"}else{"Red"})
Write-Host "  Source:       $($manifest.Source)" -ForegroundColor White
Write-Host ""

# Save manifest
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$manifestPath = Join-Path $OutputPath "manifest.json"
$manifest | ConvertTo-Json -Depth 10 | Set-Content -Path $manifestPath -Encoding UTF8
Write-Detail "Manifest saved: $manifestPath"

# Generate packaging decision report
Write-Step "REPORT" "Generating packaging decision report..."
$reportPath = New-PackagingReport -SourcePath $SourcePath -Inventory $inventory -Manifest $manifest -OutputPath $OutputPath

if ($Mode -eq "Analyze") {
    Write-Host "`nAnalysis complete. Review manifest.json and re-run with -Mode Package/Deploy/Assign." -ForegroundColor Green
    return
}

# Phase 3: Package
Write-Step "3/5" "Creating .intunewin package..."
$intunewinFile = New-IntuneWinPackage -SourcePath $SourcePath -Manifest $manifest -OutputPath $OutputPath

if ($Mode -eq "Package") {
    Write-Host "`nPackaging complete. Re-run with -Mode Deploy/Assign to upload." -ForegroundColor Green
    return
}

# Phase 4: Deploy
Write-Step "4/5" "Deploying to Intune..."
$appId = Deploy-ToIntune -IntuneWinFile $intunewinFile -Manifest $manifest

if ($Mode -eq "Deploy") {
    Write-Host "`nDeployment complete. App ID: $appId" -ForegroundColor Green
    Write-Host "Re-run with -Mode Assign to assign to devices/users." -ForegroundColor Green
    return
}

# Phase 5: Assign
Write-Step "5/5" "Assigning app..."
Set-IntuneAppAssignment -AppId $appId -Target $AssignTo

Write-Host ""
Write-Host "=============================================" -ForegroundColor Green
Write-Host "  DEPLOYMENT COMPLETE" -ForegroundColor Green
Write-Host "=============================================" -ForegroundColor Green
Write-Host "  App:        $($manifest.Metadata.DisplayName)" -ForegroundColor White
Write-Host "  App ID:     $appId" -ForegroundColor White
Write-Host "  Assigned:   $AssignTo (Required)" -ForegroundColor White
Write-Host "  Manifest:   $manifestPath" -ForegroundColor White
Write-Host "  Report:     $reportPath" -ForegroundColor White
Write-Host "=============================================" -ForegroundColor Green

#endregion
