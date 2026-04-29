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

#region ===== PHASE 2: AI ENHANCEMENT =====

function Invoke-AIAnalysis {
    param([string]$SourcePath, [hashtable]$Inventory, [hashtable]$Manifest)

    if ($NoAI) { return $Manifest }

    # Support both API key and Entra ID auth
    $authHeaders = @{ "Content-Type" = "application/json" }
    if ($AzureOpenAIKey) {
        $authHeaders["api-key"] = $AzureOpenAIKey
    } else {
        # Try Entra ID token via az CLI
        try {
            $token = (az account get-access-token --resource "https://cognitiveservices.azure.com" --query "accessToken" -o tsv 2>$null)
            if ($token) { $authHeaders["Authorization"] = "Bearer $token" }
        } catch {}
    }

    if (-not $AzureOpenAIEndpoint) {
        Write-Warn "Azure OpenAI not configured. Set AZURE_OPENAI_ENDPOINT or use -AzureOpenAIEndpoint."
        return $Manifest
    }
    if (-not $authHeaders.ContainsKey("api-key") -and -not $authHeaders.ContainsKey("Authorization")) {
        Write-Warn "No Azure OpenAI credentials. Set AZURE_OPENAI_KEY or login with 'az login'."
        return $Manifest
    }

    Write-Detail "Preparing AI analysis request..."

    # Build safe context (no secrets, summarized)
    $fileList = ($Inventory.AllFiles | ForEach-Object { "$($_.RelPath) ($($_.SizeKB)KB)" }) -join "`n"
    
    # Collect ALL scripts (not just first 3), prioritizing entry points
    $scriptSummaries = @()
    $orderedScripts = @()
    $orderedScripts += $Inventory.Scripts | Where-Object { $_.Name -match "(?i)(runconfig|install|setup|deploy)" }
    $orderedScripts += $Inventory.Scripts | Where-Object { $_.Name -match "(?i)(config|main|start)" -and $_ -notin $orderedScripts }
    $orderedScripts += $Inventory.Scripts | Where-Object { $_ -notin $orderedScripts }
    
    $totalChars = 0
    $maxTotalChars = 15000  # Budget for all scripts combined
    foreach ($s in $orderedScripts) {
        $path = Join-Path $SourcePath $s.RelPath
        $content = Get-Content $path -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        
        # Redact potential secrets
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

    $currentManifest = $Manifest | ConvertTo-Json -Depth 5

    $systemPrompt = @"
You are a senior Microsoft Intune packaging engineer. Your job is to analyze application packages and produce precise Win32 app configurations for deployment via Microsoft Intune.

## Your expertise includes:
- Identifying the correct setup file (entry point) in multi-file packages
- Determining silent install/uninstall command lines for MSI, EXE, BAT, PS1 installers
- Designing reliable detection rules that confirm the app IS installed (not just that files exist)
- Understanding how scripts modify Windows: registry writes, file copies, service installations, scheduled tasks

## Critical rules for detection:
- Detection rules must verify the OUTCOME of the installation, not prerequisites
- For scripts that write registry keys, identify the MOST SPECIFIC key/value the script creates or modifies
- Prefer registry detection over file detection when the script writes to the registry
- If the script sets a registry value to a specific number (e.g., 1), use integerComparison with operator "equal"
- If the script just creates a key, use "exists"
- NEVER use generic OS registry keys (like HKLM\Hardware) as detection — these always exist
- The keyPath must use full format: HKEY_LOCAL_MACHINE\... (not HKLM:\...)

## Critical rules for install commands:
- For .bat/.cmd files: use "cmd.exe /c <filename>" to ensure proper execution and exit code propagation
- For .ps1 files: use "powershell.exe -ExecutionPolicy Bypass -File <filename>"
- For .msi files: use "msiexec /i <filename> /qn /norestart"
- For .exe files: determine the installer framework (NSIS, InnoSetup, InstallShield, WiX) and use appropriate silent switches
- If a .bat launcher calls a .ps1 script, the .bat is the entry point (not the .ps1)

## Critical rules for uninstall:
- If the package has no uninstall capability, use: cmd.exe /c echo No uninstall available
- For MSI: msiexec /x {ProductCode} /qn /norestart
- Never invent an uninstall command that doesn't exist in the package
"@

    $prompt = @"
Analyze this application package for Intune Win32 app deployment.

## File inventory:
$fileList

## Script/file contents:
$($scriptSummaries -join "`n`n")

## Current heuristic analysis (may be inaccurate):
$currentManifest

## Instructions:
1. READ the script contents carefully. Identify what the scripts DO (not just what files exist).
2. Trace the execution flow: which file is the entry point? What does it call? What registry keys does it write?
3. Identify the BEST detection rule — a registry key/value that ONLY exists AFTER this script runs successfully.
4. Determine the correct install command line based on the entry point file type.
5. Check if an uninstall routine exists in the package.

## Return ONLY a valid JSON object:
{
  "displayName": "Human-friendly app name based on script purpose",
  "publisher": "Publisher/vendor (read from script headers or metadata)",
  "description": "What this package does when installed (1-2 sentences)",
  "installCommandLine": "Exact silent install command",
  "uninstallCommandLine": "Exact silent uninstall command or placeholder",
  "detectionType": "registry|file|productCode",
  "detectionRules": [
    {
      "type": "registry",
      "keyPath": "HKEY_LOCAL_MACHINE\\full\\path\\to\\key",
      "valueName": "ValueName",
      "operator": "exists|equal|greaterThanOrEqual",
      "comparisonValue": "value if using equal/comparison, omit for exists"
    }
  ],
  "minOS": "1803|1903|2004|21H1|21H2|22H2",
  "architecture": "x64|x86|all",
  "confidence": "high|medium|low",
  "reasoning": "Step-by-step explanation: 1) entry point identification 2) execution flow 3) detection rule justification"
}
"@

    try {
        $aiBody = @{
            messages = @(
                @{ role = "system"; content = $systemPrompt }
                @{ role = "user"; content = $prompt }
            )
            temperature = 0.1
        }
        # GPT-5.x models use max_completion_tokens, older models use max_tokens
        if ($AzureOpenAIDeployment -match "gpt-5|o4|codex") {
            $aiBody["max_completion_tokens"] = 2000
        } else {
            $aiBody["max_tokens"] = 2000
        }
        $aiBody = $aiBody | ConvertTo-Json -Depth 5

        $apiVersion = if ($AzureOpenAIDeployment -match "gpt-5|o4|codex") { "2025-04-01-preview" } else { "2024-02-15-preview" }
        $uri = "$AzureOpenAIEndpoint/openai/deployments/$AzureOpenAIDeployment/chat/completions?api-version=$apiVersion"
        
        $response = Invoke-RestMethod -Uri $uri -Method POST -Headers $authHeaders -Body $aiBody -TimeoutSec 60
        $aiText = $response.choices[0].message.content
        
        # Extract JSON from response
        if ($aiText -match '```json\s*([\s\S]*?)\s*```') { $aiText = $Matches[1] }
        $aiResult = $aiText | ConvertFrom-Json

        Write-OK "AI analysis complete (confidence: $($aiResult.confidence))"
        Write-Detail "AI reasoning: $($aiResult.reasoning)"

        # Merge AI results into manifest (AI fills gaps, doesn't override high-confidence local data)
        if ($Manifest.Confidence -ne "high") {
            if ($aiResult.displayName) { $Manifest.Metadata.DisplayName = $aiResult.displayName }
            if ($aiResult.publisher) { $Manifest.Metadata.Publisher = $aiResult.publisher }
            if ($aiResult.installCommandLine) { $Manifest.Install.CommandLine = $aiResult.installCommandLine }
            if ($aiResult.uninstallCommandLine) { $Manifest.Install.UninstallCommandLine = $aiResult.uninstallCommandLine }
        }
        if ($aiResult.description) { $Manifest.Metadata.Description = $aiResult.description }

        # AI detection rules only if local detection is low confidence
        if ($Manifest.Confidence -eq "low" -and $aiResult.detectionRules) {
            $graphRules = @()
            foreach ($r in $aiResult.detectionRules) {
                switch ($r.type) {
                    "registry" {
                        $graphRules += @{
                            "@odata.type"        = "#microsoft.graph.win32LobAppRegistryRule"
                            ruleType             = "detection"
                            check32BitOn64System = $false
                            keyPath              = $r.keyPath
                            valueName            = $r.valueName
                            operationType        = if ($r.operator -eq "exists") { "exists" } else { "integerComparison" }
                            operator             = if ($r.operator -and $r.operator -ne "exists") { $r.operator } else { "notConfigured" }
                            comparisonValue      = if ($r.comparisonValue) { $r.comparisonValue } else { $null }
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
                $Manifest.Detection = @{ Type = $aiResult.detectionType; Rules = $graphRules }
            }
        }

        $Manifest.Confidence = $aiResult.confidence
        $Manifest.Source = "ai-enhanced"
        return $Manifest

    } catch {
        Write-Warn "AI analysis failed: $($_.Exception.Message)"
        Write-Detail "Continuing with heuristic results only"
        return $Manifest
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

# Phase 2: AI Enhancement
Write-Step "2/5" "AI analysis..." 
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
Write-Host "=============================================" -ForegroundColor Green

#endregion
