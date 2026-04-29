# Deploy-IntuneAI

> AI-powered universal Intune Win32 app packager and deployer.

Analyzes any application folder — MSI, EXE, or scripts — using **local heuristics + Azure OpenAI** to automatically determine install/uninstall commands, detection rules, and requirements. Then packages as `.intunewin` and deploys to Microsoft Intune via Graph API.

## ✨ Features

- **Smart Analysis** — Automatically identifies the setup file, install commands, and detection rules
- **MSI Extraction** — Reads ProductCode, version, publisher directly from MSI metadata for high-confidence detection
- **EXE Inspection** — Extracts version info, publisher, and generates silent install switches
- **Script Analysis** — Parses PowerShell/Batch scripts to find registry writes, file paths, and service installations
- **AI Enhancement** — Uses Azure OpenAI (GPT-4o / GPT-5.x / Codex) to improve detection rules and metadata
- **Secret Redaction** — Automatically strips credentials, tokens, and base64 blobs before sending to AI
- **Phased Execution** — Run only what you need: `Analyze → Package → Deploy → Assign`
- **GPT-5.x Support** — Handles `max_completion_tokens` and newer API versions for latest models
- **Entra ID Auth** — Supports both API key and Azure AD token authentication for OpenAI

## 🚀 Quick Start

```powershell
# Clone the repo
git clone https://github.com/robgrame/Deploy-IntuneAI.git
cd Deploy-IntuneAI

# Analyze a folder (no deployment, no AI needed)
.\Deploy-IntuneAI.ps1 -SourcePath "C:\Apps\MyApp" -Mode Analyze -NoAI

# Analyze with AI enhancement
$env:AZURE_OPENAI_ENDPOINT = "https://your-instance.openai.azure.com"
$env:AZURE_OPENAI_DEPLOYMENT = "gpt-4o"
.\Deploy-IntuneAI.ps1 -SourcePath "C:\Apps\MyApp" -Mode Analyze

# Full pipeline: analyze → package → deploy → assign
.\Deploy-IntuneAI.ps1 -SourcePath "C:\Apps\MyApp" -Mode Assign -AssignTo AllDevices
```

## 📋 Modes

| Mode | What it does |
|------|-------------|
| `Analyze` | Inspect files, generate `manifest.json` — **no changes made** |
| `Package` | Analyze + create `.intunewin` package |
| `Deploy` | Analyze + Package + upload to Intune |
| `Assign` | Full pipeline including device/user assignment |

## 🔧 Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-SourcePath` | ✅ | Folder containing the app to package |
| `-Mode` | | `Analyze` (default), `Package`, `Deploy`, `Assign` |
| `-OutputPath` | | Where to save output (default: `.\IntunePackage`) |
| `-AssignTo` | | `AllDevices`, `AllUsers`, or a Group Object ID |
| `-NoAI` | | Skip AI analysis, use heuristics only |
| `-AzureOpenAIEndpoint` | | Azure OpenAI URL (or `$env:AZURE_OPENAI_ENDPOINT`) |
| `-AzureOpenAIKey` | | API key (or `$env:AZURE_OPENAI_KEY`). If empty, uses Entra ID via `az login` |
| `-AzureOpenAIDeployment` | | Model deployment name (or `$env:AZURE_OPENAI_DEPLOYMENT`) |

## 🧠 How Detection Works

The tool uses a **layered approach** — local facts first, AI fills gaps:

```
┌─────────────────────────────────────────────┐
│  1. MSI → ProductCode extraction (high)     │
│  2. EXE → File version/path (medium)        │
│  3. Script → Registry/file parsing (low)    │
│  4. AI → Contextual analysis (enhances all) │
└─────────────────────────────────────────────┘
```

| Installer Type | Detection Method | Confidence |
|---------------|------------------|------------|
| MSI | Product Code + Version | 🟢 High |
| EXE (signed) | File existence + version | 🟡 Medium |
| Script (bat/ps1) | Registry key written by script | 🟡 Medium (with AI) |
| Unknown | AI-suggested or manual | 🔴 Low |

## 📦 Package Types Supported

| Type | Install Command | Detection |
|------|----------------|-----------|
| `.msi` | `msiexec /i "app.msi" /qn /norestart` | ProductCode |
| `.exe` | `"setup.exe" /S` | File existence |
| `.bat/.cmd` | `RunConfig.bat` | Registry key |
| `.ps1` | `powershell.exe -ExecutionPolicy Bypass -File "install.ps1"` | Registry/File |

## 🔐 Authentication

### Azure OpenAI
The tool supports two auth methods (in order of preference):

1. **Entra ID (recommended)** — Just `az login`, no keys needed
2. **API Key** — Set `$env:AZURE_OPENAI_KEY`

### Microsoft Graph (for Deploy/Assign)
Uses `Connect-MgGraph` with `DeviceManagementApps.ReadWrite.All` scope.

## 📂 Output

After running, the output folder contains:

```
IntunePackage/
├── manifest.json      # Full analysis results (editable!)
└── RunConfig.intunewin # Packaged app (after Package mode)
```

> 💡 **Tip:** Run `Analyze` first, edit `manifest.json` to fine-tune detection rules or commands, then run `Deploy`.

## ⚙️ Requirements

- **PowerShell 5.1+** or **PowerShell 7+**
- **Microsoft.Graph.Authentication** module (for Deploy/Assign)
- **Azure CLI** (optional, for Entra ID auth to OpenAI)
- **IntuneWinAppUtil.exe** (auto-downloaded if not found)

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## 📄 License

[MIT](LICENSE)
