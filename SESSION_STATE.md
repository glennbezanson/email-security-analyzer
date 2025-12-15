# Email Security Analyzer - Session State
**Saved:** 2025-12-10 18:25 EST

## Project Location
```
C:\Users\GlennBezanson\OneDrive - Edge Solutions\Work Documents\Scripts\Claude\email-security-analyzer
```

## GitHub Repository
https://github.com/glennbezanson/email-security-analyzer

## Current Status: COMPLETE & FUNCTIONAL

### What's Built
- **PyQt6 desktop application** for unified email security monitoring
- **6 tabs:** Mail Flow (primary), Dashboard, Threats, Cases, Diagnostics, Analysis
- **API integrations:**
  - Abnormal Security (threats, cases, abuse campaigns)
  - Microsoft Graph (mail flow, inbox rules, OAuth apps)
  - Exchange Online PowerShell (message trace, quarantine)
  - Claude AI via Azure APIM (threat analysis)
- **Diagnostic engine** with 15+ security rules
- **Export** to JSON, CSV, Excel, Word

### Key Feature: Mail Flow Tracing
- Search by recipient email OR sender domain
- Unified results from Exchange + Abnormal
- Visual delivery path
- Quarantine release/delete actions

## To Resume Development

### 1. Activate Environment
```powershell
cd "C:\Users\GlennBezanson\OneDrive - Edge Solutions\Work Documents\Scripts\Claude\email-security-analyzer"
venv\Scripts\activate
```

### 2. Run Application
```powershell
python main.py
```

### 3. Configure API Keys
Edit `config.json` (copy from `config.example.json` if missing):
- `abnormal.api_key` - Abnormal Security API key
- `azure.client_id` - Azure AD app client ID
- `azure.client_secret` - Azure AD app secret
- `claude.api_key` - Azure APIM subscription key

## File Structure
```
email-security-analyzer/
├── main.py                    # Entry point
├── config.json                # Your credentials (gitignored)
├── config.example.json        # Template
├── requirements.txt           # Dependencies (installed in venv/)
├── core/
│   ├── config.py              # ConfigManager
│   ├── cache.py               # SQLite cache
│   └── workers.py             # QThread workers
├── api/
│   ├── abnormal.py            # Abnormal Security client
│   ├── graph.py               # Microsoft Graph client
│   ├── exchange.py            # Exchange Online PowerShell
│   └── claude.py              # Claude AI client
├── diagnostics/
│   ├── rules.py               # 15+ diagnostic rules
│   └── engine.py              # Rule evaluation
└── ui/
    ├── styles.py              # Edge Solutions branding
    ├── main_window.py         # Main window with tabs
    ├── views/
    │   ├── mailflow.py        # Mail Flow Tracing (PRIMARY)
    │   ├── dashboard.py       # Dashboard
    │   ├── threats.py         # Threats view
    │   ├── cases.py           # Cases view
    │   ├── diagnostics.py     # Diagnostics view
    │   └── analysis.py        # AI Analysis view
    ├── widgets/               # Reusable UI components
    └── dialogs/               # Settings, Export dialogs
```

## Recent Changes (2025-12-10)
1. Initial project creation with all components
2. Added Mail Flow Tracing feature as primary tab
3. Fixed font sizes (reduced by 2 points)
4. Fixed QFontDatabase API for PyQt6
5. Fixed Exchange Online client:
   - Connection included in each PowerShell call
   - Credential escaping for security
   - Auto-disconnect cleanup

## Pending / Future Work
- None explicitly requested
- Potential enhancements:
  - Add real API credentials to test full functionality
  - Visual mail flow diagram
  - More diagnostic rules

## Git Status
```
Branch: master
Remote: origin (GitHub)
Last commit: Fix Exchange Online client issues
All changes pushed: YES
```

## Dependencies (in venv/)
- PyQt6 6.10+
- azure-identity, msal
- requests, aiohttp
- anthropic
- openpyxl, python-docx
- See requirements.txt for full list
