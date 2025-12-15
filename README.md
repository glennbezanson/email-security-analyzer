# Email Security Analyzer

PyQt6 desktop application for unified email security monitoring and diagnostics.

![Edge Solutions](https://img.shields.io/badge/Edge%20Solutions-486D87?style=flat)
![Python](https://img.shields.io/badge/Python-3.11+-blue)
![PyQt6](https://img.shields.io/badge/PyQt6-6.6+-green)

## Overview

Combines multiple email security data sources with AI-powered analysis:

- **Abnormal Security** - Threat detection, cases, abuse mailbox campaigns
- **Microsoft Graph** - Mail flow, inbox rules, OAuth app monitoring
- **Claude AI** - Intelligent triage and pattern detection via Azure APIM

## Features

- Real-time dashboard with threat metrics
- Threat and case browsing with detail views
- Built-in diagnostic engine (15+ security checks)
- AI-powered threat analysis and batch pattern detection
- Executive summary report generation
- Edge Solutions branded interface

## Diagnostic Rules

| Category | Rules |
|----------|-------|
| Authentication | SPF PermError, DKIM missing, DMARC failures |
| Mail Flow | Connector loops, queue delays, Enhanced Filtering |
| Threat Detection | HTML smuggling, QR phishing, OAuth consent, inbox rules |
| Integration | Token expiry, rate limiting, sync delays |

## Setup

### Prerequisites

- Python 3.11+
- Azure AD App Registration with Graph permissions
- Abnormal Security API key
- Azure APIM subscription key (for Claude)

### Installation

```bash
git clone https://github.com/glennbezanson/email-security-analyzer.git
cd email-security-analyzer
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

### Configuration

```bash
cp config.example.json config.json
# Edit config.json with your credentials
```

### Required Azure AD Permissions

| Permission | Type | Purpose |
|------------|------|---------|
| Mail.Read | Application | Read mail messages |
| MailboxSettings.Read | Application | Read inbox rules |
| AuditLog.Read.All | Application | Read audit logs |
| Directory.Read.All | Application | Read user/domain info |

### Run

```bash
python main.py
```

## Environment

- **Tenant:** edge-solutions.com (YOUR_TENANT_ID)
- **APIM:** YOUR_APIM_ENDPOINT.azure-api.net/foundry
- **AI Services:** edgesol-ai

## Project Structure

```
email-security-analyzer/
├── main.py                   # Application entry point
├── config.json               # User configuration (gitignored)
├── config.example.json       # Example configuration
├── requirements.txt          # Python dependencies
├── core/                     # Core modules
│   ├── config.py            # Configuration management
│   ├── cache.py             # SQLite cache
│   └── workers.py           # QThread workers
├── api/                      # API clients
│   ├── abnormal.py          # Abnormal Security
│   ├── graph.py             # Microsoft Graph
│   └── claude.py            # Claude AI via APIM
├── diagnostics/              # Diagnostic engine
│   ├── rules.py             # Rule definitions
│   └── engine.py            # Rule evaluation
└── ui/                       # PyQt6 interface
    ├── styles.py            # Edge Solutions branding
    ├── main_window.py       # Main window
    ├── widgets/             # Reusable widgets
    ├── views/               # Application views
    └── dialogs/             # Dialog windows
```

## API Reference

### Abnormal Security

Generate API key:
1. Go to Abnormal portal > Settings > Integrations
2. Select REST API
3. Generate new token

### Microsoft Graph

Required scopes for application permissions:
- `Mail.Read`
- `MailboxSettings.Read`
- `AuditLog.Read.All`
- `Directory.Read.All`

### Claude AI

Uses Azure APIM endpoint for Claude access:
- Endpoint: `https://YOUR_APIM_ENDPOINT.azure-api.net/foundry`
- Auth: APIM subscription key

## Author

Glenn Bezanson - Edge Solutions
glenn.bezanson@edge-solutions.com

---

*Edge Solutions LLC*
