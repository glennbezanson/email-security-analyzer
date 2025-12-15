"""
Diagnostic Rule Definitions
Based on Email Security KB research
"""

from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict, Any
from enum import Enum
from datetime import datetime


class RuleCategory(Enum):
    AUTHENTICATION = "Authentication"
    MAIL_FLOW = "Mail Flow"
    THREAT_DETECTION = "Threat Detection"
    INTEGRATION = "Integration"
    SECURITY_POSTURE = "Security Posture"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class DiagnosticRule:
    """Definition of a diagnostic check"""
    id: str
    name: str
    description: str
    category: RuleCategory
    severity: Severity

    # Check function - returns (passed: bool, evidence: str)
    check_fn: Optional[Callable] = None

    # Remediation
    remediation_steps: List[str] = field(default_factory=list)
    reference_urls: List[str] = field(default_factory=list)

    # Metadata
    mitre_techniques: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)


@dataclass
class DiagnosticResult:
    """Result of running a diagnostic rule"""
    rule_id: str
    rule_name: str
    category: str
    severity: str
    passed: bool
    evidence: str
    timestamp: datetime = field(default_factory=datetime.utcnow)

    # Extended info
    affected_items: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'category': self.category,
            'severity': self.severity,
            'passed': self.passed,
            'evidence': self.evidence,
            'timestamp': self.timestamp.isoformat(),
            'affected_items': self.affected_items,
            'remediation_steps': self.remediation_steps
        }


# =============================================================================
# Rule Definitions
# =============================================================================

DIAGNOSTIC_RULES: Dict[str, DiagnosticRule] = {}


def register_rule(rule: DiagnosticRule):
    """Register a diagnostic rule"""
    DIAGNOSTIC_RULES[rule.id] = rule
    return rule


# -----------------------------------------------------------------------------
# Authentication Rules
# -----------------------------------------------------------------------------

register_rule(DiagnosticRule(
    id="auth_spf_permerror",
    name="SPF PermError Detection",
    description="Detects SPF records exceeding the 10 DNS lookup limit",
    category=RuleCategory.AUTHENTICATION,
    severity=Severity.HIGH,
    remediation_steps=[
        "Audit current SPF record: nslookup -type=txt yourdomain.com",
        "Count include/redirect mechanisms (max 10 total)",
        "Flatten SPF by replacing includes with direct IP ranges",
        "Consider using SPF macro services for dynamic flattening",
        "Test with: https://mxtoolbox.com/spf.aspx"
    ],
    reference_urls=[
        "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-spf-configure"
    ],
    tags=["spf", "dns", "email-authentication"]
))

register_rule(DiagnosticRule(
    id="auth_dkim_missing",
    name="DKIM Not Enabled for Custom Domain",
    description="Custom domain does not have DKIM signing enabled",
    category=RuleCategory.AUTHENTICATION,
    severity=Severity.MEDIUM,
    remediation_steps=[
        "Go to Microsoft 365 Defender > Email & collaboration > Policies",
        "Select DKIM under Email authentication settings",
        "Select your custom domain",
        "Publish CNAME records for selector1 and selector2",
        "Enable DKIM signing after DNS propagation"
    ],
    reference_urls=[
        "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dkim-configure"
    ],
    tags=["dkim", "email-authentication"]
))

register_rule(DiagnosticRule(
    id="auth_dmarc_fail",
    name="DMARC Alignment Failures",
    description="Messages failing DMARC alignment (compauth=fail)",
    category=RuleCategory.AUTHENTICATION,
    severity=Severity.HIGH,
    remediation_steps=[
        "Review DMARC reports for failing sources",
        "Ensure SPF includes all legitimate sending services",
        "Configure DKIM for all sending domains",
        "Verify header From domain matches SPF/DKIM domains",
        "Consider p=quarantine before p=reject"
    ],
    reference_urls=[
        "https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/email-authentication-dmarc-configure"
    ],
    mitre_techniques=["T1566"],
    tags=["dmarc", "email-authentication", "spoofing"]
))

# -----------------------------------------------------------------------------
# Mail Flow Rules
# -----------------------------------------------------------------------------

register_rule(DiagnosticRule(
    id="flow_connector_loop",
    name="Mail Loop Detection (5.4.6/5.4.14)",
    description="Detects mail routing loops causing hop count exceeded errors",
    category=RuleCategory.MAIL_FLOW,
    severity=Severity.CRITICAL,
    remediation_steps=[
        "Check Accepted Domains - ensure proper type (Authoritative vs Internal Relay)",
        "Review connector configurations for circular routing",
        "Verify MX records point to correct endpoint",
        "Check for conflicting transport rules",
        "Run: Get-AcceptedDomain | FL Name, DomainType"
    ],
    reference_urls=[
        "https://learn.microsoft.com/en-us/exchange/troubleshoot/email-delivery/ndr/fix-error-code-5-4-6-through-5-4-20-in-exchange-online"
    ],
    tags=["mail-flow", "ndr", "connector"]
))

register_rule(DiagnosticRule(
    id="flow_queue_delay",
    name="Mail Queue Delays",
    description="Messages showing extended pending/deferred status",
    category=RuleCategory.MAIL_FLOW,
    severity=Severity.MEDIUM,
    remediation_steps=[
        "Check message trace for specific delay events",
        "Review Safe Attachments scanning settings",
        "Check for transport rule processing bottlenecks",
        "Verify connector TLS configuration",
        "Check Microsoft 365 Service Health"
    ],
    reference_urls=[
        "https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/message-trace-modern-eac"
    ],
    tags=["mail-flow", "performance", "queue"]
))

register_rule(DiagnosticRule(
    id="flow_enhanced_filtering_missing",
    name="Enhanced Filtering Not Configured",
    description="Third-party SEG in use but Enhanced Filtering for Connectors not enabled",
    category=RuleCategory.MAIL_FLOW,
    severity=Severity.HIGH,
    remediation_steps=[
        "Go to security.microsoft.com/skiplisting",
        "Configure Enhanced Filtering for inbound connectors",
        "Add third-party SEG IP ranges to skip listing",
        "This preserves original sender IP and authentication signals"
    ],
    reference_urls=[
        "https://learn.microsoft.com/en-us/exchange/mail-flow-best-practices/use-connectors-to-configure-mail-flow/enhanced-filtering-for-connectors"
    ],
    tags=["mail-flow", "connector", "seg", "authentication"]
))

# -----------------------------------------------------------------------------
# Threat Detection Rules
# -----------------------------------------------------------------------------

register_rule(DiagnosticRule(
    id="threat_post_delivery_gap",
    name="Post-Delivery Remediation Gap",
    description="Threats reaching inbox before Abnormal remediation",
    category=RuleCategory.THREAT_DETECTION,
    severity=Severity.MEDIUM,
    remediation_steps=[
        "This is expected behavior for API-based security",
        "Review auto-forwarding rules that may exfiltrate before remediation",
        "Consider ZAP (Zero-hour Auto Purge) timing",
        "Evaluate if native Microsoft protection should be primary"
    ],
    tags=["abnormal", "detection-gap", "timing"]
))

register_rule(DiagnosticRule(
    id="threat_html_smuggling",
    name="HTML Smuggling Attack Detection",
    description="HTML attachments with embedded JavaScript payloads",
    category=RuleCategory.THREAT_DETECTION,
    severity=Severity.HIGH,
    remediation_steps=[
        "Block or warn on HTML attachments from external senders",
        "Enable Safe Attachments with Dynamic Delivery",
        "Monitor for JavaScript blob creation in endpoint telemetry",
        "Consider blocking .html/.htm attachments via transport rule"
    ],
    reference_urls=[
        "https://www.microsoft.com/en-us/security/blog/2021/11/11/html-smuggling-surges/"
    ],
    mitre_techniques=["T1027.006"],
    tags=["html-smuggling", "evasion", "malware"]
))

register_rule(DiagnosticRule(
    id="threat_qr_code_phishing",
    name="QR Code Phishing (Quishing)",
    description="QR codes in emails directing to credential harvesting",
    category=RuleCategory.THREAT_DETECTION,
    severity=Severity.HIGH,
    remediation_steps=[
        "Most email scanners cannot decode QR codes",
        "Educate users on QR code risks",
        "Consider blocking image-only emails from first-time senders",
        "Monitor for PDF attachments containing QR codes"
    ],
    mitre_techniques=["T1566.001"],
    tags=["quishing", "qr-code", "phishing", "evasion"]
))

register_rule(DiagnosticRule(
    id="threat_delayed_detonation",
    name="Delayed URL Weaponization",
    description="URLs weaponized after delivery-time scanning",
    category=RuleCategory.THREAT_DETECTION,
    severity=Severity.HIGH,
    remediation_steps=[
        "Ensure Safe Links is configured for click-time verification",
        "Enable Safe Links for internal messages",
        "Review Safe Links policies for excluded URLs",
        "Consider time-of-click URL sandboxing"
    ],
    reference_urls=[
        "https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-configure"
    ],
    mitre_techniques=["T1566.002"],
    tags=["safe-links", "url", "phishing", "evasion"]
))

register_rule(DiagnosticRule(
    id="threat_inbox_rule_persistence",
    name="Malicious Inbox Rule Detection",
    description="Inbox rules forwarding to external or deleting security alerts",
    category=RuleCategory.THREAT_DETECTION,
    severity=Severity.CRITICAL,
    remediation_steps=[
        "Audit all inbox rules: Get-InboxRule -Mailbox user@domain.com",
        "Look for: ForwardTo, RedirectTo, DeleteMessage actions",
        "Check for rules filtering security keywords",
        "Remove suspicious rules and reset user password",
        "Enable mailbox auditing for rule changes"
    ],
    mitre_techniques=["T1564.008", "T1114.003"],
    tags=["inbox-rules", "persistence", "exfiltration"]
))

register_rule(DiagnosticRule(
    id="threat_oauth_consent_phishing",
    name="Risky OAuth Application Consent",
    description="OAuth apps with excessive mail permissions",
    category=RuleCategory.THREAT_DETECTION,
    severity=Severity.CRITICAL,
    remediation_steps=[
        "Review app permissions in Azure AD > Enterprise applications",
        "Revoke consent for suspicious applications",
        "Enable admin consent workflow",
        "Block user consent for unverified publishers",
        "Monitor for new OAuth grants in audit logs"
    ],
    reference_urls=[
        "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent"
    ],
    mitre_techniques=["T1550.001"],
    tags=["oauth", "consent-phishing", "persistence"]
))

# -----------------------------------------------------------------------------
# Integration Rules
# -----------------------------------------------------------------------------

register_rule(DiagnosticRule(
    id="integration_token_expiry",
    name="API Token Expiration Warning",
    description="OAuth refresh tokens approaching 90-day inactivity limit",
    category=RuleCategory.INTEGRATION,
    severity=Severity.MEDIUM,
    remediation_steps=[
        "Refresh tokens before 90-day inactivity window",
        "Implement token validation before API calls",
        "Set up monitoring for token refresh failures",
        "Store refresh tokens securely (Azure Key Vault)"
    ],
    tags=["oauth", "token", "integration"]
))

register_rule(DiagnosticRule(
    id="integration_rate_limit",
    name="API Rate Limiting Detected",
    description="API calls being throttled (HTTP 429)",
    category=RuleCategory.INTEGRATION,
    severity=Severity.MEDIUM,
    remediation_steps=[
        "Implement exponential backoff on 429 responses",
        "Check Retry-After header for wait time",
        "Batch API calls where possible",
        "Review x-ms-throttle-information header for specific limits",
        "Consider using delta queries to reduce call volume"
    ],
    reference_urls=[
        "https://learn.microsoft.com/en-us/graph/throttling"
    ],
    tags=["api", "throttling", "performance"]
))

register_rule(DiagnosticRule(
    id="integration_abnormal_sync_delay",
    name="Abnormal Security Sync Delay",
    description="Significant delay between email receipt and Abnormal processing",
    category=RuleCategory.INTEGRATION,
    severity=Severity.LOW,
    remediation_steps=[
        "This is normal for API-based architecture (post-delivery)",
        "Monitor Abnormal status page for service incidents",
        "Verify API connectivity and authentication",
        "Check for tenant-specific processing delays"
    ],
    tags=["abnormal", "sync", "latency"]
))

# -----------------------------------------------------------------------------
# Security Posture Rules
# -----------------------------------------------------------------------------

register_rule(DiagnosticRule(
    id="posture_safe_attachments_disabled",
    name="Safe Attachments Not Enabled",
    description="Defender for Office 365 Safe Attachments not configured",
    category=RuleCategory.SECURITY_POSTURE,
    severity=Severity.HIGH,
    remediation_steps=[
        "Enable Safe Attachments in Defender portal",
        "Configure Dynamic Delivery for minimal delay",
        "Apply policy to all recipients",
        "Enable Safe Documents for Office clients"
    ],
    reference_urls=[
        "https://learn.microsoft.com/en-us/defender-office-365/safe-attachments-policies-configure"
    ],
    tags=["safe-attachments", "defender", "malware"]
))

register_rule(DiagnosticRule(
    id="posture_safe_links_gaps",
    name="Safe Links Coverage Gaps",
    description="Safe Links not protecting all click scenarios",
    category=RuleCategory.SECURITY_POSTURE,
    severity=Severity.MEDIUM,
    remediation_steps=[
        "Enable Safe Links for email messages",
        "Enable Safe Links for Microsoft Teams",
        "Enable Safe Links for Office apps",
        "Review excluded URLs list for over-permissiveness",
        "Enable 'Do not allow users to click through'"
    ],
    reference_urls=[
        "https://learn.microsoft.com/en-us/defender-office-365/safe-links-policies-configure"
    ],
    tags=["safe-links", "defender", "phishing"]
))


def get_rule(rule_id: str) -> Optional[DiagnosticRule]:
    """Get rule by ID"""
    return DIAGNOSTIC_RULES.get(rule_id)


def get_rules_by_category(category: RuleCategory) -> List[DiagnosticRule]:
    """Get all rules in a category"""
    return [r for r in DIAGNOSTIC_RULES.values() if r.category == category]


def get_all_rules() -> List[DiagnosticRule]:
    """Get all registered rules"""
    return list(DIAGNOSTIC_RULES.values())
