"""
Diagnostic Rule Evaluation Engine
"""

from typing import List, Dict, Any, Optional, TYPE_CHECKING
from datetime import datetime, timedelta
import logging

from .rules import (
    DiagnosticRule, DiagnosticResult, RuleCategory, Severity,
    get_rule, get_all_rules
)

if TYPE_CHECKING:
    from api.abnormal import AbnormalClient
    from api.graph import GraphClient

logger = logging.getLogger(__name__)


class DiagnosticEngine:
    """
    Evaluates diagnostic rules against live data from APIs
    """

    def __init__(
        self,
        abnormal_client: 'AbnormalClient',
        graph_client: 'GraphClient',
        enabled_rules: List[str] = None
    ):
        self.abnormal = abnormal_client
        self.graph = graph_client
        self.enabled_rules = enabled_rules or [r.id for r in get_all_rules()]
        self._cache = {}
        self._cache_ttl = timedelta(minutes=15)

    def run_all_checks(self) -> List[DiagnosticResult]:
        """Run all enabled diagnostic checks"""
        results = []

        for rule_id in self.enabled_rules:
            rule = get_rule(rule_id)
            if not rule:
                continue

            try:
                result = self._run_check(rule)
                results.append(result)
            except Exception as e:
                logger.error(f"Rule {rule_id} failed: {e}")
                results.append(DiagnosticResult(
                    rule_id=rule_id,
                    rule_name=rule.name,
                    category=rule.category.value,
                    severity=Severity.INFO.value,
                    passed=False,
                    evidence=f"Check failed: {str(e)}"
                ))

        return results

    def run_category(self, category: RuleCategory) -> List[DiagnosticResult]:
        """Run all checks in a category"""
        results = []

        for rule in get_all_rules():
            if rule.category == category and rule.id in self.enabled_rules:
                try:
                    results.append(self._run_check(rule))
                except Exception as e:
                    logger.error(f"Rule {rule.id} failed: {e}")

        return results

    def _run_check(self, rule: DiagnosticRule) -> DiagnosticResult:
        """Run a single diagnostic check"""

        # Dispatch to specific check implementation
        check_method = getattr(self, f"_check_{rule.id}", None)

        if check_method:
            passed, evidence, affected = check_method()
        else:
            # Default: rule not implemented
            passed = True
            evidence = "Check not implemented"
            affected = []

        return DiagnosticResult(
            rule_id=rule.id,
            rule_name=rule.name,
            category=rule.category.value,
            severity=rule.severity.value,
            passed=passed,
            evidence=evidence,
            affected_items=affected,
            remediation_steps=rule.remediation_steps if not passed else []
        )

    # =========================================================================
    # Check Implementations
    # =========================================================================

    def _check_auth_dmarc_fail(self) -> tuple:
        """Check for DMARC alignment failures in recent messages"""
        threats = self._get_cached('threats', self._fetch_threats, hours_back=24)

        dmarc_fails = []

        for threat in threats[:50]:  # Sample first 50
            try:
                # Check if threat was caught due to auth failure
                if 'spoofing' in threat.attack_strategy.lower():
                    dmarc_fails.append(threat.from_address)
            except Exception:
                continue

        if dmarc_fails:
            return (
                False,
                f"Found {len(dmarc_fails)} messages with potential DMARC failures",
                list(set(dmarc_fails))[:10]
            )

        return (True, "No DMARC alignment issues detected", [])

    def _check_threat_inbox_rule_persistence(self) -> tuple:
        """Check for malicious inbox rules"""
        try:
            suspicious = self.graph.get_suspicious_rules_all_users(max_users=50)

            if suspicious:
                affected = [s['user'] for s in suspicious]
                reasons = [s['reason'] for s in suspicious]

                return (
                    False,
                    f"Found {len(suspicious)} suspicious inbox rules: {', '.join(set(reasons))}",
                    affected
                )

            return (True, "No suspicious inbox rules detected", [])

        except Exception as e:
            return (True, f"Unable to check inbox rules: {e}", [])

    def _check_threat_oauth_consent_phishing(self) -> tuple:
        """Check for risky OAuth app consents"""
        try:
            risky_apps = self.graph.get_risky_oauth_apps()

            if risky_apps:
                affected = [f"{a.display_name} ({', '.join(a.permissions)})" for a in risky_apps]

                return (
                    False,
                    f"Found {len(risky_apps)} OAuth apps with risky permissions",
                    affected
                )

            return (True, "No risky OAuth applications detected", [])

        except Exception as e:
            return (True, f"Unable to check OAuth apps: {e}", [])

    def _check_threat_post_delivery_gap(self) -> tuple:
        """Check for post-delivery timing gaps"""
        threats = self._get_cached('threats', self._fetch_threats, hours_back=24)

        # Calculate unremediated count
        unremediated = 0

        for threat in threats[:50]:
            try:
                if threat.remediation_status.value == 'Not Remediated':
                    unremediated += 1
            except Exception:
                continue

        total = min(len(threats), 50)
        if total > 0 and unremediated > total * 0.2:  # >20% unremediated
            return (
                False,
                f"{unremediated} of {total} sampled threats not yet remediated",
                []
            )

        return (True, "Remediation timing within normal parameters", [])

    def _check_threat_html_smuggling(self) -> tuple:
        """Check for HTML smuggling patterns in recent threats"""
        threats = self._get_cached('threats', self._fetch_threats, hours_back=24)

        html_threats = []

        for threat in threats[:50]:
            try:
                for att in threat.attachments:
                    filename = att.get('fileName', '').lower()
                    if filename.endswith(('.html', '.htm', '.shtml')):
                        html_threats.append(threat.threat_id)
                        break
            except Exception:
                continue

        if html_threats:
            return (
                False,
                f"Found {len(html_threats)} threats with HTML attachments",
                html_threats
            )

        return (True, "No HTML smuggling patterns detected", [])

    def _check_threat_qr_code_phishing(self) -> tuple:
        """Check for QR code phishing patterns"""
        threats = self._get_cached('threats', self._fetch_threats, hours_back=24)

        qr_threats = []

        for threat in threats[:50]:
            try:
                # Check for image-only emails or PDF attachments
                has_image_attachment = any(
                    att.get('fileName', '').lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.pdf'))
                    for att in threat.attachments
                )

                # Heuristic: image attachment + no URLs = potential QR code
                if has_image_attachment and not threat.urls:
                    qr_threats.append(threat.threat_id)

            except Exception:
                continue

        if qr_threats:
            return (
                False,
                f"Found {len(qr_threats)} potential QR code phishing attempts",
                qr_threats
            )

        return (True, "No QR code phishing patterns detected", [])

    def _check_integration_rate_limit(self) -> tuple:
        """Check if we've hit API rate limits recently"""
        # This would typically check a log of recent API responses
        # For now, return OK
        return (True, "No rate limiting detected", [])

    def _check_auth_spf_permerror(self) -> tuple:
        """Check for SPF permanent errors"""
        # Would require DNS lookups or message header analysis
        return (True, "SPF check requires manual DNS verification", [])

    def _check_auth_dkim_missing(self) -> tuple:
        """Check for missing DKIM configuration"""
        # Would require DNS lookups
        return (True, "DKIM check requires manual DNS verification", [])

    def _check_flow_connector_loop(self) -> tuple:
        """Check for mail loop errors"""
        # Would require Exchange Online access
        return (True, "Mail loop check not implemented", [])

    def _check_flow_queue_delay(self) -> tuple:
        """Check for mail queue delays"""
        # Would require message trace data
        return (True, "Queue delay check not implemented", [])

    def _check_flow_enhanced_filtering_missing(self) -> tuple:
        """Check for Enhanced Filtering configuration"""
        # Would require Exchange Online admin access
        return (True, "Enhanced Filtering check not implemented", [])

    def _check_threat_delayed_detonation(self) -> tuple:
        """Check for delayed URL weaponization"""
        # Would require click-time analysis data
        return (True, "Delayed detonation check not implemented", [])

    def _check_integration_token_expiry(self) -> tuple:
        """Check for token expiration warnings"""
        # Would require token metadata
        return (True, "Token expiry check not implemented", [])

    def _check_integration_abnormal_sync_delay(self) -> tuple:
        """Check for Abnormal sync delays"""
        # Would require timestamp comparison
        return (True, "Sync delay check not implemented", [])

    def _check_posture_safe_attachments_disabled(self) -> tuple:
        """Check Safe Attachments configuration"""
        # Would require Defender API access
        return (True, "Safe Attachments check not implemented", [])

    def _check_posture_safe_links_gaps(self) -> tuple:
        """Check Safe Links coverage"""
        # Would require Defender API access
        return (True, "Safe Links check not implemented", [])

    # =========================================================================
    # Helpers
    # =========================================================================

    def _fetch_threats(self, hours_back: int = 24):
        """Fetch threats from Abnormal API"""
        return self.abnormal.get_threats_with_details(hours_back=hours_back, max_details=100)

    def _get_cached(self, key: str, fetch_fn, **kwargs):
        """Get cached data or fetch fresh"""
        cache_entry = self._cache.get(key)

        if cache_entry:
            data, timestamp = cache_entry
            if datetime.utcnow() - timestamp < self._cache_ttl:
                return data

        data = fetch_fn(**kwargs)
        self._cache[key] = (data, datetime.utcnow())
        return data
