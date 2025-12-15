"""
Claude AI Analysis Client
Via Azure APIM endpoint
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, TYPE_CHECKING
import requests
import json
import logging

if TYPE_CHECKING:
    from .abnormal import AbnormalThreat, AbnormalCase

logger = logging.getLogger(__name__)


@dataclass
class ThreatAnalysis:
    """AI analysis result for a threat"""
    threat_id: str
    summary: str
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: float  # 0.0 - 1.0

    # Indicators
    indicators: List[str] = field(default_factory=list)
    attack_techniques: List[str] = field(default_factory=list)  # MITRE ATT&CK

    # Recommendations
    recommendations: List[str] = field(default_factory=list)
    immediate_actions: List[str] = field(default_factory=list)

    # Patterns
    patterns_detected: List[str] = field(default_factory=list)
    similar_threats: List[str] = field(default_factory=list)

    # Raw response for debugging
    raw_response: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'threat_id': self.threat_id,
            'summary': self.summary,
            'risk_level': self.risk_level,
            'confidence': self.confidence,
            'indicators': self.indicators,
            'attack_techniques': self.attack_techniques,
            'recommendations': self.recommendations,
            'immediate_actions': self.immediate_actions,
            'patterns_detected': self.patterns_detected,
            'similar_threats': self.similar_threats
        }


@dataclass
class BatchAnalysis:
    """AI analysis result for multiple threats"""
    summary: str
    total_analyzed: int
    risk_distribution: Dict[str, int]  # {CRITICAL: 2, HIGH: 5, ...}

    # Campaign detection
    campaigns_detected: List[Dict] = field(default_factory=list)
    targeted_users: List[str] = field(default_factory=list)
    targeted_departments: List[str] = field(default_factory=list)

    # Patterns
    common_indicators: List[str] = field(default_factory=list)
    attack_timeline: List[Dict] = field(default_factory=list)

    # Priority
    investigation_priority: List[str] = field(default_factory=list)  # Ordered threat IDs

    raw_response: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'summary': self.summary,
            'total_analyzed': self.total_analyzed,
            'risk_distribution': self.risk_distribution,
            'campaigns_detected': self.campaigns_detected,
            'targeted_users': self.targeted_users,
            'targeted_departments': self.targeted_departments,
            'common_indicators': self.common_indicators,
            'attack_timeline': self.attack_timeline,
            'investigation_priority': self.investigation_priority
        }


@dataclass
class DiagnosticAnalysis:
    """AI analysis of diagnostic findings"""
    summary: str
    severity: str

    root_causes: List[str] = field(default_factory=list)
    affected_services: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)

    # Documentation links
    reference_docs: List[str] = field(default_factory=list)

    raw_response: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'summary': self.summary,
            'severity': self.severity,
            'root_causes': self.root_causes,
            'affected_services': self.affected_services,
            'remediation_steps': self.remediation_steps,
            'reference_docs': self.reference_docs
        }


class ClaudeClient:
    """
    Claude AI Client via Azure APIM
    """

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        model: str = "claude-sonnet-4-20250514",
        max_tokens: int = 4096
    ):
        self.endpoint = endpoint.rstrip('/')
        self.model = model
        self.max_tokens = max_tokens
        self.session = requests.Session()
        self.session.headers.update({
            'api-key': api_key,
            'Content-Type': 'application/json',
            'anthropic-version': '2023-06-01'
        })

    def _call(self, system: str, user: str) -> str:
        """Make Claude API call"""
        payload = {
            'model': self.model,
            'max_tokens': self.max_tokens,
            'messages': [{'role': 'user', 'content': user}],
            'system': system
        }

        try:
            response = self.session.post(
                f"{self.endpoint}/messages",
                json=payload,
                timeout=120
            )
            response.raise_for_status()
            data = response.json()
            return data['content'][0]['text']
        except requests.exceptions.RequestException as e:
            logger.error(f"Claude API call failed: {e}")
            raise ClaudeAPIError(str(e))

    def _parse_json_response(self, response: str) -> Dict:
        """Extract JSON from Claude response"""
        try:
            # Handle markdown code blocks
            if '```json' in response:
                response = response.split('```json')[1].split('```')[0]
            elif '```' in response:
                response = response.split('```')[1].split('```')[0]
            return json.loads(response.strip())
        except json.JSONDecodeError:
            logger.warning("Failed to parse Claude response as JSON")
            return {}

    # =========================================================================
    # Threat Analysis
    # =========================================================================

    def analyze_threat(self, threat: 'AbnormalThreat') -> ThreatAnalysis:
        """
        Analyze a single threat for triage
        """
        system = """You are an expert email security analyst. Analyze the provided threat data and respond with a JSON object.

Your analysis should:
1. Assess the true risk level based on indicators (not just vendor classification)
2. Identify specific attack techniques (reference MITRE ATT&CK where applicable)
3. Provide actionable recommendations
4. Note any patterns that suggest campaign activity

Response format (JSON only):
{
    "summary": "Brief description of the threat (2-3 sentences)",
    "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "confidence": 0.0-1.0,
    "indicators": ["list", "of", "suspicious", "indicators"],
    "attack_techniques": ["T1566.001 - Spearphishing Attachment", ...],
    "recommendations": ["Actionable recommendation 1", ...],
    "immediate_actions": ["Block sender domain", ...],
    "patterns_detected": ["Campaign indicator", ...]
}"""

        user = f"""Analyze this email threat:

Subject: {threat.subject}
From: {threat.from_name} <{threat.from_address}>
To: {', '.join(threat.to_addresses)}
Received: {threat.received_time.isoformat()}

Vendor Classification:
- Attack Type: {threat.attack_type.value}
- Attack Strategy: {threat.attack_strategy}
- Vendor Severity: {threat.severity.value}

Technical Details:
- Return Path: {threat.return_path or 'Not available'}
- Sender IP: {threat.sender_ip or 'Not available'}
- Internet Message ID: {threat.internet_message_id or 'Not available'}

Content Analysis:
- URLs in message: {len(threat.urls)} ({', '.join(threat.urls[:3]) if threat.urls else 'None'})
- Attachments: {len(threat.attachments)} ({', '.join(a.get('fileName', 'unknown') for a in threat.attachments[:3]) if threat.attachments else 'None'})
- Impersonated Party: {threat.impersonated_party or 'None detected'}

Vendor Insights: {threat.summary_insights or 'None provided'}

Provide your analysis as JSON."""

        response = self._call(system, user)
        data = self._parse_json_response(response)

        return ThreatAnalysis(
            threat_id=threat.threat_id,
            summary=data.get('summary', response[:500]),
            risk_level=data.get('risk_level', 'MEDIUM'),
            confidence=float(data.get('confidence', 0.5)),
            indicators=data.get('indicators', []),
            attack_techniques=data.get('attack_techniques', []),
            recommendations=data.get('recommendations', []),
            immediate_actions=data.get('immediate_actions', []),
            patterns_detected=data.get('patterns_detected', []),
            raw_response=response
        )

    def analyze_threat_batch(
        self,
        threats: List['AbnormalThreat']
    ) -> BatchAnalysis:
        """
        Analyze multiple threats for patterns and campaigns
        """
        system = """You are an expert email security analyst reviewing multiple threats for pattern analysis.

Your goals:
1. Identify related threats that may be part of the same campaign
2. Find targeted users or departments
3. Detect attack escalation or progression
4. Prioritize which threats need immediate investigation

Response format (JSON only):
{
    "summary": "Overview of the threat landscape",
    "risk_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    "campaigns_detected": [
        {"name": "Campaign name", "threat_ids": [], "indicators": []}
    ],
    "targeted_users": ["user1@domain.com", ...],
    "targeted_departments": ["Finance", "Executive", ...],
    "common_indicators": ["Shared indicator 1", ...],
    "attack_timeline": [
        {"time": "ISO timestamp", "event": "Description"}
    ],
    "investigation_priority": ["threat_id_1", "threat_id_2", ...]
}"""

        # Format threats for analysis
        threats_text = "\n\n---\n\n".join([
            f"""Threat ID: {t.threat_id}
Subject: {t.subject}
From: {t.from_address}
To: {', '.join(t.to_addresses[:3])}
Type: {t.attack_type.value}
Strategy: {t.attack_strategy}
Time: {t.received_time.isoformat()}
URLs: {len(t.urls)}, Attachments: {len(t.attachments)}"""
            for t in threats[:25]  # Limit for context window
        ])

        user = f"""Analyze these {len(threats)} email threats for patterns and campaigns:

{threats_text}

Provide your analysis as JSON."""

        response = self._call(system, user)
        data = self._parse_json_response(response)

        return BatchAnalysis(
            summary=data.get('summary', response[:500]),
            total_analyzed=len(threats),
            risk_distribution=data.get('risk_distribution', {}),
            campaigns_detected=data.get('campaigns_detected', []),
            targeted_users=data.get('targeted_users', []),
            targeted_departments=data.get('targeted_departments', []),
            common_indicators=data.get('common_indicators', []),
            attack_timeline=data.get('attack_timeline', []),
            investigation_priority=data.get('investigation_priority', []),
            raw_response=response
        )

    # =========================================================================
    # Diagnostic Analysis
    # =========================================================================

    def analyze_diagnostic_findings(
        self,
        findings: List[Dict]
    ) -> DiagnosticAnalysis:
        """
        Analyze diagnostic rule findings for root cause
        """
        system = """You are an expert Microsoft 365 and email security administrator analyzing diagnostic findings.

Your goals:
1. Identify root causes for the detected issues
2. Determine which services are affected
3. Provide step-by-step remediation instructions
4. Reference official documentation where helpful

Response format (JSON only):
{
    "summary": "Brief overview of the health state",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
    "root_causes": ["Root cause 1", ...],
    "affected_services": ["Exchange Online", "Defender for Office 365", ...],
    "remediation_steps": [
        "Step 1: Do this first",
        "Step 2: Then do this",
        ...
    ],
    "reference_docs": [
        "https://learn.microsoft.com/...",
        ...
    ]
}"""

        findings_text = "\n\n".join([
            f"""Finding: {f.get('rule_name', 'Unknown')}
Severity: {f.get('severity', 'MEDIUM')}
Category: {f.get('category', 'Unknown')}
Details: {f.get('details', 'No details')}
Evidence: {f.get('evidence', 'None')}"""
            for f in findings
        ])

        user = f"""Analyze these diagnostic findings and provide remediation guidance:

{findings_text}

Provide your analysis as JSON."""

        response = self._call(system, user)
        data = self._parse_json_response(response)

        return DiagnosticAnalysis(
            summary=data.get('summary', response[:500]),
            severity=data.get('severity', 'MEDIUM'),
            root_causes=data.get('root_causes', []),
            affected_services=data.get('affected_services', []),
            remediation_steps=data.get('remediation_steps', []),
            reference_docs=data.get('reference_docs', []),
            raw_response=response
        )

    # =========================================================================
    # Reports
    # =========================================================================

    def generate_executive_summary(
        self,
        threats: List['AbnormalThreat'],
        cases: List['AbnormalCase'],
        diagnostics: List[Dict],
        mail_stats: Dict
    ) -> str:
        """
        Generate executive summary report
        """
        system = """You are preparing a daily email security briefing for IT leadership.

Requirements:
1. Keep it under 500 words
2. Lead with the most important items
3. Be direct and actionable
4. Highlight trends vs. normal activity
5. End with recommended focus areas

Use a professional but accessible tone. Avoid jargon where possible."""

        # Summarize threats
        threat_summary = self._summarize_threats(threats)

        user = f"""Generate a daily email security summary:

THREATS (Last 24 hours):
- Total: {len(threats)}
- By Type: {threat_summary['by_type']}
- By Severity: {threat_summary['by_severity']}
- Remediated: {threat_summary['remediated']}

CASES:
- Active: {len(cases)}
- Types: {', '.join(set(c.case_type for c in cases)) if cases else 'None'}

DIAGNOSTICS:
- Issues Found: {len([d for d in diagnostics if d.get('severity') in ['CRITICAL', 'HIGH']])} high/critical
- Categories: {', '.join(set(d.get('category', 'Unknown') for d in diagnostics)) if diagnostics else 'None'}

MAIL FLOW:
{json.dumps(mail_stats, indent=2, default=str)}

Generate the executive summary."""

        return self._call(system, user)

    def _summarize_threats(self, threats: List['AbnormalThreat']) -> Dict:
        """Helper to summarize threat list"""
        by_type = {}
        by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        remediated = 0

        for t in threats:
            type_name = t.attack_type.value
            by_type[type_name] = by_type.get(type_name, 0) + 1
            by_severity[t.severity.value] = by_severity.get(t.severity.value, 0) + 1
            if t.remediation_status.value in ['Remediated', 'Auto-Remediated']:
                remediated += 1

        return {
            'by_type': by_type,
            'by_severity': by_severity,
            'remediated': remediated
        }


class ClaudeAPIError(Exception):
    """Claude API error"""
    pass
