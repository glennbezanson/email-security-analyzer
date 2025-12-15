"""
Abnormal Security REST API Client
API-only, no SMTP connections
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from enum import Enum
import requests
import logging

logger = logging.getLogger(__name__)


class AttackType(Enum):
    CREDENTIAL_PHISHING = "Credential Phishing"
    MALWARE = "Malware"
    BEC = "Business Email Compromise"
    VENDOR_FRAUD = "Vendor Fraud"
    SOCIAL_ENGINEERING = "Social Engineering"
    SPAM = "Spam"
    SCAM = "Scam"
    GRAYMAIL = "Graymail"
    UNKNOWN = "Unknown"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RemediationStatus(Enum):
    NOT_REMEDIATED = "Not Remediated"
    REMEDIATED = "Remediated"
    AUTO_REMEDIATED = "Auto-Remediated"
    PENDING = "Pending"


@dataclass
class AbnormalThreat:
    """Threat detected by Abnormal Security"""
    threat_id: str
    subject: str
    from_address: str
    from_name: str
    to_addresses: List[str]
    received_time: datetime
    attack_type: AttackType
    attack_strategy: str
    severity: Severity
    remediation_status: RemediationStatus
    is_read: bool
    summary_insights: Optional[str] = None
    impersonated_party: Optional[str] = None
    internet_message_id: Optional[str] = None
    return_path: Optional[str] = None
    sender_ip: Optional[str] = None
    urls: List[str] = field(default_factory=list)
    attachments: List[Dict] = field(default_factory=list)

    @property
    def has_attachments(self) -> bool:
        return len(self.attachments) > 0

    @property
    def has_urls(self) -> bool:
        return len(self.urls) > 0

    @property
    def is_high_severity(self) -> bool:
        return self.severity in [Severity.CRITICAL, Severity.HIGH]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'threat_id': self.threat_id,
            'subject': self.subject,
            'from_address': self.from_address,
            'from_name': self.from_name,
            'to_addresses': self.to_addresses,
            'received_time': self.received_time.isoformat(),
            'attack_type': self.attack_type.value,
            'attack_strategy': self.attack_strategy,
            'severity': self.severity.value,
            'remediation_status': self.remediation_status.value,
            'is_read': self.is_read,
            'summary_insights': self.summary_insights,
            'impersonated_party': self.impersonated_party,
            'internet_message_id': self.internet_message_id,
            'return_path': self.return_path,
            'sender_ip': self.sender_ip,
            'urls': self.urls,
            'attachments': self.attachments
        }


@dataclass
class AbnormalCase:
    """Security case from Abnormal Security"""
    case_id: str
    case_type: str  # ATO, Vendor, etc.
    severity: Severity
    status: str
    created_time: datetime
    description: str
    affected_user: Optional[str] = None
    threat_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'case_id': self.case_id,
            'case_type': self.case_type,
            'severity': self.severity.value,
            'status': self.status,
            'created_time': self.created_time.isoformat(),
            'description': self.description,
            'affected_user': self.affected_user,
            'threat_ids': self.threat_ids
        }


@dataclass
class AbuseCampaign:
    """Abuse mailbox campaign (user-reported phishing)"""
    campaign_id: str
    attack_type: str
    subject: str
    from_address: str
    first_reported: datetime
    last_reported: datetime
    report_count: int
    status: str  # Safe, Malicious, Spam, etc.
    recipients: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'campaign_id': self.campaign_id,
            'attack_type': self.attack_type,
            'subject': self.subject,
            'from_address': self.from_address,
            'first_reported': self.first_reported.isoformat(),
            'last_reported': self.last_reported.isoformat(),
            'report_count': self.report_count,
            'status': self.status,
            'recipients': self.recipients
        }


class AbnormalClient:
    """
    Abnormal Security REST API Client

    API Limits:
    - 100 threats/cases per page
    - Rate limits apply (undocumented, monitor for 429s)
    """

    def __init__(self, base_url: str, api_key: str, api_version: str = "v1"):
        self.base_url = base_url.rstrip('/')
        self.api_version = api_version
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make API request with error handling"""
        url = f"{self.base_url}/{self.api_version}/{endpoint.lstrip('/')}"

        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response.json() if response.content else {}
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 429:
                logger.warning("Abnormal API rate limit hit")
                raise RateLimitError("API rate limit exceeded")
            logger.error(f"Abnormal API error: {e.response.status_code} - {e.response.text}")
            raise APIError(f"HTTP {e.response.status_code}: {e.response.text}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Abnormal API request failed: {e}")
            raise APIError(f"Request failed: {str(e)}")

    def get_threats(
        self,
        hours_back: int = 24,
        page_size: int = 100
    ) -> List[str]:
        """
        Get threat IDs from the past N hours
        Returns list of threat_id strings for subsequent detail fetching
        """
        from_time = (datetime.utcnow() - timedelta(hours=hours_back)).isoformat() + 'Z'

        threat_ids = []
        page_number = 1

        while True:
            response = self._request(
                'GET',
                'threats',
                params={
                    'filter': f'receivedTime gte {from_time}',
                    'pageSize': page_size,
                    'pageNumber': page_number
                }
            )

            threats = response.get('threats', [])
            threat_ids.extend([t['threatId'] for t in threats])

            # Check for more pages
            if len(threats) < page_size:
                break
            page_number += 1

        logger.info(f"Retrieved {len(threat_ids)} threat IDs from last {hours_back} hours")
        return threat_ids

    def get_threat_details(self, threat_id: str) -> AbnormalThreat:
        """Get full details for a specific threat"""
        data = self._request('GET', f'threats/{threat_id}')

        # Map attack type
        attack_type_str = data.get('attackType', 'Unknown')
        try:
            attack_type = AttackType(attack_type_str)
        except ValueError:
            attack_type = AttackType.UNKNOWN

        # Determine severity based on attack type
        severity = self._calculate_severity(attack_type_str, data)

        # Map remediation status
        remediation_str = data.get('remediationStatus', 'Not Remediated')
        try:
            remediation = RemediationStatus(remediation_str)
        except ValueError:
            remediation = RemediationStatus.NOT_REMEDIATED

        return AbnormalThreat(
            threat_id=data['threatId'],
            subject=data.get('subject', ''),
            from_address=data.get('fromAddress', ''),
            from_name=data.get('fromName', ''),
            to_addresses=data.get('toAddresses', []),
            received_time=self._parse_datetime(data.get('receivedTime')),
            attack_type=attack_type,
            attack_strategy=data.get('attackStrategy', ''),
            severity=severity,
            remediation_status=remediation,
            is_read=data.get('isRead', False),
            summary_insights=data.get('summaryInsights'),
            impersonated_party=data.get('impersonatedParty'),
            internet_message_id=data.get('internetMessageId'),
            return_path=data.get('returnPath'),
            sender_ip=data.get('senderIpAddress'),
            urls=data.get('urls', []),
            attachments=data.get('attachments', [])
        )

    def get_threats_with_details(
        self,
        hours_back: int = 24,
        max_details: int = 100
    ) -> List[AbnormalThreat]:
        """
        Get threats with full details (convenience method)

        Args:
            hours_back: Hours to look back
            max_details: Maximum number of threats to fetch details for

        Returns:
            List of AbnormalThreat objects with full details
        """
        threat_ids = self.get_threats(hours_back=hours_back)
        threats = []

        for threat_id in threat_ids[:max_details]:
            try:
                threat = self.get_threat_details(threat_id)
                threats.append(threat)
            except APIError as e:
                logger.warning(f"Failed to get details for threat {threat_id}: {e}")
                continue

        return threats

    def get_cases(self, days_back: int = 7) -> List[AbnormalCase]:
        """Get Abnormal cases (ATO, vendor impersonation, etc.)"""
        from_time = (datetime.utcnow() - timedelta(days=days_back)).isoformat() + 'Z'

        cases = []

        # Get regular cases
        try:
            response = self._request('GET', 'cases', params={
                'filter': f'createdTime gte {from_time}'
            })

            for case_data in response.get('cases', []):
                try:
                    case_detail = self._request('GET', f"cases/{case_data['caseId']}")
                    cases.append(self._parse_case(case_detail))
                except APIError as e:
                    logger.warning(f"Failed to get case details: {e}")
        except APIError as e:
            logger.warning(f"Failed to get cases: {e}")

        # Get vendor cases
        try:
            vendor_response = self._request('GET', 'vendor-cases', params={
                'filter': f'createdTime gte {from_time}'
            })
            for case_data in vendor_response.get('vendorCases', []):
                try:
                    case_detail = self._request('GET', f"vendor-cases/{case_data['vendorCaseId']}")
                    cases.append(self._parse_vendor_case(case_detail))
                except APIError as e:
                    logger.warning(f"Failed to get vendor case details: {e}")
        except APIError as e:
            logger.debug("Vendor cases endpoint not available or access denied")

        logger.info(f"Retrieved {len(cases)} cases from last {days_back} days")
        return cases

    def get_abuse_campaigns(self, days_back: int = 7) -> List[AbuseCampaign]:
        """Get abuse mailbox campaigns (user-reported phishing)"""
        from_time = (datetime.utcnow() - timedelta(days=days_back)).isoformat() + 'Z'

        try:
            response = self._request('GET', 'abuse-mailbox/campaigns', params={
                'filter': f'firstReported gte {from_time}'
            })

            campaigns = []
            for c in response.get('campaigns', []):
                campaigns.append(AbuseCampaign(
                    campaign_id=c['campaignId'],
                    attack_type=c.get('attackType', 'Unknown'),
                    subject=c.get('subject', ''),
                    from_address=c.get('fromAddress', ''),
                    first_reported=self._parse_datetime(c.get('firstReported')),
                    last_reported=self._parse_datetime(c.get('lastReported')),
                    report_count=c.get('reportCount', 0),
                    status=c.get('overallStatus', 'Unknown'),
                    recipients=c.get('recipients', [])
                ))

            logger.info(f"Retrieved {len(campaigns)} abuse campaigns")
            return campaigns

        except APIError as e:
            logger.warning(f"Failed to get abuse campaigns: {e}")
            return []

    def remediate_threat(self, threat_id: str, action: str = "remediate") -> Dict:
        """
        Take remediation action on a threat
        Actions: remediate, unremediate
        """
        response = self._request(
            'POST',
            f'threats/{threat_id}/action',
            json={'action': action}
        )
        logger.info(f"Remediation action '{action}' initiated for threat {threat_id}")
        return response

    def get_action_status(self, threat_id: str, action_id: str) -> Dict:
        """Check status of an async remediation action"""
        return self._request('GET', f'threats/{threat_id}/actions/{action_id}')

    def _calculate_severity(self, attack_type: str, data: Dict) -> Severity:
        """Determine severity based on attack type and characteristics"""
        critical_types = ['Credential Phishing', 'Malware']
        high_types = ['Business Email Compromise', 'Vendor Fraud']
        medium_types = ['Social Engineering', 'Scam']

        if any(t in attack_type for t in critical_types):
            return Severity.CRITICAL
        elif any(t in attack_type for t in high_types):
            return Severity.HIGH
        elif any(t in attack_type for t in medium_types):
            return Severity.MEDIUM
        elif 'Spam' in attack_type or 'Graymail' in attack_type:
            return Severity.LOW
        return Severity.MEDIUM

    def _parse_case(self, data: Dict) -> AbnormalCase:
        """Parse case API response to model"""
        severity_str = data.get('severity', 'MEDIUM')
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.MEDIUM

        return AbnormalCase(
            case_id=data['caseId'],
            case_type=data.get('caseType', 'Unknown'),
            severity=severity,
            status=data.get('status', 'Open'),
            created_time=self._parse_datetime(data.get('createdTime')),
            description=data.get('description', ''),
            affected_user=data.get('affectedUser'),
            threat_ids=data.get('threatIds', [])
        )

    def _parse_vendor_case(self, data: Dict) -> AbnormalCase:
        """Parse vendor case to standard case model"""
        severity_str = data.get('severity', 'HIGH')
        try:
            severity = Severity(severity_str)
        except ValueError:
            severity = Severity.HIGH

        return AbnormalCase(
            case_id=data['vendorCaseId'],
            case_type='Vendor Impersonation',
            severity=severity,
            status=data.get('status', 'Open'),
            created_time=self._parse_datetime(data.get('createdTime')),
            description=data.get('description', ''),
            affected_user=data.get('recipientAddress'),
            threat_ids=[]
        )

    @staticmethod
    def _parse_datetime(dt_str: Optional[str]) -> datetime:
        """Parse ISO datetime string"""
        if not dt_str:
            return datetime.utcnow()
        try:
            return datetime.fromisoformat(dt_str.rstrip('Z'))
        except ValueError:
            return datetime.utcnow()


class APIError(Exception):
    """Base API error"""
    pass


class RateLimitError(APIError):
    """Rate limit exceeded"""
    pass
