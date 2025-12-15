"""
Microsoft Graph API Client
For O365 mail flow analysis and diagnostics
API-only, no SMTP connections
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from enum import Enum
import requests
from msal import ConfidentialClientApplication
import logging

logger = logging.getLogger(__name__)


class MessageStatus(Enum):
    DELIVERED = "Delivered"
    PENDING = "Pending"
    EXPANDED = "Expanded"
    FAILED = "Failed"
    QUARANTINED = "Quarantined"
    FILTERED = "FilteredAsSpam"


@dataclass
class GraphMessage:
    """Email message from Graph API"""
    id: str
    subject: str
    sender: str
    sender_name: str
    recipients: List[str]
    received_time: datetime
    has_attachments: bool
    importance: str
    is_read: bool
    internet_message_id: str
    body_preview: str
    categories: List[str] = field(default_factory=list)

    # Authentication results (from headers)
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    compauth_result: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'subject': self.subject,
            'sender': self.sender,
            'sender_name': self.sender_name,
            'recipients': self.recipients,
            'received_time': self.received_time.isoformat(),
            'has_attachments': self.has_attachments,
            'importance': self.importance,
            'is_read': self.is_read,
            'internet_message_id': self.internet_message_id,
            'body_preview': self.body_preview,
            'categories': self.categories,
            'spf_result': self.spf_result,
            'dkim_result': self.dkim_result,
            'dmarc_result': self.dmarc_result,
            'compauth_result': self.compauth_result
        }


@dataclass
class MessageTrace:
    """Message trace result"""
    message_id: str
    message_trace_id: str
    sender: str
    recipient: str
    subject: str
    status: MessageStatus
    received_time: datetime
    size: int
    direction: str  # Inbound, Outbound

    # Delivery details
    delivery_status: Optional[str] = None
    delivery_detail: Optional[str] = None
    transport_rule_match: Optional[str] = None


@dataclass
class MailFlowStats:
    """Aggregated mail flow statistics"""
    period_days: int
    total_received: int
    total_sent: int
    spam_received: int
    malware_blocked: int
    phishing_blocked: int
    quarantined: int

    # By day breakdown
    daily_counts: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'period_days': self.period_days,
            'total_received': self.total_received,
            'total_sent': self.total_sent,
            'spam_received': self.spam_received,
            'malware_blocked': self.malware_blocked,
            'phishing_blocked': self.phishing_blocked,
            'quarantined': self.quarantined,
            'daily_counts': self.daily_counts
        }


@dataclass
class InboxRule:
    """User inbox rule"""
    id: str
    display_name: str
    sequence: int
    is_enabled: bool
    conditions: Dict[str, Any]
    actions: Dict[str, Any]

    # Security indicators
    forwards_to_external: bool = False
    deletes_messages: bool = False
    moves_to_deleted: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'display_name': self.display_name,
            'sequence': self.sequence,
            'is_enabled': self.is_enabled,
            'conditions': self.conditions,
            'actions': self.actions,
            'forwards_to_external': self.forwards_to_external,
            'deletes_messages': self.deletes_messages,
            'moves_to_deleted': self.moves_to_deleted
        }


@dataclass
class OAuthApp:
    """OAuth application with permissions"""
    app_id: str
    display_name: str
    publisher: str
    permissions: List[str]
    consent_type: str  # AdminConsent, UserConsent
    consent_time: datetime
    user_principal_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'app_id': self.app_id,
            'display_name': self.display_name,
            'publisher': self.publisher,
            'permissions': self.permissions,
            'consent_type': self.consent_type,
            'consent_time': self.consent_time.isoformat(),
            'user_principal_name': self.user_principal_name
        }


class GraphClient:
    """
    Microsoft Graph API Client

    Required Permissions (Application):
    - Mail.Read (or Mail.ReadBasic.All)
    - Reports.Read.All
    - AuditLog.Read.All
    - Directory.Read.All
    - SecurityEvents.Read.All
    """

    GRAPH_URL = "https://graph.microsoft.com/v1.0"
    GRAPH_BETA_URL = "https://graph.microsoft.com/beta"
    SCOPES = ["https://graph.microsoft.com/.default"]

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.app = ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret
        ) if client_id and client_secret else None
        self._token = None
        self._token_expires = datetime.min
        self._tenant_domains_cache = None

    def _get_token(self) -> str:
        """Get or refresh access token"""
        if not self.app:
            raise GraphAPIError("Graph client not configured - missing credentials")

        if datetime.utcnow() >= self._token_expires:
            result = self.app.acquire_token_for_client(scopes=self.SCOPES)
            if 'access_token' not in result:
                raise GraphAPIError(f"Auth failed: {result.get('error_description')}")
            self._token = result['access_token']
            # Tokens valid for 60-90 mins, refresh at 55 mins
            self._token_expires = datetime.utcnow() + timedelta(minutes=55)
        return self._token

    def _request(
        self,
        method: str,
        endpoint: str,
        beta: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """Make Graph API request"""
        base = self.GRAPH_BETA_URL if beta else self.GRAPH_URL
        url = f"{base}/{endpoint.lstrip('/')}"

        headers = {
            'Authorization': f'Bearer {self._get_token()}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.request(method, url, headers=headers, **kwargs)

            # Handle throttling
            if response.status_code == 429:
                retry_after = response.headers.get('Retry-After', 60)
                logger.warning(f"Graph API throttled, retry after {retry_after}s")
                raise ThrottlingError(f"Rate limited, retry after {retry_after}s")

            response.raise_for_status()
            return response.json() if response.content else {}

        except requests.exceptions.HTTPError as e:
            logger.error(f"Graph API error: {e.response.status_code} - {e.response.text}")
            raise GraphAPIError(f"HTTP {e.response.status_code}: {e.response.text}")
        except requests.exceptions.RequestException as e:
            logger.error(f"Graph API request failed: {e}")
            raise GraphAPIError(f"Request failed: {str(e)}")

    def _paginate(
        self,
        endpoint: str,
        max_results: int = 1000,
        **kwargs
    ) -> List[Dict]:
        """Handle Graph API pagination"""
        results = []
        next_link = None

        while len(results) < max_results:
            if next_link:
                # Extract endpoint from full URL
                response = self._request('GET', next_link.replace(self.GRAPH_URL, '').replace(self.GRAPH_BETA_URL, ''))
            else:
                response = self._request('GET', endpoint, **kwargs)

            results.extend(response.get('value', []))
            next_link = response.get('@odata.nextLink')

            if not next_link:
                break

        return results[:max_results]

    # =========================================================================
    # Mail Operations
    # =========================================================================

    def search_messages(
        self,
        query: str,
        user_id: str = None,
        top: int = 50
    ) -> List[GraphMessage]:
        """
        Search messages using KQL

        Args:
            query: KQL search query (e.g., "from:attacker@evil.com")
            user_id: Specific user mailbox or None for service context
            top: Max results
        """
        endpoint = f"users/{user_id}/messages" if user_id else "me/messages"
        params = {
            '$search': f'"{query}"',
            '$top': top,
            '$select': 'id,subject,from,toRecipients,receivedDateTime,hasAttachments,'
                      'importance,isRead,internetMessageId,bodyPreview,categories'
        }

        messages = self._request('GET', endpoint, params=params).get('value', [])
        return [self._parse_message(m) for m in messages]

    def get_message_headers(self, user_id: str, message_id: str) -> Dict[str, str]:
        """
        Get internet message headers for authentication analysis
        """
        endpoint = f"users/{user_id}/messages/{message_id}"
        params = {
            '$select': 'internetMessageHeaders'
        }

        response = self._request('GET', endpoint, params=params)
        headers = {}

        for header in response.get('internetMessageHeaders', []):
            headers[header['name'].lower()] = header['value']

        return headers

    def get_authentication_results(self, user_id: str, message_id: str) -> Dict:
        """
        Extract SPF, DKIM, DMARC results from message headers
        """
        headers = self.get_message_headers(user_id, message_id)

        auth_results = {
            'spf': None,
            'dkim': None,
            'dmarc': None,
            'compauth': None,
            'arc': None
        }

        # Parse Authentication-Results header
        auth_header = headers.get('authentication-results', '')

        if 'spf=pass' in auth_header.lower():
            auth_results['spf'] = 'pass'
        elif 'spf=fail' in auth_header.lower():
            auth_results['spf'] = 'fail'
        elif 'spf=softfail' in auth_header.lower():
            auth_results['spf'] = 'softfail'
        elif 'spf=neutral' in auth_header.lower():
            auth_results['spf'] = 'neutral'
        elif 'spf=temperror' in auth_header.lower():
            auth_results['spf'] = 'temperror'
        elif 'spf=permerror' in auth_header.lower():
            auth_results['spf'] = 'permerror'

        if 'dkim=pass' in auth_header.lower():
            auth_results['dkim'] = 'pass'
        elif 'dkim=fail' in auth_header.lower():
            auth_results['dkim'] = 'fail'

        if 'dmarc=pass' in auth_header.lower():
            auth_results['dmarc'] = 'pass'
        elif 'dmarc=fail' in auth_header.lower():
            auth_results['dmarc'] = 'fail'

        # Parse compauth from X-MS-Exchange-Organization-CompAuth
        compauth_header = headers.get('x-ms-exchange-organization-compauth', '')
        if compauth_header:
            auth_results['compauth'] = compauth_header

        return auth_results

    # =========================================================================
    # Mail Flow Reports
    # =========================================================================

    def get_mail_flow_stats(self, days: int = 7) -> MailFlowStats:
        """Get mail activity statistics"""
        period = f"D{min(days, 30)}"  # Max 30 days

        try:
            # Get email activity counts
            activity = self._request(
                'GET',
                f"reports/getEmailActivityCounts(period='{period}')",
                beta=True
            )

            stats = MailFlowStats(
                period_days=days,
                total_received=0,
                total_sent=0,
                spam_received=0,
                malware_blocked=0,
                phishing_blocked=0,
                quarantined=0
            )

            # Parse activity data
            for row in activity.get('value', []):
                stats.total_received += row.get('receive', 0)
                stats.total_sent += row.get('send', 0)

            return stats

        except GraphAPIError as e:
            logger.warning(f"Failed to get mail flow stats: {e}")
            return MailFlowStats(
                period_days=days,
                total_received=0,
                total_sent=0,
                spam_received=0,
                malware_blocked=0,
                phishing_blocked=0,
                quarantined=0
            )

    def get_threat_protection_stats(self, days: int = 7) -> Dict:
        """Get Defender for Office 365 statistics"""
        try:
            # This requires specific Defender licensing
            period = f"D{min(days, 30)}"
            response = self._request(
                'GET',
                f"reports/getOffice365ActiveUserCounts(period='{period}')",
                beta=True
            )
            return response
        except GraphAPIError:
            logger.warning("Threat protection stats not available (requires Defender license)")
            return {}

    # =========================================================================
    # Security - Inbox Rules
    # =========================================================================

    def get_inbox_rules(self, user_id: str) -> List[InboxRule]:
        """
        Get inbox rules for a user
        Critical for detecting malicious forwarding rules (MITRE T1564.008)
        """
        try:
            response = self._request('GET', f"users/{user_id}/mailFolders/inbox/messageRules")

            rules = []
            for r in response.get('value', []):
                rule = InboxRule(
                    id=r['id'],
                    display_name=r.get('displayName', ''),
                    sequence=r.get('sequence', 0),
                    is_enabled=r.get('isEnabled', False),
                    conditions=r.get('conditions', {}),
                    actions=r.get('actions', {})
                )

                # Check for suspicious actions
                actions = r.get('actions', {})
                if actions.get('forwardTo') or actions.get('forwardAsAttachmentTo'):
                    forwards = actions.get('forwardTo', []) + actions.get('forwardAsAttachmentTo', [])
                    for fwd in forwards:
                        addr = fwd.get('emailAddress', {}).get('address', '')
                        # Check if external
                        if addr and '@' in addr:
                            domain = addr.split('@')[1].lower()
                            if domain not in self._get_tenant_domains():
                                rule.forwards_to_external = True
                                break

                if actions.get('delete', False):
                    rule.deletes_messages = True

                if actions.get('moveToFolder') == 'deleteditems':
                    rule.moves_to_deleted = True

                rules.append(rule)

            return rules

        except GraphAPIError as e:
            logger.error(f"Failed to get inbox rules for {user_id}: {e}")
            return []

    def get_suspicious_rules_all_users(self, max_users: int = 100) -> List[Dict]:
        """Scan all users for suspicious inbox rules"""
        try:
            users = self._paginate('users', max_results=max_users, params={
                '$select': 'id,userPrincipalName,mail',
                '$filter': "accountEnabled eq true"
            })
        except GraphAPIError as e:
            logger.error(f"Failed to get users: {e}")
            return []

        suspicious = []

        for user in users:
            user_id = user['id']
            upn = user.get('userPrincipalName', '')

            try:
                rules = self.get_inbox_rules(user_id)
                for rule in rules:
                    if rule.forwards_to_external or rule.deletes_messages:
                        suspicious.append({
                            'user': upn,
                            'rule': rule,
                            'reason': self._get_rule_risk_reason(rule)
                        })
            except Exception as e:
                logger.debug(f"Couldn't check rules for {upn}: {e}")

        return suspicious

    # =========================================================================
    # Security - OAuth Apps
    # =========================================================================

    def get_oauth_app_consents(self, days_back: int = 30) -> List[OAuthApp]:
        """
        Get OAuth application consents
        Critical for detecting consent phishing attacks
        """
        apps = []

        try:
            # Get OAuth2PermissionGrants
            grants = self._paginate(
                'oauth2PermissionGrants',
                params={'$filter': "consentType eq 'Principal'"}
            )

            for grant in grants:
                app_info = self._get_app_info(grant.get('clientId', ''))

                apps.append(OAuthApp(
                    app_id=grant.get('clientId', ''),
                    display_name=app_info.get('displayName', 'Unknown'),
                    publisher=app_info.get('publisherName', 'Unknown'),
                    permissions=grant.get('scope', '').split(),
                    consent_type=grant.get('consentType', ''),
                    consent_time=self._parse_datetime(grant.get('startTime')),
                    user_principal_name=grant.get('principalId')
                ))

        except GraphAPIError as e:
            logger.error(f"Failed to get OAuth consents: {e}")

        return apps

    def get_risky_oauth_apps(self) -> List[OAuthApp]:
        """Get OAuth apps with risky permission combinations"""
        all_apps = self.get_oauth_app_consents()

        risky_scopes = [
            'Mail.Read', 'Mail.ReadWrite', 'Mail.Send',
            'MailboxSettings.ReadWrite', 'User.ReadBasic.All'
        ]

        risky = []
        for app in all_apps:
            risk_score = sum(1 for p in app.permissions if p in risky_scopes)
            if risk_score >= 2:
                risky.append(app)

        return risky

    # =========================================================================
    # Audit Logs
    # =========================================================================

    def get_mail_audit_events(
        self,
        user_id: str = None,
        hours_back: int = 24
    ) -> List[Dict]:
        """Get mailbox audit events"""
        from_time = (datetime.utcnow() - timedelta(hours=hours_back)).strftime('%Y-%m-%dT%H:%M:%SZ')

        filter_query = f"activityDateTime ge {from_time}"
        if user_id:
            filter_query += f" and targetResources/any(t: t/id eq '{user_id}')"

        try:
            events = self._paginate(
                'auditLogs/signIns',
                beta=True,
                params={'$filter': filter_query}
            )
            return events
        except GraphAPIError:
            logger.warning("Audit log access requires Azure AD Premium license")
            return []

    # =========================================================================
    # Helpers
    # =========================================================================

    def _get_tenant_domains(self) -> List[str]:
        """Get verified domains for the tenant"""
        if self._tenant_domains_cache:
            return self._tenant_domains_cache

        try:
            response = self._request('GET', 'domains')
            self._tenant_domains_cache = [d['id'].lower() for d in response.get('value', [])]
            return self._tenant_domains_cache
        except GraphAPIError:
            return []

    def _get_app_info(self, app_id: str) -> Dict:
        """Get app registration details"""
        try:
            return self._request('GET', f"servicePrincipals/{app_id}")
        except GraphAPIError:
            return {}

    def _parse_message(self, data: Dict) -> GraphMessage:
        """Parse Graph message response"""
        sender = data.get('from', {}).get('emailAddress', {})
        recipients = [
            r.get('emailAddress', {}).get('address', '')
            for r in data.get('toRecipients', [])
        ]

        return GraphMessage(
            id=data['id'],
            subject=data.get('subject', ''),
            sender=sender.get('address', ''),
            sender_name=sender.get('name', ''),
            recipients=recipients,
            received_time=self._parse_datetime(data.get('receivedDateTime')),
            has_attachments=data.get('hasAttachments', False),
            importance=data.get('importance', 'normal'),
            is_read=data.get('isRead', False),
            internet_message_id=data.get('internetMessageId', ''),
            body_preview=data.get('bodyPreview', ''),
            categories=data.get('categories', [])
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

    def _get_rule_risk_reason(self, rule: InboxRule) -> str:
        """Generate risk reason for suspicious rule"""
        reasons = []
        if rule.forwards_to_external:
            reasons.append("Forwards to external address")
        if rule.deletes_messages:
            reasons.append("Deletes messages automatically")
        if rule.moves_to_deleted:
            reasons.append("Moves messages to Deleted Items")
        return "; ".join(reasons) if reasons else "Unknown risk"


class GraphAPIError(Exception):
    """Graph API error"""
    pass


class ThrottlingError(GraphAPIError):
    """Rate limit exceeded"""
    pass
