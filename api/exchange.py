"""
Exchange Online Client
Message trace and quarantine via Exchange Online PowerShell
"""

import subprocess
import json
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)


class DeliveryStatus(Enum):
    """Mail delivery status"""
    DELIVERED = "Delivered"
    QUARANTINED = "Quarantined"
    FILTERED = "Filtered"
    FAILED = "Failed"
    PENDING = "Pending"
    EXPANDED = "Expanded"
    UNKNOWN = "Unknown"


class QuarantineType(Enum):
    """Quarantine reason type"""
    SPAM = "Spam"
    PHISH = "Phish"
    MALWARE = "Malware"
    HIGH_CONFIDENCE_PHISH = "HighConfPhish"
    BULK = "Bulk"
    TRANSPORT_RULE = "TransportRule"
    UNKNOWN = "Unknown"


@dataclass
class MessageTraceEvent:
    """Single message trace event"""
    date: datetime
    event: str
    action: str
    detail: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'date': self.date.isoformat(),
            'event': self.event,
            'action': self.action,
            'detail': self.detail
        }


@dataclass
class MessageTrace:
    """Message trace result"""
    message_id: str
    message_trace_id: str
    sender: str
    recipient: str
    subject: str
    received: datetime
    status: DeliveryStatus
    from_ip: str = ""
    to_ip: str = ""
    size: int = 0
    events: List[MessageTraceEvent] = field(default_factory=list)
    source: str = "Exchange"  # Exchange or Abnormal

    def to_dict(self) -> Dict[str, Any]:
        return {
            'message_id': self.message_id,
            'message_trace_id': self.message_trace_id,
            'sender': self.sender,
            'recipient': self.recipient,
            'subject': self.subject,
            'received': self.received.isoformat(),
            'status': self.status.value,
            'from_ip': self.from_ip,
            'to_ip': self.to_ip,
            'size': self.size,
            'events': [e.to_dict() for e in self.events],
            'source': self.source
        }


@dataclass
class QuarantineMessage:
    """Quarantined message"""
    identity: str
    message_id: str
    sender: str
    recipient: str
    subject: str
    received: datetime
    quarantine_type: QuarantineType
    release_status: str
    policy_name: str = ""
    expires: Optional[datetime] = None
    source: str = "Exchange"

    def to_dict(self) -> Dict[str, Any]:
        return {
            'identity': self.identity,
            'message_id': self.message_id,
            'sender': self.sender,
            'recipient': self.recipient,
            'subject': self.subject,
            'received': self.received.isoformat(),
            'quarantine_type': self.quarantine_type.value,
            'release_status': self.release_status,
            'policy_name': self.policy_name,
            'expires': self.expires.isoformat() if self.expires else None,
            'source': self.source
        }


@dataclass
class TransportRule:
    """Exchange transport rule"""
    name: str
    priority: int
    state: str
    mode: str
    conditions: List[str]
    actions: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'priority': self.priority,
            'state': self.state,
            'mode': self.mode,
            'conditions': self.conditions,
            'actions': self.actions
        }


class ExchangeClient:
    """
    Exchange Online client using PowerShell
    Requires ExchangeOnlineManagement module
    """

    def __init__(self, tenant_id: str = "", client_id: str = "", client_secret: str = ""):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self._connected = False
        self._connection_error = ""

    def _escape_ps_string(self, s: str) -> str:
        """Escape a string for PowerShell single quotes"""
        return s.replace("'", "''")

    def _get_connection_script(self) -> str:
        """Get PowerShell script to connect to Exchange Online"""
        if not self.tenant_id or not self.client_id or not self.client_secret:
            return ""

        escaped_secret = self._escape_ps_string(self.client_secret)
        escaped_client = self._escape_ps_string(self.client_id)
        escaped_tenant = self._escape_ps_string(self.tenant_id)

        return f"""
$secureSecret = ConvertTo-SecureString '{escaped_secret}' -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential('{escaped_client}', $secureSecret)
Connect-ExchangeOnline -AppId '{escaped_client}' -Organization '{escaped_tenant}' -Credential $credential -ShowBanner:$false
"""

    def _run_powershell(self, script: str, timeout: int = 60, with_connection: bool = False) -> tuple[bool, str]:
        """Run PowerShell script and return output"""
        try:
            # Build full script with optional connection
            connection_script = ""
            if with_connection:
                connection_script = self._get_connection_script()
                if not connection_script:
                    return False, "Missing credentials for Exchange Online connection"

            full_script = f"""
$ErrorActionPreference = 'Stop'
try {{
    {connection_script}
    {script}
}} catch {{
    Write-Error $_.Exception.Message
    exit 1
}} finally {{
    if ($?) {{ Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue }}
}}
"""
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", full_script],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode != 0:
                error = result.stderr.strip() if result.stderr else "Unknown error"
                return False, error

            return True, result.stdout.strip()

        except subprocess.TimeoutExpired:
            return False, "Command timed out"
        except FileNotFoundError:
            return False, "PowerShell not found"
        except Exception as e:
            return False, str(e)

    def check_module_installed(self) -> bool:
        """Check if ExchangeOnlineManagement module is installed"""
        success, output = self._run_powershell(
            "Get-Module -ListAvailable -Name ExchangeOnlineManagement | Select-Object -First 1"
        )
        return success and bool(output)

    def connect(self) -> tuple[bool, str]:
        """Test connection to Exchange Online"""
        if not self.tenant_id or not self.client_id or not self.client_secret:
            self._connection_error = "Missing credentials for Exchange Online connection"
            return False, self._connection_error

        script = "Write-Output 'Connected'"
        success, output = self._run_powershell(script, timeout=120, with_connection=True)

        if success and "Connected" in output:
            self._connected = True
            return True, "Connected to Exchange Online"
        else:
            self._connection_error = output
            return False, output

    def get_message_trace(
        self,
        sender: str = "",
        recipient: str = "",
        sender_domain: str = "",
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        message_id: str = "",
        page_size: int = 100
    ) -> List[MessageTrace]:
        """
        Get message trace data
        Note: Message trace only goes back 10 days via PowerShell
        """
        if not start_date:
            start_date = datetime.utcnow() - timedelta(days=7)
        if not end_date:
            end_date = datetime.utcnow()

        # Build parameters
        params = [
            f"-StartDate '{start_date.strftime('%m/%d/%Y')}'",
            f"-EndDate '{end_date.strftime('%m/%d/%Y')}'",
            f"-PageSize {page_size}"
        ]

        if sender:
            params.append(f"-SenderAddress '{sender}'")
        if recipient:
            params.append(f"-RecipientAddress '{recipient}'")
        if message_id:
            params.append(f"-MessageId '{message_id}'")

        script = f"""
$results = Get-MessageTrace {' '.join(params)} | Select-Object MessageId, MessageTraceId, SenderAddress, RecipientAddress, Subject, Received, Status, FromIP, ToIP, Size
$results | ConvertTo-Json -Depth 3
"""
        success, output = self._run_powershell(script, timeout=120, with_connection=True)

        if not success:
            logger.error(f"Message trace failed: {output}")
            return []

        traces = []
        try:
            if not output:
                return []

            data = json.loads(output)
            if not isinstance(data, list):
                data = [data]

            for item in data:
                # Filter by sender domain if specified
                if sender_domain:
                    item_sender = item.get('SenderAddress', '')
                    if not item_sender.lower().endswith(f"@{sender_domain.lower()}"):
                        continue

                status_str = item.get('Status', 'Unknown')
                status = DeliveryStatus.UNKNOWN
                for s in DeliveryStatus:
                    if s.value.lower() == status_str.lower():
                        status = s
                        break

                received = datetime.fromisoformat(item['Received'].replace('Z', '+00:00')) if item.get('Received') else datetime.utcnow()

                traces.append(MessageTrace(
                    message_id=item.get('MessageId', ''),
                    message_trace_id=item.get('MessageTraceId', ''),
                    sender=item.get('SenderAddress', ''),
                    recipient=item.get('RecipientAddress', ''),
                    subject=item.get('Subject', ''),
                    received=received,
                    status=status,
                    from_ip=item.get('FromIP', ''),
                    to_ip=item.get('ToIP', ''),
                    size=item.get('Size', 0)
                ))

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse message trace: {e}")

        return traces

    def get_message_trace_detail(self, message_trace_id: str, recipient: str = "") -> List[MessageTraceEvent]:
        """Get detailed events for a message trace"""
        params = [f"-MessageTraceId '{message_trace_id}'"]
        if recipient:
            params.append(f"-RecipientAddress '{recipient}'")

        script = f"""
$results = Get-MessageTraceDetail {' '.join(params)} | Select-Object Date, Event, Action, Detail
$results | ConvertTo-Json -Depth 3
"""
        success, output = self._run_powershell(script, timeout=60, with_connection=True)

        if not success:
            logger.error(f"Message trace detail failed: {output}")
            return []

        events = []
        try:
            if not output:
                return []

            data = json.loads(output)
            if not isinstance(data, list):
                data = [data]

            for item in data:
                date = datetime.fromisoformat(item['Date'].replace('Z', '+00:00')) if item.get('Date') else datetime.utcnow()
                events.append(MessageTraceEvent(
                    date=date,
                    event=item.get('Event', ''),
                    action=item.get('Action', ''),
                    detail=item.get('Detail', '')
                ))

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse trace detail: {e}")

        return events

    def get_quarantine_messages(
        self,
        sender: str = "",
        recipient: str = "",
        sender_domain: str = "",
        quarantine_type: Optional[QuarantineType] = None,
        page_size: int = 100
    ) -> List[QuarantineMessage]:
        """Get quarantined messages"""
        params = [f"-PageSize {page_size}"]

        if sender:
            params.append(f"-SenderAddress '{sender}'")
        if recipient:
            params.append(f"-RecipientAddress '{recipient}'")
        if quarantine_type:
            params.append(f"-Type '{quarantine_type.value}'")

        script = f"""
$results = Get-QuarantineMessage {' '.join(params)} | Select-Object Identity, MessageId, SenderAddress, RecipientAddress, Subject, ReceivedTime, Type, ReleaseStatus, PolicyName, Expires
$results | ConvertTo-Json -Depth 3
"""
        success, output = self._run_powershell(script, timeout=120, with_connection=True)

        if not success:
            logger.error(f"Quarantine query failed: {output}")
            return []

        messages = []
        try:
            if not output:
                return []

            data = json.loads(output)
            if not isinstance(data, list):
                data = [data]

            for item in data:
                # Filter by sender domain if specified
                if sender_domain:
                    item_sender = item.get('SenderAddress', '')
                    if not item_sender.lower().endswith(f"@{sender_domain.lower()}"):
                        continue

                q_type = QuarantineType.UNKNOWN
                type_str = item.get('Type', '')
                for qt in QuarantineType:
                    if qt.value.lower() == type_str.lower():
                        q_type = qt
                        break

                received = datetime.fromisoformat(item['ReceivedTime'].replace('Z', '+00:00')) if item.get('ReceivedTime') else datetime.utcnow()
                expires = datetime.fromisoformat(item['Expires'].replace('Z', '+00:00')) if item.get('Expires') else None

                # Handle multiple recipients
                recipients = item.get('RecipientAddress', [])
                if isinstance(recipients, str):
                    recipients = [recipients]

                for recip in recipients:
                    messages.append(QuarantineMessage(
                        identity=item.get('Identity', ''),
                        message_id=item.get('MessageId', ''),
                        sender=item.get('SenderAddress', ''),
                        recipient=recip,
                        subject=item.get('Subject', ''),
                        received=received,
                        quarantine_type=q_type,
                        release_status=item.get('ReleaseStatus', ''),
                        policy_name=item.get('PolicyName', ''),
                        expires=expires
                    ))

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse quarantine: {e}")

        return messages

    def release_quarantine_message(self, identity: str, release_to_all: bool = False) -> tuple[bool, str]:
        """Release a message from quarantine"""
        params = [f"-Identity '{identity}'"]
        if release_to_all:
            params.append("-ReleaseToAll")

        script = f"Release-QuarantineMessage {' '.join(params)} -Confirm:$false"
        return self._run_powershell(script, with_connection=True)

    def delete_quarantine_message(self, identity: str) -> tuple[bool, str]:
        """Delete a message from quarantine"""
        script = f"Delete-QuarantineMessage -Identity '{identity}' -Confirm:$false"
        return self._run_powershell(script, with_connection=True)

    def get_transport_rules(self) -> List[TransportRule]:
        """Get transport rules"""
        script = """
$rules = Get-TransportRule | Select-Object Name, Priority, State, Mode, @{N='Conditions';E={$_.Conditions -join '; '}}, @{N='Actions';E={$_.Actions -join '; '}}
$rules | ConvertTo-Json -Depth 3
"""
        success, output = self._run_powershell(script, timeout=60, with_connection=True)

        if not success:
            logger.error(f"Transport rules query failed: {output}")
            return []

        rules = []
        try:
            if not output:
                return []

            data = json.loads(output)
            if not isinstance(data, list):
                data = [data]

            for item in data:
                conditions = item.get('Conditions', '')
                actions = item.get('Actions', '')

                rules.append(TransportRule(
                    name=item.get('Name', ''),
                    priority=item.get('Priority', 0),
                    state=item.get('State', ''),
                    mode=item.get('Mode', ''),
                    conditions=conditions.split('; ') if conditions else [],
                    actions=actions.split('; ') if actions else []
                ))

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse transport rules: {e}")

        return rules

    def disconnect(self):
        """Disconnect from Exchange Online"""
        self._run_powershell("Disconnect-ExchangeOnline -Confirm:$false")
        self._connected = False
