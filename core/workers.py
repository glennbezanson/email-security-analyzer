"""
QThread Workers for Async Operations
"""

from PyQt6.QtCore import QThread, pyqtSignal
from typing import Dict, List, Any
import logging

logger = logging.getLogger(__name__)


class RefreshWorker(QThread):
    """
    Worker thread for refreshing data from all sources
    """

    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, abnormal_client, graph_client, config):
        super().__init__()
        self.abnormal = abnormal_client
        self.graph = graph_client
        self.config = config

    def run(self):
        try:
            data = {}

            # Get threats from Abnormal
            self.progress.emit("Fetching threats...")
            hours_back = self.config.get('settings.threat_lookback_hours', 24)

            try:
                data['threats'] = self.abnormal.get_threats_with_details(
                    hours_back=hours_back,
                    max_details=100
                )
            except Exception as e:
                logger.error(f"Failed to fetch threats: {e}")
                data['threats'] = []

            # Get cases from Abnormal
            self.progress.emit("Fetching cases...")
            days_back = self.config.get('settings.case_lookback_days', 7)

            try:
                data['cases'] = self.abnormal.get_cases(days_back=days_back)
            except Exception as e:
                logger.error(f"Failed to fetch cases: {e}")
                data['cases'] = []

            # Get mail flow stats from Graph
            self.progress.emit("Fetching mail flow stats...")

            try:
                data['mail_stats'] = self.graph.get_mail_flow_stats(days=7)
            except Exception as e:
                logger.error(f"Failed to fetch mail stats: {e}")
                data['mail_stats'] = None

            self.finished.emit(data)

        except Exception as e:
            logger.error(f"Refresh worker failed: {e}")
            self.error.emit(str(e))


class DiagnosticWorker(QThread):
    """
    Worker thread for running diagnostic checks
    """

    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    progress = pyqtSignal(str, int, int)  # rule_name, current, total

    def __init__(self, diagnostic_engine):
        super().__init__()
        self.engine = diagnostic_engine

    def run(self):
        try:
            results = self.engine.run_all_checks()
            self.finished.emit(results)
        except Exception as e:
            logger.error(f"Diagnostic worker failed: {e}")
            self.error.emit(str(e))


class ThreatDetailsWorker(QThread):
    """
    Worker thread for fetching threat details
    """

    finished = pyqtSignal(object)
    error = pyqtSignal(str)

    def __init__(self, abnormal_client, threat_id: str):
        super().__init__()
        self.abnormal = abnormal_client
        self.threat_id = threat_id

    def run(self):
        try:
            threat = self.abnormal.get_threat_details(self.threat_id)
            self.finished.emit(threat)
        except Exception as e:
            logger.error(f"Failed to fetch threat details: {e}")
            self.error.emit(str(e))


class RemediateWorker(QThread):
    """
    Worker thread for remediating threats
    """

    finished = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, abnormal_client, threat_id: str, action: str = "remediate"):
        super().__init__()
        self.abnormal = abnormal_client
        self.threat_id = threat_id
        self.action = action

    def run(self):
        try:
            result = self.abnormal.remediate_threat(self.threat_id, self.action)
            self.finished.emit(result)
        except Exception as e:
            logger.error(f"Remediation failed: {e}")
            self.error.emit(str(e))


class InboxRulesWorker(QThread):
    """
    Worker thread for checking inbox rules
    """

    finished = pyqtSignal(list)
    error = pyqtSignal(str)
    progress = pyqtSignal(int, int)  # current, total

    def __init__(self, graph_client, max_users: int = 100):
        super().__init__()
        self.graph = graph_client
        self.max_users = max_users

    def run(self):
        try:
            suspicious = self.graph.get_suspicious_rules_all_users(self.max_users)
            self.finished.emit(suspicious)
        except Exception as e:
            logger.error(f"Inbox rules check failed: {e}")
            self.error.emit(str(e))


class OAuthAppsWorker(QThread):
    """
    Worker thread for checking OAuth apps
    """

    finished = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, graph_client):
        super().__init__()
        self.graph = graph_client

    def run(self):
        try:
            apps = self.graph.get_risky_oauth_apps()
            self.finished.emit(apps)
        except Exception as e:
            logger.error(f"OAuth apps check failed: {e}")
            self.error.emit(str(e))


class ConnectionTestWorker(QThread):
    """
    Worker thread for testing API connections
    """

    finished = pyqtSignal(dict)  # {service: {connected: bool, message: str}}

    def __init__(self, abnormal_client, graph_client, claude_client):
        super().__init__()
        self.abnormal = abnormal_client
        self.graph = graph_client
        self.claude = claude_client

    def run(self):
        results = {}

        # Test Abnormal
        try:
            self.abnormal.get_threats(hours_back=1)
            results['abnormal'] = {'connected': True, 'message': 'Connected'}
        except Exception as e:
            results['abnormal'] = {'connected': False, 'message': str(e)[:50]}

        # Test Graph
        try:
            self.graph.get_mail_flow_stats(days=1)
            results['graph'] = {'connected': True, 'message': 'Connected'}
        except Exception as e:
            results['graph'] = {'connected': False, 'message': str(e)[:50]}

        # Test Claude (simple health check)
        try:
            # Just verify the endpoint is reachable
            import requests
            response = requests.get(
                self.claude.endpoint.replace('/messages', '/health'),
                headers={'api-key': self.claude.session.headers.get('api-key')},
                timeout=5
            )
            if response.status_code in [200, 404]:  # 404 is fine, means endpoint exists
                results['claude'] = {'connected': True, 'message': 'Connected'}
            else:
                results['claude'] = {'connected': False, 'message': f'HTTP {response.status_code}'}
        except Exception as e:
            results['claude'] = {'connected': False, 'message': str(e)[:50]}

        self.finished.emit(results)
