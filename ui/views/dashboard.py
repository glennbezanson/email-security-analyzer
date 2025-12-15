"""
Dashboard View
Overview of email security status
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QFrame, QLabel, QScrollArea
)
from PyQt6.QtCore import Qt
from typing import Dict, List, Any

from ..styles import EdgeColors
from ..widgets import MetricCard, SeverityMetricCard, StatusCard


class DashboardView(QWidget):
    """
    Main dashboard view with metrics and status overview
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self._setup_ui()

    def _setup_ui(self):
        """Setup dashboard layout"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        # Scroll area for dashboard content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(16)

        # Top metrics row
        metrics_row = QHBoxLayout()
        metrics_row.setSpacing(16)

        self.threats_card = MetricCard(
            title="THREATS (24H)",
            value="0",
            subtitle="Loading...",
            accent=True
        )
        metrics_row.addWidget(self.threats_card)

        self.cases_card = MetricCard(
            title="ACTIVE CASES",
            value="0",
            subtitle="Loading..."
        )
        metrics_row.addWidget(self.cases_card)

        self.remediated_card = MetricCard(
            title="REMEDIATED",
            value="0%",
            subtitle="Loading..."
        )
        metrics_row.addWidget(self.remediated_card)

        self.diagnostics_card = MetricCard(
            title="DIAGNOSTICS",
            value="--",
            subtitle="Not run yet"
        )
        metrics_row.addWidget(self.diagnostics_card)

        content_layout.addLayout(metrics_row)

        # Second row - severity breakdown and status
        details_row = QHBoxLayout()
        details_row.setSpacing(16)

        # Severity breakdown
        self.severity_card = SeverityMetricCard(title="THREAT SEVERITY")
        details_row.addWidget(self.severity_card)

        # Connection status
        status_container = QFrame()
        status_container.setObjectName("card")
        status_layout = QVBoxLayout(status_container)
        status_layout.setContentsMargins(16, 16, 16, 16)
        status_layout.setSpacing(12)

        status_title = QLabel("CONNECTION STATUS")
        status_title.setStyleSheet(f"""
            font-size: 10px;
            font-weight: 500;
            color: {EdgeColors.TEXT_SECONDARY};
            text-transform: uppercase;
            letter-spacing: 1px;
        """)
        status_layout.addWidget(status_title)

        self.abnormal_status = StatusCard("Abnormal Security")
        status_layout.addWidget(self.abnormal_status)

        self.graph_status = StatusCard("Microsoft Graph")
        status_layout.addWidget(self.graph_status)

        self.claude_status = StatusCard("Claude AI (APIM)")
        status_layout.addWidget(self.claude_status)

        status_layout.addStretch()

        details_row.addWidget(status_container)

        # Attack types breakdown
        attacks_container = QFrame()
        attacks_container.setObjectName("card")
        attacks_layout = QVBoxLayout(attacks_container)
        attacks_layout.setContentsMargins(16, 16, 16, 16)
        attacks_layout.setSpacing(12)

        attacks_title = QLabel("ATTACK TYPES (24H)")
        attacks_title.setStyleSheet(f"""
            font-size: 10px;
            font-weight: 500;
            color: {EdgeColors.TEXT_SECONDARY};
            text-transform: uppercase;
            letter-spacing: 1px;
        """)
        attacks_layout.addWidget(attacks_title)

        self.attack_labels = {}
        attack_types = [
            "Credential Phishing",
            "Business Email Compromise",
            "Malware",
            "Social Engineering",
            "Spam/Graymail"
        ]

        for attack_type in attack_types:
            row = QHBoxLayout()
            label = QLabel(attack_type)
            label.setStyleSheet(f"color: {EdgeColors.TEXT_PRIMARY}; font-size: 10px;")
            row.addWidget(label)
            row.addStretch()
            count = QLabel("0")
            count.setStyleSheet(f"color: {EdgeColors.TEXT_PRIMARY}; font-weight: 600;")
            row.addWidget(count)
            self.attack_labels[attack_type] = count
            attacks_layout.addLayout(row)

        attacks_layout.addStretch()

        details_row.addWidget(attacks_container)

        content_layout.addLayout(details_row)

        # Recent activity section
        activity_container = QFrame()
        activity_container.setObjectName("card")
        activity_layout = QVBoxLayout(activity_container)
        activity_layout.setContentsMargins(16, 16, 16, 16)
        activity_layout.setSpacing(12)

        activity_title = QLabel("RECENT ACTIVITY")
        activity_title.setStyleSheet(f"""
            font-size: 10px;
            font-weight: 500;
            color: {EdgeColors.TEXT_SECONDARY};
            text-transform: uppercase;
            letter-spacing: 1px;
        """)
        activity_layout.addWidget(activity_title)

        self.activity_list = QVBoxLayout()
        self.activity_list.setSpacing(8)
        activity_layout.addLayout(self.activity_list)

        # Placeholder for empty state
        self.empty_label = QLabel("No recent activity")
        self.empty_label.setStyleSheet(f"""
            color: {EdgeColors.TEXT_SECONDARY};
            font-style: italic;
            padding: 20px;
        """)
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        activity_layout.addWidget(self.empty_label)

        activity_layout.addStretch()

        content_layout.addWidget(activity_container)
        content_layout.addStretch()

        scroll.setWidget(content)
        layout.addWidget(scroll)

    def update_data(self, data: Dict[str, Any]):
        """Update dashboard with new data"""
        threats = data.get('threats', [])
        cases = data.get('cases', [])
        diagnostics = data.get('diagnostics', [])

        # Update threat count
        self.threats_card.set_value(str(len(threats)))

        # Calculate severity breakdown
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        attack_counts = {}
        remediated = 0

        for threat in threats:
            severity_counts[threat.severity.value] = severity_counts.get(threat.severity.value, 0) + 1

            attack_type = threat.attack_type.value
            attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1

            if threat.remediation_status.value in ['Remediated', 'Auto-Remediated']:
                remediated += 1

        self.severity_card.set_counts(severity_counts)

        # Update remediation rate
        if threats:
            rate = int((remediated / len(threats)) * 100)
            self.remediated_card.set_value(f"{rate}%")
            self.remediated_card.set_subtitle(f"{remediated} of {len(threats)}")
        else:
            self.remediated_card.set_value("--")
            self.remediated_card.set_subtitle("No threats")

        # Update attack type counts
        for attack_type, label in self.attack_labels.items():
            count = attack_counts.get(attack_type, 0)
            label.setText(str(count))

        # Update cases
        self.cases_card.set_value(str(len(cases)))
        open_cases = sum(1 for c in cases if c.status == 'Open')
        self.cases_card.set_subtitle(f"{open_cases} open")

        # Update diagnostics
        if diagnostics:
            failed = sum(1 for d in diagnostics if not d.passed)
            if failed > 0:
                self.diagnostics_card.set_value(str(failed))
                self.diagnostics_card.set_subtitle("issues found")
            else:
                self.diagnostics_card.set_value("OK")
                self.diagnostics_card.set_subtitle("All checks passed")

        # Update recent activity
        self._update_activity(threats[:5])

    def update_connection_status(self, service: str, connected: bool, message: str = ""):
        """Update connection status for a service"""
        status_map = {
            'abnormal': self.abnormal_status,
            'graph': self.graph_status,
            'claude': self.claude_status
        }

        if service in status_map:
            status_card = status_map[service]
            status_text = message if message else ("Connected" if connected else "Disconnected")
            status_card.set_status(status_text, connected)

    def _update_activity(self, threats: List):
        """Update recent activity list"""
        # Clear existing
        while self.activity_list.count():
            item = self.activity_list.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not threats:
            self.empty_label.show()
            return

        self.empty_label.hide()

        for threat in threats:
            item = self._create_activity_item(threat)
            self.activity_list.addWidget(item)

    def _create_activity_item(self, threat) -> QFrame:
        """Create activity item widget"""
        item = QFrame()
        item.setStyleSheet(f"""
            background-color: {EdgeColors.LIGHT};
            border-radius: 4px;
            padding: 8px;
        """)

        layout = QHBoxLayout(item)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(12)

        # Severity indicator
        severity_color = {
            'CRITICAL': EdgeColors.ERROR,
            'HIGH': EdgeColors.WARNING,
            'MEDIUM': EdgeColors.INFO,
            'LOW': EdgeColors.MUTED
        }.get(threat.severity.value, EdgeColors.MUTED)

        indicator = QLabel()
        indicator.setFixedSize(8, 8)
        indicator.setStyleSheet(f"""
            background-color: {severity_color};
            border-radius: 4px;
        """)
        layout.addWidget(indicator)

        # Details
        details = QVBoxLayout()
        details.setSpacing(2)

        subject = QLabel(threat.subject[:50] + ("..." if len(threat.subject) > 50 else ""))
        subject.setStyleSheet(f"color: {EdgeColors.TEXT_PRIMARY}; font-size: 10px;")
        details.addWidget(subject)

        meta = QLabel(f"{threat.attack_type.value} • {threat.from_address}")
        meta.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY}; font-size: 9px;")
        details.addWidget(meta)

        layout.addLayout(details, 1)

        # Time
        time_label = QLabel(threat.received_time.strftime("%H:%M"))
        time_label.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY}; font-size: 9px;")
        layout.addWidget(time_label)

        return item
