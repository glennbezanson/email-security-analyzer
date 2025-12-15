"""
Detail Panel Widget
Displays detailed information about a selected item
"""

from PyQt6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QWidget, QTextEdit
)
from PyQt6.QtCore import Qt, pyqtSignal
from typing import Optional

from ..styles import EdgeColors, get_severity_color, get_status_color


class DetailPanel(QFrame):
    """
    Panel for displaying detailed threat/case information
    """

    analyze_requested = pyqtSignal(object)
    remediate_requested = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setObjectName("card")
        self.current_item = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header
        header = QHBoxLayout()

        self.title_label = QLabel("Details")
        self.title_label.setObjectName("sectionTitle")
        header.addWidget(self.title_label)

        header.addStretch()

        self.close_btn = QPushButton("x")
        self.close_btn.setFixedSize(24, 24)
        self.close_btn.setStyleSheet(f"""
            background-color: transparent;
            color: {EdgeColors.TEXT_SECONDARY};
            border: none;
            font-size: 14px;
        """)
        header.addWidget(self.close_btn)

        layout.addLayout(header)

        # Content scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        self.content_widget = QWidget()
        self.content_layout = QVBoxLayout(self.content_widget)
        self.content_layout.setContentsMargins(0, 0, 0, 0)
        self.content_layout.setSpacing(16)

        scroll.setWidget(self.content_widget)
        layout.addWidget(scroll)

        # Action buttons
        self.actions_layout = QHBoxLayout()
        self.actions_layout.setSpacing(8)

        self.analyze_btn = QPushButton("Analyze with AI")
        self.analyze_btn.clicked.connect(self._on_analyze)
        self.actions_layout.addWidget(self.analyze_btn)

        self.remediate_btn = QPushButton("Remediate")
        self.remediate_btn.setObjectName("accent")
        self.remediate_btn.clicked.connect(self._on_remediate)
        self.actions_layout.addWidget(self.remediate_btn)

        self.actions_layout.addStretch()

        layout.addLayout(self.actions_layout)

        # Initially hidden
        self.hide()

    def show_threat(self, threat):
        """Display threat details"""
        self.current_item = threat
        self._clear_content()

        # Header info
        self._add_header_section(threat)

        # Sender info
        self._add_section("Sender Information", [
            ("From", f"{threat.from_name} <{threat.from_address}>"),
            ("Return Path", threat.return_path or "Not available"),
            ("Sender IP", threat.sender_ip or "Not available"),
            ("To", ", ".join(threat.to_addresses[:3]) + ("..." if len(threat.to_addresses) > 3 else ""))
        ])

        # Attack details
        self._add_section("Attack Analysis", [
            ("Attack Type", threat.attack_type.value),
            ("Strategy", threat.attack_strategy),
            ("Impersonated", threat.impersonated_party or "None detected")
        ])

        # URLs
        if threat.urls:
            self._add_list_section("URLs Found", threat.urls[:5])

        # Attachments
        if threat.attachments:
            att_names = [a.get('fileName', 'Unknown') for a in threat.attachments]
            self._add_list_section("Attachments", att_names[:5])

        # Vendor insights
        if threat.summary_insights:
            self._add_text_section("Vendor Insights", threat.summary_insights)

        self.content_layout.addStretch()
        self.show()

    def show_case(self, case):
        """Display case details"""
        self.current_item = case
        self._clear_content()

        # Header
        self._add_row("Case ID", case.case_id)
        self._add_row("Type", case.case_type)

        severity_label = QLabel(case.severity.value)
        severity_label.setStyleSheet(f"""
            color: {get_severity_color(case.severity.value)};
            font-weight: 600;
        """)
        self._add_row("Severity", case.severity.value)

        self._add_row("Status", case.status)
        self._add_row("Created", case.created_time.strftime("%Y-%m-%d %H:%M"))

        if case.affected_user:
            self._add_row("Affected User", case.affected_user)

        if case.description:
            self._add_text_section("Description", case.description)

        if case.threat_ids:
            self._add_list_section("Related Threats", case.threat_ids[:5])

        self.content_layout.addStretch()
        self.remediate_btn.hide()
        self.show()

    def _clear_content(self):
        """Clear current content"""
        while self.content_layout.count():
            item = self.content_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self.remediate_btn.show()

    def _add_header_section(self, threat):
        """Add threat header section"""
        header = QFrame()
        header.setStyleSheet(f"""
            background-color: {EdgeColors.LIGHT};
            border-radius: 8px;
            padding: 12px;
        """)

        h_layout = QVBoxLayout(header)
        h_layout.setSpacing(8)

        # Subject
        subject = QLabel(threat.subject)
        subject.setStyleSheet(f"""
            font-size: 14px;
            font-weight: 600;
            color: {EdgeColors.TEXT_PRIMARY};
        """)
        subject.setWordWrap(True)
        h_layout.addWidget(subject)

        # Meta row
        meta = QHBoxLayout()

        severity = QLabel(threat.severity.value)
        severity.setStyleSheet(f"""
            background-color: {get_severity_color(threat.severity.value)};
            color: {EdgeColors.TEXT_INVERSE};
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 9px;
            font-weight: bold;
        """)
        meta.addWidget(severity)

        status = QLabel(threat.remediation_status.value)
        status.setStyleSheet(f"""
            color: {get_status_color(threat.remediation_status.value)};
            font-size: 10px;
            font-weight: 500;
        """)
        meta.addWidget(status)

        time = QLabel(threat.received_time.strftime("%Y-%m-%d %H:%M"))
        time.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY}; font-size: 10px;")
        meta.addWidget(time)

        meta.addStretch()
        h_layout.addLayout(meta)

        self.content_layout.addWidget(header)

    def _add_section(self, title: str, items: list):
        """Add a labeled section with key-value pairs"""
        section = QFrame()
        s_layout = QVBoxLayout(section)
        s_layout.setContentsMargins(0, 0, 0, 0)
        s_layout.setSpacing(8)

        title_label = QLabel(title)
        title_label.setStyleSheet(f"""
            font-size: 10px;
            font-weight: 600;
            color: {EdgeColors.TEXT_SECONDARY};
            text-transform: uppercase;
            letter-spacing: 1px;
        """)
        s_layout.addWidget(title_label)

        for key, value in items:
            self._add_row_to_layout(s_layout, key, value)

        self.content_layout.addWidget(section)

    def _add_row(self, key: str, value: str):
        """Add a single key-value row"""
        self._add_row_to_layout(self.content_layout, key, value)

    def _add_row_to_layout(self, layout, key: str, value: str):
        """Add a row to specified layout"""
        row = QHBoxLayout()

        key_label = QLabel(f"{key}:")
        key_label.setStyleSheet(f"""
            color: {EdgeColors.TEXT_SECONDARY};
            font-size: 10px;
            min-width: 100px;
        """)
        row.addWidget(key_label)

        value_label = QLabel(str(value))
        value_label.setStyleSheet(f"""
            color: {EdgeColors.TEXT_PRIMARY};
            font-size: 10px;
        """)
        value_label.setWordWrap(True)
        row.addWidget(value_label, 1)

        layout.addLayout(row)

    def _add_list_section(self, title: str, items: list):
        """Add a section with a list of items"""
        section = QFrame()
        s_layout = QVBoxLayout(section)
        s_layout.setContentsMargins(0, 0, 0, 0)
        s_layout.setSpacing(4)

        title_label = QLabel(title)
        title_label.setStyleSheet(f"""
            font-size: 10px;
            font-weight: 600;
            color: {EdgeColors.TEXT_SECONDARY};
            text-transform: uppercase;
            letter-spacing: 1px;
        """)
        s_layout.addWidget(title_label)

        for item in items:
            item_label = QLabel(f"• {item}")
            item_label.setStyleSheet(f"""
                color: {EdgeColors.TEXT_PRIMARY};
                font-size: 10px;
                margin-left: 8px;
            """)
            item_label.setWordWrap(True)
            s_layout.addWidget(item_label)

        self.content_layout.addWidget(section)

    def _add_text_section(self, title: str, text: str):
        """Add a section with wrapped text"""
        section = QFrame()
        s_layout = QVBoxLayout(section)
        s_layout.setContentsMargins(0, 0, 0, 0)
        s_layout.setSpacing(4)

        title_label = QLabel(title)
        title_label.setStyleSheet(f"""
            font-size: 10px;
            font-weight: 600;
            color: {EdgeColors.TEXT_SECONDARY};
            text-transform: uppercase;
            letter-spacing: 1px;
        """)
        s_layout.addWidget(title_label)

        text_label = QLabel(text)
        text_label.setStyleSheet(f"""
            color: {EdgeColors.TEXT_PRIMARY};
            font-size: 10px;
            background-color: {EdgeColors.LIGHT};
            padding: 8px;
            border-radius: 4px;
        """)
        text_label.setWordWrap(True)
        s_layout.addWidget(text_label)

        self.content_layout.addWidget(section)

    def _on_analyze(self):
        """Handle analyze button click"""
        if self.current_item:
            self.analyze_requested.emit(self.current_item)

    def _on_remediate(self):
        """Handle remediate button click"""
        if self.current_item and hasattr(self.current_item, 'threat_id'):
            self.remediate_requested.emit(self.current_item.threat_id)
