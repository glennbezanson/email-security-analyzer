"""
Settings Dialog
Configure application settings
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget,
    QFormLayout, QLineEdit, QSpinBox, QCheckBox, QLabel,
    QPushButton, QGroupBox, QMessageBox
)
from PyQt6.QtCore import Qt

from ..styles import EdgeColors


class SettingsDialog(QDialog):
    """
    Application settings dialog
    """

    def __init__(self, config, parent=None):
        super().__init__(parent)

        self.config = config
        self.setWindowTitle("Settings")
        self.setMinimumSize(600, 500)

        self._setup_ui()
        self._load_settings()

    def _setup_ui(self):
        """Setup dialog UI"""
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        # Tab widget
        tabs = QTabWidget()
        tabs.addTab(self._create_api_tab(), "API Credentials")
        tabs.addTab(self._create_general_tab(), "General")
        tabs.addTab(self._create_diagnostics_tab(), "Diagnostics")

        layout.addWidget(tabs)

        # Buttons
        buttons = QHBoxLayout()
        buttons.addStretch()

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setObjectName("secondary")
        cancel_btn.clicked.connect(self.reject)
        buttons.addWidget(cancel_btn)

        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self._save_settings)
        buttons.addWidget(save_btn)

        layout.addLayout(buttons)

    def _create_api_tab(self) -> QWidget:
        """Create API credentials tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)

        # Abnormal Security
        abnormal_group = QGroupBox("Abnormal Security")
        abnormal_layout = QFormLayout()

        self.abnormal_url = QLineEdit()
        abnormal_layout.addRow("Base URL:", self.abnormal_url)

        self.abnormal_key = QLineEdit()
        self.abnormal_key.setEchoMode(QLineEdit.EchoMode.Password)
        abnormal_layout.addRow("API Key:", self.abnormal_key)

        abnormal_group.setLayout(abnormal_layout)
        layout.addWidget(abnormal_group)

        # Microsoft Azure
        azure_group = QGroupBox("Microsoft Azure / Graph API")
        azure_layout = QFormLayout()

        self.azure_tenant = QLineEdit()
        azure_layout.addRow("Tenant ID:", self.azure_tenant)

        self.azure_client = QLineEdit()
        azure_layout.addRow("Client ID:", self.azure_client)

        self.azure_secret = QLineEdit()
        self.azure_secret.setEchoMode(QLineEdit.EchoMode.Password)
        azure_layout.addRow("Client Secret:", self.azure_secret)

        azure_group.setLayout(azure_layout)
        layout.addWidget(azure_group)

        # Claude AI
        claude_group = QGroupBox("Claude AI (via APIM)")
        claude_layout = QFormLayout()

        self.claude_endpoint = QLineEdit()
        claude_layout.addRow("Endpoint:", self.claude_endpoint)

        self.claude_key = QLineEdit()
        self.claude_key.setEchoMode(QLineEdit.EchoMode.Password)
        claude_layout.addRow("API Key:", self.claude_key)

        self.claude_model = QLineEdit()
        claude_layout.addRow("Model:", self.claude_model)

        claude_group.setLayout(claude_layout)
        layout.addWidget(claude_group)

        layout.addStretch()

        return widget

    def _create_general_tab(self) -> QWidget:
        """Create general settings tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)

        # Refresh settings
        refresh_group = QGroupBox("Data Refresh")
        refresh_layout = QFormLayout()

        self.refresh_interval = QSpinBox()
        self.refresh_interval.setRange(1, 60)
        self.refresh_interval.setSuffix(" minutes")
        refresh_layout.addRow("Auto-refresh interval:", self.refresh_interval)

        self.threat_lookback = QSpinBox()
        self.threat_lookback.setRange(1, 168)
        self.threat_lookback.setSuffix(" hours")
        refresh_layout.addRow("Threat lookback:", self.threat_lookback)

        self.case_lookback = QSpinBox()
        self.case_lookback.setRange(1, 30)
        self.case_lookback.setSuffix(" days")
        refresh_layout.addRow("Case lookback:", self.case_lookback)

        self.cache_ttl = QSpinBox()
        self.cache_ttl.setRange(1, 60)
        self.cache_ttl.setSuffix(" minutes")
        refresh_layout.addRow("Cache TTL:", self.cache_ttl)

        refresh_group.setLayout(refresh_layout)
        layout.addWidget(refresh_group)

        # Automation
        auto_group = QGroupBox("Automation")
        auto_layout = QVBoxLayout()

        self.auto_analyze = QCheckBox("Auto-analyze new threats with Claude")
        auto_layout.addWidget(self.auto_analyze)

        self.auto_diagnose = QCheckBox("Run diagnostics on startup")
        auto_layout.addWidget(self.auto_diagnose)

        auto_group.setLayout(auto_layout)
        layout.addWidget(auto_group)

        layout.addStretch()

        return widget

    def _create_diagnostics_tab(self) -> QWidget:
        """Create diagnostics settings tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(16)

        info_label = QLabel(
            "Select which diagnostic rules to enable. "
            "Disabled rules will not be run during diagnostic checks."
        )
        info_label.setWordWrap(True)
        info_label.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY};")
        layout.addWidget(info_label)

        # Rule checkboxes
        self.rule_checks = {}

        from diagnostics.rules import get_all_rules, RuleCategory

        # Group by category
        for category in RuleCategory:
            group = QGroupBox(category.value)
            group_layout = QVBoxLayout()

            rules = [r for r in get_all_rules() if r.category == category]
            for rule in rules:
                check = QCheckBox(rule.name)
                check.setToolTip(rule.description)
                self.rule_checks[rule.id] = check
                group_layout.addWidget(check)

            group.setLayout(group_layout)
            layout.addWidget(group)

        layout.addStretch()

        return widget

    def _load_settings(self):
        """Load current settings into form"""
        # API settings
        self.abnormal_url.setText(self.config.get('abnormal.base_url', ''))
        self.abnormal_key.setText(self.config.get('abnormal.api_key', ''))

        self.azure_tenant.setText(self.config.get('azure.tenant_id', ''))
        self.azure_client.setText(self.config.get('azure.client_id', ''))
        self.azure_secret.setText(self.config.get('azure.client_secret', ''))

        self.claude_endpoint.setText(self.config.get('claude.endpoint', ''))
        self.claude_key.setText(self.config.get('claude.api_key', ''))
        self.claude_model.setText(self.config.get('claude.model', ''))

        # General settings
        self.refresh_interval.setValue(self.config.get('settings.refresh_interval_minutes', 5))
        self.threat_lookback.setValue(self.config.get('settings.threat_lookback_hours', 24))
        self.case_lookback.setValue(self.config.get('settings.case_lookback_days', 7))
        self.cache_ttl.setValue(self.config.get('settings.cache_ttl_minutes', 15))

        self.auto_analyze.setChecked(self.config.get('settings.auto_analyze', False))
        self.auto_diagnose.setChecked(self.config.get('settings.auto_diagnose', True))

        # Diagnostic rules
        enabled_rules = self.config.get('diagnostics.enabled_rules', [])
        for rule_id, check in self.rule_checks.items():
            check.setChecked(rule_id in enabled_rules)

    def _save_settings(self):
        """Save settings and close"""
        # API settings
        self.config.set('abnormal.base_url', self.abnormal_url.text())
        self.config.set('abnormal.api_key', self.abnormal_key.text())

        self.config.set('azure.tenant_id', self.azure_tenant.text())
        self.config.set('azure.client_id', self.azure_client.text())
        self.config.set('azure.client_secret', self.azure_secret.text())

        self.config.set('claude.endpoint', self.claude_endpoint.text())
        self.config.set('claude.api_key', self.claude_key.text())
        self.config.set('claude.model', self.claude_model.text())

        # General settings
        self.config.set('settings.refresh_interval_minutes', self.refresh_interval.value())
        self.config.set('settings.threat_lookback_hours', self.threat_lookback.value())
        self.config.set('settings.case_lookback_days', self.case_lookback.value())
        self.config.set('settings.cache_ttl_minutes', self.cache_ttl.value())

        self.config.set('settings.auto_analyze', self.auto_analyze.isChecked())
        self.config.set('settings.auto_diagnose', self.auto_diagnose.isChecked())

        # Diagnostic rules
        enabled_rules = [
            rule_id for rule_id, check in self.rule_checks.items()
            if check.isChecked()
        ]
        self.config.set('diagnostics.enabled_rules', enabled_rules)

        # Save to file
        try:
            self.config.save()
            QMessageBox.information(self, "Settings Saved", "Settings have been saved successfully.")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save settings: {e}")
