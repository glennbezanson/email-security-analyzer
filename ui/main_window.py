"""
Main Application Window
Edge Solutions branded Email Security Analyzer
"""

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QToolBar, QStatusBar, QLabel, QMessageBox,
    QSplitter, QFrame
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QIcon, QFont
from datetime import datetime
import logging

from .styles import EDGE_STYLESHEET, EdgeColors
from .views.dashboard import DashboardView
from .views.threats import ThreatsView
from .views.cases import CasesView
from .views.diagnostics import DiagnosticsView
from .views.analysis import AnalysisView
from .views.mailflow import MailFlowView

from core.config import ConfigManager
from core.workers import RefreshWorker, DiagnosticWorker, ConnectionTestWorker
from api.abnormal import AbnormalClient
from api.graph import GraphClient
from api.claude import ClaudeClient
from api.exchange import ExchangeClient
from diagnostics.engine import DiagnosticEngine

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """Main application window"""

    data_refreshed = pyqtSignal(dict)
    diagnostics_complete = pyqtSignal(list)

    def __init__(self):
        super().__init__()

        # Load configuration
        self.config = ConfigManager()

        # Initialize API clients
        self._init_clients()

        # Setup UI
        self.setWindowTitle("Email Security Analyzer - Edge Solutions")
        self.setMinimumSize(1400, 900)
        self.setStyleSheet(EDGE_STYLESHEET)

        self._setup_menubar()
        self._setup_toolbar()
        self._setup_central_widget()
        self._setup_statusbar()

        # Auto-refresh timer
        interval = self.config.get('settings.refresh_interval_minutes', 5)
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh_data)
        self.refresh_timer.start(interval * 60 * 1000)

        # Initial load
        QTimer.singleShot(500, self.refresh_data)

        # Test connections
        QTimer.singleShot(1000, self._test_connections)

        # Run diagnostics if enabled
        if self.config.get('settings.auto_diagnose', True):
            QTimer.singleShot(3000, self.run_diagnostics)

    def _init_clients(self):
        """Initialize API clients from config"""
        # Abnormal Security
        abnormal_cfg = self.config.get_section('abnormal')
        self.abnormal = AbnormalClient(
            base_url=abnormal_cfg.get('base_url', 'https://api.abnormalplatform.com'),
            api_key=abnormal_cfg.get('api_key', ''),
            api_version=abnormal_cfg.get('api_version', 'v1')
        )

        # Microsoft Graph
        azure_cfg = self.config.get_section('azure')
        self.graph = GraphClient(
            tenant_id=azure_cfg.get('tenant_id', ''),
            client_id=azure_cfg.get('client_id', ''),
            client_secret=azure_cfg.get('client_secret', '')
        )

        # Claude AI
        claude_cfg = self.config.get_section('claude')
        self.claude = ClaudeClient(
            endpoint=claude_cfg.get('endpoint', ''),
            api_key=claude_cfg.get('api_key', ''),
            model=claude_cfg.get('model', 'claude-sonnet-4-20250514')
        )

        # Exchange Online (for mail flow tracing)
        self.exchange_client = ExchangeClient(
            tenant_id=azure_cfg.get('tenant_id', ''),
            client_id=azure_cfg.get('client_id', ''),
            client_secret=azure_cfg.get('client_secret', '')
        )

        # Alias for mailflow view
        self.abnormal_client = self.abnormal

        # Diagnostic Engine
        diag_cfg = self.config.get_section('diagnostics')
        self.diagnostics_engine = DiagnosticEngine(
            abnormal_client=self.abnormal,
            graph_client=self.graph,
            enabled_rules=diag_cfg.get('enabled_rules', [])
        )

    def _setup_menubar(self):
        """Setup menu bar"""
        menubar = self.menuBar()
        menubar.setStyleSheet(f"""
            QMenuBar {{
                background-color: {EdgeColors.PRIMARY};
                color: {EdgeColors.TEXT_INVERSE};
                padding: 4px;
            }}
            QMenuBar::item:selected {{
                background-color: #3d5c73;
            }}
        """)

        # File menu
        file_menu = menubar.addMenu("&File")

        refresh_action = QAction("&Refresh", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self.refresh_data)
        file_menu.addAction(refresh_action)

        file_menu.addSeparator()

        export_action = QAction("&Export Report...", self)
        export_action.setShortcut("Ctrl+E")
        export_action.triggered.connect(self.export_report)
        file_menu.addAction(export_action)

        file_menu.addSeparator()

        settings_action = QAction("&Settings...", self)
        settings_action.setShortcut("Ctrl+,")
        settings_action.triggered.connect(self.show_settings)
        file_menu.addAction(settings_action)

        file_menu.addSeparator()

        exit_action = QAction("E&xit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # View menu
        view_menu = menubar.addMenu("&View")

        mailflow_action = QAction("&Mail Flow", self)
        mailflow_action.setShortcut("Ctrl+1")
        mailflow_action.triggered.connect(lambda: self.tabs.setCurrentIndex(0))
        view_menu.addAction(mailflow_action)

        dashboard_action = QAction("&Dashboard", self)
        dashboard_action.setShortcut("Ctrl+2")
        dashboard_action.triggered.connect(lambda: self.tabs.setCurrentIndex(1))
        view_menu.addAction(dashboard_action)

        threats_action = QAction("&Threats", self)
        threats_action.setShortcut("Ctrl+3")
        threats_action.triggered.connect(lambda: self.tabs.setCurrentIndex(2))
        view_menu.addAction(threats_action)

        cases_action = QAction("&Cases", self)
        cases_action.setShortcut("Ctrl+4")
        cases_action.triggered.connect(lambda: self.tabs.setCurrentIndex(3))
        view_menu.addAction(cases_action)

        diagnostics_action = QAction("D&iagnostics", self)
        diagnostics_action.setShortcut("Ctrl+5")
        diagnostics_action.triggered.connect(lambda: self.tabs.setCurrentIndex(4))
        view_menu.addAction(diagnostics_action)

        analysis_action = QAction("&Analysis", self)
        analysis_action.setShortcut("Ctrl+6")
        analysis_action.triggered.connect(lambda: self.tabs.setCurrentIndex(5))
        view_menu.addAction(analysis_action)

        # Tools menu
        tools_menu = menubar.addMenu("&Tools")

        analyze_action = QAction("&Analyze Selected...", self)
        analyze_action.setShortcut("Ctrl+A")
        analyze_action.triggered.connect(self.analyze_selected)
        tools_menu.addAction(analyze_action)

        batch_action = QAction("&Batch Analysis...", self)
        batch_action.triggered.connect(self.batch_analysis)
        tools_menu.addAction(batch_action)

        tools_menu.addSeparator()

        run_diag_action = QAction("Run &Diagnostics", self)
        run_diag_action.setShortcut("Ctrl+D")
        run_diag_action.triggered.connect(self.run_diagnostics)
        tools_menu.addAction(run_diag_action)

        tools_menu.addSeparator()

        summary_action = QAction("Generate &Summary...", self)
        summary_action.triggered.connect(self.generate_summary)
        tools_menu.addAction(summary_action)

        # Help menu
        help_menu = menubar.addMenu("&Help")

        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def _setup_toolbar(self):
        """Setup toolbar"""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        toolbar.setStyleSheet(f"""
            QToolBar {{
                background-color: {EdgeColors.LIGHT};
                border-bottom: 1px solid {EdgeColors.MUTED};
                padding: 8px;
                spacing: 8px;
            }}
            QToolButton {{
                background-color: transparent;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                color: {EdgeColors.TEXT_PRIMARY};
            }}
            QToolButton:hover {{
                background-color: rgba(72, 109, 135, 0.1);
            }}
            QToolButton:pressed {{
                background-color: rgba(72, 109, 135, 0.2);
            }}
        """)
        self.addToolBar(toolbar)

        # Refresh
        refresh_btn = QAction("Refresh", self)
        refresh_btn.triggered.connect(self.refresh_data)
        toolbar.addAction(refresh_btn)

        toolbar.addSeparator()

        # Analyze
        analyze_btn = QAction("Analyze", self)
        analyze_btn.triggered.connect(self.analyze_selected)
        toolbar.addAction(analyze_btn)

        # Diagnostics
        diag_btn = QAction("Diagnose", self)
        diag_btn.triggered.connect(self.run_diagnostics)
        toolbar.addAction(diag_btn)

        toolbar.addSeparator()

        # Summary
        summary_btn = QAction("Summary", self)
        summary_btn.triggered.connect(self.generate_summary)
        toolbar.addAction(summary_btn)

        # Spacer
        spacer = QWidget()
        spacer.setSizePolicy(
            spacer.sizePolicy().Policy.Expanding,
            spacer.sizePolicy().Policy.Preferred
        )
        toolbar.addWidget(spacer)

        # Settings
        settings_btn = QAction("Settings", self)
        settings_btn.triggered.connect(self.show_settings)
        toolbar.addAction(settings_btn)

    def _setup_central_widget(self):
        """Setup central widget with tabs"""
        central = QWidget()
        self.setCentralWidget(central)

        layout = QVBoxLayout(central)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # Header
        header = QLabel("Email Security Analyzer")
        header.setObjectName("pageTitle")
        header.setStyleSheet(f"""
            font-size: 26px;
            font-weight: bold;
            color: {EdgeColors.TEXT_PRIMARY};
            padding-bottom: 8px;
        """)
        layout.addWidget(header)

        # Tab widget
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        layout.addWidget(self.tabs)

        # Create views
        self.dashboard_view = DashboardView(self)
        self.threats_view = ThreatsView(self)
        self.cases_view = CasesView(self)
        self.diagnostics_view = DiagnosticsView(self)
        self.analysis_view = AnalysisView(self)
        self.mailflow_view = MailFlowView(self)

        # Add tabs - Mail Flow is primary feature
        self.tabs.addTab(self.mailflow_view, "Mail Flow")
        self.tabs.addTab(self.dashboard_view, "Dashboard")
        self.tabs.addTab(self.threats_view, "Threats")
        self.tabs.addTab(self.cases_view, "Cases")
        self.tabs.addTab(self.diagnostics_view, "Diagnostics")
        self.tabs.addTab(self.analysis_view, "Analysis")

        # Connect signals
        self.data_refreshed.connect(self._on_data_refreshed)
        self.diagnostics_complete.connect(self._on_diagnostics_complete)

        # Connect view signals
        self.threats_view.analyze_requested.connect(self._on_analyze_threats)
        self.diagnostics_view.run_diagnostics.connect(self.run_diagnostics)
        self.diagnostics_view.analyze_findings.connect(self._on_analyze_diagnostics)

    def _setup_statusbar(self):
        """Setup status bar"""
        self.statusbar = QStatusBar()
        self.statusbar.setStyleSheet(f"""
            QStatusBar {{
                background-color: {EdgeColors.LIGHT};
                border-top: 1px solid {EdgeColors.MUTED};
                padding: 4px;
            }}
        """)
        self.setStatusBar(self.statusbar)

        self.status_label = QLabel("Ready")
        self.statusbar.addWidget(self.status_label)

        self.last_refresh_label = QLabel("")
        self.last_refresh_label.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY};")
        self.statusbar.addPermanentWidget(self.last_refresh_label)

    # =========================================================================
    # Actions
    # =========================================================================

    def refresh_data(self):
        """Refresh data from all sources"""
        self.status_label.setText("Refreshing...")

        self.refresh_worker = RefreshWorker(
            self.abnormal,
            self.graph,
            self.config
        )
        self.refresh_worker.finished.connect(self._on_refresh_finished)
        self.refresh_worker.error.connect(self._on_refresh_error)
        self.refresh_worker.progress.connect(lambda msg: self.status_label.setText(msg))
        self.refresh_worker.start()

    def _on_refresh_finished(self, data: dict):
        """Handle refresh completion"""
        self.data_refreshed.emit(data)
        self.status_label.setText("Ready")
        self.last_refresh_label.setText(
            f"Last refresh: {datetime.now().strftime('%H:%M:%S')}"
        )

    def _on_refresh_error(self, error: str):
        """Handle refresh error"""
        self.status_label.setText(f"Error: {error}")
        QMessageBox.warning(self, "Refresh Error", error)

    def _on_data_refreshed(self, data: dict):
        """Update all views with new data"""
        self.dashboard_view.update_data(data)
        self.threats_view.update_data(data.get('threats', []))
        self.cases_view.update_data(data.get('cases', []))

    def run_diagnostics(self):
        """Run diagnostic checks"""
        self.status_label.setText("Running diagnostics...")

        self.diag_worker = DiagnosticWorker(self.diagnostics_engine)
        self.diag_worker.finished.connect(self._on_diagnostics_finished)
        self.diag_worker.error.connect(self._on_diagnostics_error)
        self.diag_worker.start()

    def _on_diagnostics_finished(self, results: list):
        """Handle diagnostics completion"""
        self.diagnostics_complete.emit(results)
        self.status_label.setText("Ready")

        # Count issues
        issues = sum(1 for r in results if not r.passed)
        if issues > 0:
            self.statusbar.showMessage(f"Found {issues} diagnostic issue(s)", 5000)

    def _on_diagnostics_error(self, error: str):
        """Handle diagnostics error"""
        self.status_label.setText(f"Diagnostic error: {error}")

    def _on_diagnostics_complete(self, results: list):
        """Update diagnostics view and dashboard"""
        self.diagnostics_view.update_results(results)

    def _test_connections(self):
        """Test API connections"""
        self.conn_worker = ConnectionTestWorker(self.abnormal, self.graph, self.claude)
        self.conn_worker.finished.connect(self._on_connection_test_complete)
        self.conn_worker.start()

    def _on_connection_test_complete(self, results: dict):
        """Update dashboard with connection status"""
        for service, status in results.items():
            self.dashboard_view.update_connection_status(
                service,
                status['connected'],
                status['message']
            )

    def analyze_selected(self):
        """Analyze selected items with Claude"""
        current = self.tabs.currentWidget()
        if hasattr(current, 'get_selected_items'):
            items = current.get_selected_items()
            if items:
                self._on_analyze_threats(items)
            else:
                QMessageBox.information(
                    self, "No Selection",
                    "Please select items to analyze."
                )

    def _on_analyze_threats(self, threats: list):
        """Handle analyze threats request"""
        self.analysis_view.analyze_threats(threats, self.claude)
        self.tabs.setCurrentWidget(self.analysis_view)

    def _on_analyze_diagnostics(self, findings: list):
        """Handle analyze diagnostics request"""
        self.analysis_view.analyze_diagnostics(findings, self.claude)
        self.tabs.setCurrentWidget(self.analysis_view)

    def batch_analysis(self):
        """Run batch analysis on all recent threats"""
        threats = self.threats_view.threats
        if threats:
            self.analysis_view.analyze_threats(threats, self.claude)
            self.tabs.setCurrentWidget(self.analysis_view)
        else:
            QMessageBox.information(
                self, "No Threats",
                "No threats available for batch analysis."
            )

    def generate_summary(self):
        """Generate executive summary"""
        self.status_label.setText("Generating summary...")
        # TODO: Implement summary generation
        self.status_label.setText("Summary generation not yet implemented")

    def export_report(self):
        """Export report dialog"""
        from .dialogs.export import ExportDialog
        dialog = ExportDialog(self)
        dialog.exec()

    def show_settings(self):
        """Show settings dialog"""
        from .dialogs.settings import SettingsDialog
        dialog = SettingsDialog(self.config, self)
        if dialog.exec():
            # Reload config and reinitialize clients
            self.config.reload()
            self._init_clients()

    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(
            self,
            "About Email Security Analyzer",
            f"""<h2 style="color: {EdgeColors.PRIMARY};">Email Security Analyzer</h2>
            <p>Version 1.0.0</p>
            <p>Unified email security monitoring combining:</p>
            <ul>
                <li>Abnormal Security API</li>
                <li>Microsoft Graph API</li>
                <li>Claude AI Analysis</li>
            </ul>
            <p style="color: {EdgeColors.TEXT_SECONDARY};">
                Edge Solutions LLC
            </p>"""
        )
