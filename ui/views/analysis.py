"""
Analysis View
Display Claude AI analysis results
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel,
    QPushButton, QTextEdit, QScrollArea, QProgressBar,
    QSplitter
)
from PyQt6.QtCore import Qt, pyqtSignal, QThread
from typing import List, Optional

from ..styles import EdgeColors


class AnalysisWorker(QThread):
    """Worker thread for running Claude analysis"""

    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    progress = pyqtSignal(int, int)

    def __init__(self, claude_client, threats=None, batch=False, diagnostics=None):
        super().__init__()
        self.claude = claude_client
        self.threats = threats
        self.batch = batch
        self.diagnostics = diagnostics

    def run(self):
        try:
            if self.diagnostics:
                result = self.claude.analyze_diagnostic_findings(self.diagnostics)
            elif self.batch and self.threats:
                result = self.claude.analyze_threat_batch(self.threats)
            elif self.threats and len(self.threats) == 1:
                result = self.claude.analyze_threat(self.threats[0])
            else:
                # Multiple threats, analyze individually
                results = []
                for i, threat in enumerate(self.threats or []):
                    self.progress.emit(i + 1, len(self.threats))
                    result = self.claude.analyze_threat(threat)
                    results.append(result)
                self.finished.emit(results)
                return

            self.finished.emit(result)

        except Exception as e:
            self.error.emit(str(e))


class AnalysisView(QWidget):
    """
    View for displaying Claude AI analysis
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self.current_analysis = None
        self._setup_ui()

    def _setup_ui(self):
        """Setup analysis view layout"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        # Header
        header = QHBoxLayout()

        title = QLabel("AI Analysis")
        title.setObjectName("sectionTitle")
        header.addWidget(title)

        header.addStretch()

        self.status_label = QLabel("No analysis running")
        self.status_label.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY};")
        header.addWidget(self.status_label)

        layout.addLayout(header)

        # Progress bar (hidden by default)
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumHeight(4)
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        # Main content splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Analysis results panel
        results_container = QFrame()
        results_container.setObjectName("card")
        results_layout = QVBoxLayout(results_container)
        results_layout.setContentsMargins(16, 16, 16, 16)
        results_layout.setSpacing(12)

        results_title = QLabel("Analysis Results")
        results_title.setStyleSheet(f"""
            font-size: 10px;
            font-weight: 600;
            color: {EdgeColors.TEXT_PRIMARY};
        """)
        results_layout.addWidget(results_title)

        # Scroll area for results
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        self.results_content = QWidget()
        self.results_layout = QVBoxLayout(self.results_content)
        self.results_layout.setContentsMargins(0, 0, 0, 0)
        self.results_layout.setSpacing(16)

        # Empty state
        self.empty_label = QLabel("Select threats or run diagnostics to analyze with Claude AI")
        self.empty_label.setStyleSheet(f"""
            color: {EdgeColors.TEXT_SECONDARY};
            font-style: italic;
            padding: 40px;
        """)
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setWordWrap(True)
        self.results_layout.addWidget(self.empty_label)

        scroll.setWidget(self.results_content)
        results_layout.addWidget(scroll)

        splitter.addWidget(results_container)

        # Raw response panel
        raw_container = QFrame()
        raw_container.setObjectName("card")
        raw_layout = QVBoxLayout(raw_container)
        raw_layout.setContentsMargins(16, 16, 16, 16)
        raw_layout.setSpacing(8)

        raw_header = QHBoxLayout()
        raw_title = QLabel("Raw Response")
        raw_title.setStyleSheet(f"""
            font-size: 10px;
            font-weight: 600;
            color: {EdgeColors.TEXT_PRIMARY};
        """)
        raw_header.addWidget(raw_title)

        raw_header.addStretch()

        self.copy_btn = QPushButton("Copy")
        self.copy_btn.setObjectName("secondary")
        self.copy_btn.setEnabled(False)
        self.copy_btn.clicked.connect(self._copy_raw)
        raw_header.addWidget(self.copy_btn)

        raw_layout.addLayout(raw_header)

        self.raw_text = QTextEdit()
        self.raw_text.setReadOnly(True)
        self.raw_text.setStyleSheet(f"""
            background-color: {EdgeColors.LIGHT};
            border: none;
            border-radius: 4px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 10px;
            padding: 8px;
        """)
        raw_layout.addWidget(self.raw_text)

        splitter.addWidget(raw_container)

        # Set splitter sizes
        splitter.setSizes([600, 400])

        layout.addWidget(splitter)

    def analyze_threats(self, threats: List, claude_client):
        """Start threat analysis"""
        self.status_label.setText("Analyzing...")
        self.progress_bar.setMaximum(len(threats))
        self.progress_bar.setValue(0)
        self.progress_bar.show()

        self._clear_results()
        self.empty_label.hide()

        self.worker = AnalysisWorker(claude_client, threats=threats, batch=len(threats) > 1)
        self.worker.finished.connect(self._on_analysis_finished)
        self.worker.error.connect(self._on_analysis_error)
        self.worker.progress.connect(self._on_progress)
        self.worker.start()

    def analyze_diagnostics(self, findings: List, claude_client):
        """Start diagnostic analysis"""
        self.status_label.setText("Analyzing diagnostics...")
        self.progress_bar.setMaximum(0)  # Indeterminate
        self.progress_bar.show()

        self._clear_results()
        self.empty_label.hide()

        self.worker = AnalysisWorker(claude_client, diagnostics=findings)
        self.worker.finished.connect(self._on_analysis_finished)
        self.worker.error.connect(self._on_analysis_error)
        self.worker.start()

    def _on_analysis_finished(self, result):
        """Handle analysis completion"""
        self.progress_bar.hide()
        self.status_label.setText("Analysis complete")
        self.current_analysis = result
        self.copy_btn.setEnabled(True)

        if isinstance(result, list):
            # Multiple threat analyses
            for analysis in result:
                self._add_threat_analysis(analysis)
        elif hasattr(result, 'summary'):
            # Single analysis result
            if hasattr(result, 'threat_id'):
                self._add_threat_analysis(result)
            elif hasattr(result, 'total_analyzed'):
                self._add_batch_analysis(result)
            elif hasattr(result, 'root_causes'):
                self._add_diagnostic_analysis(result)

        # Set raw response
        if hasattr(result, 'raw_response') and result.raw_response:
            self.raw_text.setText(result.raw_response)

        self.results_layout.addStretch()

    def _on_analysis_error(self, error: str):
        """Handle analysis error"""
        self.progress_bar.hide()
        self.status_label.setText(f"Error: {error}")

        error_label = QLabel(f"Analysis failed: {error}")
        error_label.setStyleSheet(f"""
            color: {EdgeColors.ERROR};
            padding: 20px;
        """)
        error_label.setWordWrap(True)
        self.results_layout.addWidget(error_label)

    def _on_progress(self, current: int, total: int):
        """Handle progress update"""
        self.progress_bar.setValue(current)
        self.status_label.setText(f"Analyzing {current}/{total}...")

    def _clear_results(self):
        """Clear current results"""
        while self.results_layout.count():
            item = self.results_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        self.raw_text.clear()
        self.copy_btn.setEnabled(False)

    def _add_threat_analysis(self, analysis):
        """Add threat analysis result to view"""
        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 16, 16, 16)
        card_layout.setSpacing(12)

        # Header
        header = QHBoxLayout()
        id_label = QLabel(f"Threat: {analysis.threat_id}")
        id_label.setStyleSheet(f"font-weight: 600; color: {EdgeColors.TEXT_PRIMARY};")
        header.addWidget(id_label)

        header.addStretch()

        risk_label = QLabel(analysis.risk_level)
        risk_color = {
            'CRITICAL': EdgeColors.ERROR,
            'HIGH': EdgeColors.WARNING,
            'MEDIUM': EdgeColors.INFO,
            'LOW': EdgeColors.MUTED
        }.get(analysis.risk_level, EdgeColors.TEXT_SECONDARY)
        risk_label.setStyleSheet(f"""
            background-color: {risk_color};
            color: {EdgeColors.TEXT_INVERSE};
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        """)
        header.addWidget(risk_label)

        confidence = QLabel(f"{int(analysis.confidence * 100)}% confidence")
        confidence.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY}; font-size: 10px;")
        header.addWidget(confidence)

        card_layout.addLayout(header)

        # Summary
        summary = QLabel(analysis.summary)
        summary.setWordWrap(True)
        summary.setStyleSheet(f"color: {EdgeColors.TEXT_PRIMARY};")
        card_layout.addWidget(summary)

        # Indicators
        if analysis.indicators:
            self._add_list_section(card_layout, "Indicators", analysis.indicators[:5])

        # Attack techniques
        if analysis.attack_techniques:
            self._add_list_section(card_layout, "MITRE ATT&CK", analysis.attack_techniques[:5])

        # Recommendations
        if analysis.recommendations:
            self._add_list_section(card_layout, "Recommendations", analysis.recommendations[:5])

        # Immediate actions
        if analysis.immediate_actions:
            self._add_list_section(card_layout, "Immediate Actions", analysis.immediate_actions, EdgeColors.WARNING)

        self.results_layout.addWidget(card)

    def _add_batch_analysis(self, analysis):
        """Add batch analysis result to view"""
        card = QFrame()
        card.setObjectName("cardAccent")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 16, 16, 16)
        card_layout.setSpacing(12)

        # Header
        header_label = QLabel(f"Batch Analysis: {analysis.total_analyzed} threats")
        header_label.setStyleSheet(f"font-weight: 600; font-size: 10px; color: {EdgeColors.TEXT_PRIMARY};")
        card_layout.addWidget(header_label)

        # Summary
        summary = QLabel(analysis.summary)
        summary.setWordWrap(True)
        summary.setStyleSheet(f"color: {EdgeColors.TEXT_PRIMARY};")
        card_layout.addWidget(summary)

        # Campaigns
        if analysis.campaigns_detected:
            for campaign in analysis.campaigns_detected:
                camp_label = QLabel(f"Campaign: {campaign.get('name', 'Unknown')}")
                camp_label.setStyleSheet(f"color: {EdgeColors.WARNING}; font-weight: 600;")
                card_layout.addWidget(camp_label)

        # Investigation priority
        if analysis.investigation_priority:
            self._add_list_section(card_layout, "Investigation Priority", analysis.investigation_priority[:5])

        self.results_layout.addWidget(card)

    def _add_diagnostic_analysis(self, analysis):
        """Add diagnostic analysis result to view"""
        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(16, 16, 16, 16)
        card_layout.setSpacing(12)

        # Header
        header = QHBoxLayout()
        header_label = QLabel("Diagnostic Analysis")
        header_label.setStyleSheet(f"font-weight: 600; font-size: 10px; color: {EdgeColors.TEXT_PRIMARY};")
        header.addWidget(header_label)

        header.addStretch()

        severity_label = QLabel(analysis.severity)
        header.addWidget(severity_label)

        card_layout.addLayout(header)

        # Summary
        summary = QLabel(analysis.summary)
        summary.setWordWrap(True)
        summary.setStyleSheet(f"color: {EdgeColors.TEXT_PRIMARY};")
        card_layout.addWidget(summary)

        # Root causes
        if analysis.root_causes:
            self._add_list_section(card_layout, "Root Causes", analysis.root_causes)

        # Affected services
        if analysis.affected_services:
            self._add_list_section(card_layout, "Affected Services", analysis.affected_services)

        # Remediation steps
        if analysis.remediation_steps:
            self._add_numbered_list(card_layout, "Remediation Steps", analysis.remediation_steps)

        # Reference docs
        if analysis.reference_docs:
            self._add_list_section(card_layout, "Reference Documentation", analysis.reference_docs)

        self.results_layout.addWidget(card)

    def _add_list_section(self, layout, title: str, items: List, color: str = None):
        """Add a section with bullet list"""
        title_label = QLabel(title)
        title_label.setStyleSheet(f"""
            font-size: 10px;
            font-weight: 600;
            color: {EdgeColors.TEXT_SECONDARY};
            margin-top: 8px;
        """)
        layout.addWidget(title_label)

        for item in items:
            item_label = QLabel(f"• {item}")
            item_label.setStyleSheet(f"""
                color: {color or EdgeColors.TEXT_PRIMARY};
                font-size: 10px;
                margin-left: 8px;
            """)
            item_label.setWordWrap(True)
            layout.addWidget(item_label)

    def _add_numbered_list(self, layout, title: str, items: List):
        """Add a section with numbered list"""
        title_label = QLabel(title)
        title_label.setStyleSheet(f"""
            font-size: 10px;
            font-weight: 600;
            color: {EdgeColors.TEXT_SECONDARY};
            margin-top: 8px;
        """)
        layout.addWidget(title_label)

        for i, item in enumerate(items, 1):
            item_label = QLabel(f"{i}. {item}")
            item_label.setStyleSheet(f"""
                color: {EdgeColors.TEXT_PRIMARY};
                font-size: 10px;
                margin-left: 8px;
            """)
            item_label.setWordWrap(True)
            layout.addWidget(item_label)

    def _copy_raw(self):
        """Copy raw response to clipboard"""
        from PyQt6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(self.raw_text.toPlainText())
        self.status_label.setText("Copied to clipboard")
