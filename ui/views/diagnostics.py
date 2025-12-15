"""
Diagnostics View
Display diagnostic check results
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel,
    QPushButton, QComboBox, QScrollArea
)
from PyQt6.QtCore import Qt, pyqtSignal
from typing import List, Dict

from ..styles import EdgeColors
from ..widgets import DiagnosticResultsList


class DiagnosticsView(QWidget):
    """
    View for running and reviewing diagnostic checks
    """

    run_diagnostics = pyqtSignal()
    analyze_findings = pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__(parent)

        self.results = []
        self._setup_ui()

    def _setup_ui(self):
        """Setup diagnostics view layout"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        # Header
        header = QHBoxLayout()

        title = QLabel("Diagnostic Checks")
        title.setObjectName("sectionTitle")
        header.addWidget(title)

        header.addStretch()

        # Category filter
        category_label = QLabel("Category:")
        category_label.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY};")
        header.addWidget(category_label)

        self.category_combo = QComboBox()
        self.category_combo.addItems([
            "All Categories",
            "Authentication",
            "Mail Flow",
            "Threat Detection",
            "Integration",
            "Security Posture"
        ])
        self.category_combo.currentTextChanged.connect(self._on_category_changed)
        header.addWidget(self.category_combo)

        header.addSpacing(16)

        self.run_btn = QPushButton("Run Diagnostics")
        self.run_btn.clicked.connect(self.run_diagnostics.emit)
        header.addWidget(self.run_btn)

        layout.addLayout(header)

        # Summary cards
        summary_row = QHBoxLayout()
        summary_row.setSpacing(16)

        self.passed_card = self._create_summary_card("PASSED", "0", EdgeColors.SUCCESS)
        summary_row.addWidget(self.passed_card)

        self.failed_card = self._create_summary_card("FAILED", "0", EdgeColors.ERROR)
        summary_row.addWidget(self.failed_card)

        self.critical_card = self._create_summary_card("CRITICAL", "0", EdgeColors.ERROR)
        summary_row.addWidget(self.critical_card)

        self.high_card = self._create_summary_card("HIGH", "0", EdgeColors.WARNING)
        summary_row.addWidget(self.high_card)

        layout.addLayout(summary_row)

        # Results list
        self.results_list = DiagnosticResultsList()
        layout.addWidget(self.results_list, 1)

        # Footer
        footer = QHBoxLayout()

        self.analyze_btn = QPushButton("Analyze with AI")
        self.analyze_btn.clicked.connect(self._on_analyze_clicked)
        self.analyze_btn.setEnabled(False)
        footer.addWidget(self.analyze_btn)

        footer.addStretch()

        self.export_btn = QPushButton("Export Report")
        self.export_btn.setObjectName("secondary")
        self.export_btn.setEnabled(False)
        footer.addWidget(self.export_btn)

        layout.addLayout(footer)

    def _create_summary_card(self, title: str, value: str, color: str) -> QFrame:
        """Create a summary metric card"""
        card = QFrame()
        card.setObjectName("card")
        card.setMinimumHeight(80)

        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 12, 16, 12)
        layout.setSpacing(4)

        title_label = QLabel(title)
        title_label.setStyleSheet(f"""
            font-size: 9px;
            font-weight: 500;
            color: {EdgeColors.TEXT_SECONDARY};
            letter-spacing: 1px;
        """)
        layout.addWidget(title_label)

        value_label = QLabel(value)
        value_label.setObjectName(f"summary_{title.lower()}")
        value_label.setStyleSheet(f"""
            font-size: 22px;
            font-weight: bold;
            color: {color};
        """)
        layout.addWidget(value_label)

        return card

    def update_results(self, results: List):
        """Update with diagnostic results"""
        self.results = results

        # Calculate summary
        passed = sum(1 for r in results if r.passed)
        failed = len(results) - passed
        critical = sum(1 for r in results if not r.passed and r.severity == "CRITICAL")
        high = sum(1 for r in results if not r.passed and r.severity == "HIGH")

        # Update summary cards
        self.passed_card.findChild(QLabel, "summary_passed").setText(str(passed))
        self.failed_card.findChild(QLabel, "summary_failed").setText(str(failed))
        self.critical_card.findChild(QLabel, "summary_critical").setText(str(critical))
        self.high_card.findChild(QLabel, "summary_high").setText(str(high))

        # Update results list
        self._apply_filter()

        # Enable buttons
        self.analyze_btn.setEnabled(failed > 0)
        self.export_btn.setEnabled(len(results) > 0)

    def _apply_filter(self):
        """Apply category filter to results"""
        category = self.category_combo.currentText()

        if category == "All Categories":
            filtered = self.results
        else:
            filtered = [r for r in self.results if r.category == category]

        self.results_list.set_results(filtered)

    def _on_category_changed(self, category: str):
        """Handle category filter change"""
        self._apply_filter()

    def _on_analyze_clicked(self):
        """Handle analyze button click"""
        # Get failed results
        failed = [r for r in self.results if not r.passed]
        if failed:
            # Convert to dict format for Claude
            findings = [r.to_dict() for r in failed]
            self.analyze_findings.emit(findings)
