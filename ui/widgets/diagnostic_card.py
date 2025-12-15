"""
Diagnostic Card Widget
Displays diagnostic rule results
"""

from PyQt6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QWidget
)
from PyQt6.QtCore import Qt, pyqtSignal
from typing import List

from ..styles import EdgeColors, get_severity_color


class DiagnosticResultCard(QFrame):
    """
    Card displaying a single diagnostic result
    """

    fix_requested = pyqtSignal(str)  # Emits rule_id

    def __init__(self, result, parent=None):
        super().__init__(parent)

        self.result = result
        passed = result.passed

        # Style based on pass/fail
        if passed:
            self.setObjectName("card")
            border_color = EdgeColors.SUCCESS
        else:
            severity = result.severity
            if severity == "CRITICAL":
                self.setObjectName("cardError")
            elif severity == "HIGH":
                self.setObjectName("cardWarning")
            else:
                self.setObjectName("cardAccent")
            border_color = get_severity_color(severity)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        # Header row
        header = QHBoxLayout()

        # Status indicator
        status_indicator = QLabel("PASS" if passed else "FAIL")
        status_indicator.setStyleSheet(f"""
            background-color: {EdgeColors.SUCCESS if passed else get_severity_color(result.severity)};
            color: {EdgeColors.TEXT_INVERSE};
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 8px;
            font-weight: bold;
        """)
        header.addWidget(status_indicator)

        # Category
        category_label = QLabel(result.category)
        category_label.setStyleSheet(f"""
            color: {EdgeColors.TEXT_SECONDARY};
            font-size: 8px;
        """)
        header.addWidget(category_label)

        header.addStretch()

        # Severity (only show for failures)
        if not passed:
            severity_label = QLabel(result.severity)
            severity_label.setStyleSheet(f"""
                color: {get_severity_color(result.severity)};
                font-size: 8px;
                font-weight: 600;
            """)
            header.addWidget(severity_label)

        layout.addLayout(header)

        # Rule name
        name_label = QLabel(result.rule_name)
        name_label.setStyleSheet(f"""
            font-size: 8px;
            font-weight: 600;
            color: {EdgeColors.TEXT_PRIMARY};
        """)
        name_label.setWordWrap(True)
        layout.addWidget(name_label)

        # Evidence
        evidence_label = QLabel(result.evidence)
        evidence_label.setStyleSheet(f"""
            font-size: 8px;
            color: {EdgeColors.TEXT_SECONDARY};
        """)
        evidence_label.setWordWrap(True)
        layout.addWidget(evidence_label)

        # Affected items (if any)
        if result.affected_items:
            affected_text = ", ".join(result.affected_items[:5])
            if len(result.affected_items) > 5:
                affected_text += f" (+{len(result.affected_items) - 5} more)"

            affected_label = QLabel(f"Affected: {affected_text}")
            affected_label.setStyleSheet(f"""
                font-size: 9px;
                color: {EdgeColors.TEXT_SECONDARY};
                font-style: italic;
            """)
            affected_label.setWordWrap(True)
            layout.addWidget(affected_label)

        # Remediation steps (for failures)
        if not passed and result.remediation_steps:
            layout.addSpacing(8)

            steps_label = QLabel("Remediation:")
            steps_label.setStyleSheet(f"""
                font-size: 8px;
                font-weight: 600;
                color: {EdgeColors.TEXT_PRIMARY};
            """)
            layout.addWidget(steps_label)

            for i, step in enumerate(result.remediation_steps[:3], 1):
                step_label = QLabel(f"{i}. {step}")
                step_label.setStyleSheet(f"""
                    font-size: 9px;
                    color: {EdgeColors.TEXT_SECONDARY};
                    margin-left: 8px;
                """)
                step_label.setWordWrap(True)
                layout.addWidget(step_label)

            if len(result.remediation_steps) > 3:
                more_label = QLabel(f"...and {len(result.remediation_steps) - 3} more steps")
                more_label.setStyleSheet(f"""
                    font-size: 9px;
                    color: {EdgeColors.TEXT_SECONDARY};
                    font-style: italic;
                    margin-left: 8px;
                """)
                layout.addWidget(more_label)


class DiagnosticResultsList(QFrame):
    """
    Scrollable list of diagnostic results
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setObjectName("card")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header
        header = QHBoxLayout()

        title = QLabel("Diagnostic Results")
        title.setObjectName("sectionTitle")
        header.addWidget(title)

        header.addStretch()

        self.summary_label = QLabel()
        self.summary_label.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY};")
        header.addWidget(self.summary_label)

        layout.addLayout(header)

        # Scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        self.results_container = QWidget()
        self.results_layout = QVBoxLayout(self.results_container)
        self.results_layout.setContentsMargins(0, 0, 0, 0)
        self.results_layout.setSpacing(12)

        scroll.setWidget(self.results_container)
        layout.addWidget(scroll)

    def set_results(self, results: List):
        """Update displayed results"""
        # Clear existing
        while self.results_layout.count():
            item = self.results_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Count pass/fail
        passed = sum(1 for r in results if r.passed)
        failed = len(results) - passed

        self.summary_label.setText(f"{passed} passed, {failed} failed")

        # Add result cards (failures first)
        sorted_results = sorted(results, key=lambda r: (r.passed, r.severity))

        for result in sorted_results:
            card = DiagnosticResultCard(result)
            self.results_layout.addWidget(card)

        self.results_layout.addStretch()
