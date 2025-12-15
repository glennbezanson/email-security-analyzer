"""
Threat Table Widget
Displays list of threats in a table format
"""

from PyQt6.QtWidgets import (
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from typing import List, Optional
from datetime import datetime

from ..styles import EdgeColors, get_severity_color, get_status_color


class ThreatTable(QTableWidget):
    """
    Table widget for displaying threat data
    """

    threat_selected = pyqtSignal(str)  # Emits threat_id
    threat_double_clicked = pyqtSignal(str)  # Emits threat_id

    COLUMNS = [
        ("Severity", 80),
        ("Time", 120),
        ("Subject", 250),
        ("From", 200),
        ("Attack Type", 150),
        ("Status", 120)
    ]

    def __init__(self, parent=None):
        super().__init__(parent)

        self.threats = []
        self._setup_table()

    def _setup_table(self):
        """Initialize table configuration"""
        self.setColumnCount(len(self.COLUMNS))
        self.setHorizontalHeaderLabels([col[0] for col in self.COLUMNS])

        # Set column widths
        header = self.horizontalHeader()
        for i, (_, width) in enumerate(self.COLUMNS):
            if i == 2:  # Subject column stretches
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
            else:
                self.setColumnWidth(i, width)

        # Table settings
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)

        # Signals
        self.itemSelectionChanged.connect(self._on_selection_changed)
        self.cellDoubleClicked.connect(self._on_double_click)

    def set_threats(self, threats: List):
        """Populate table with threat data"""
        self.threats = threats
        self.setRowCount(len(threats))

        for row, threat in enumerate(threats):
            # Severity
            severity_item = QTableWidgetItem(threat.severity.value)
            severity_item.setData(Qt.ItemDataRole.UserRole, threat.threat_id)
            color = get_severity_color(threat.severity.value)
            severity_item.setForeground(QColor(color))
            severity_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.setItem(row, 0, severity_item)

            # Time
            time_str = threat.received_time.strftime("%H:%M:%S")
            time_item = QTableWidgetItem(time_str)
            time_item.setToolTip(threat.received_time.strftime("%Y-%m-%d %H:%M:%S"))
            self.setItem(row, 1, time_item)

            # Subject
            subject_item = QTableWidgetItem(threat.subject[:100])
            subject_item.setToolTip(threat.subject)
            self.setItem(row, 2, subject_item)

            # From
            from_text = f"{threat.from_name} <{threat.from_address}>" if threat.from_name else threat.from_address
            from_item = QTableWidgetItem(from_text[:50])
            from_item.setToolTip(from_text)
            self.setItem(row, 3, from_item)

            # Attack Type
            attack_item = QTableWidgetItem(threat.attack_type.value)
            self.setItem(row, 4, attack_item)

            # Status
            status_item = QTableWidgetItem(threat.remediation_status.value)
            status_color = get_status_color(threat.remediation_status.value)
            status_item.setForeground(QColor(status_color))
            self.setItem(row, 5, status_item)

    def get_selected_threats(self) -> List:
        """Get currently selected threat objects"""
        selected_rows = set(item.row() for item in self.selectedItems())
        return [self.threats[row] for row in selected_rows if row < len(self.threats)]

    def get_selected_threat_ids(self) -> List[str]:
        """Get IDs of selected threats"""
        return [t.threat_id for t in self.get_selected_threats()]

    def _on_selection_changed(self):
        """Handle selection change"""
        threats = self.get_selected_threats()
        if threats:
            self.threat_selected.emit(threats[0].threat_id)

    def _on_double_click(self, row: int, column: int):
        """Handle double click"""
        if row < len(self.threats):
            self.threat_double_clicked.emit(self.threats[row].threat_id)


class ThreatListWidget(QFrame):
    """
    Container widget with threat table and controls
    """

    threat_selected = pyqtSignal(str)
    analyze_requested = pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setObjectName("card")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Header
        header = QHBoxLayout()

        title = QLabel("Threats")
        title.setObjectName("sectionTitle")
        header.addWidget(title)

        header.addStretch()

        self.count_label = QLabel("0 threats")
        self.count_label.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY};")
        header.addWidget(self.count_label)

        layout.addLayout(header)

        # Table
        self.table = ThreatTable()
        self.table.threat_selected.connect(self.threat_selected.emit)
        layout.addWidget(self.table)

        # Footer
        footer = QHBoxLayout()

        self.analyze_btn = QPushButton("Analyze Selected")
        self.analyze_btn.clicked.connect(self._on_analyze_clicked)
        footer.addWidget(self.analyze_btn)

        footer.addStretch()

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setObjectName("secondary")
        footer.addWidget(self.refresh_btn)

        layout.addLayout(footer)

    def set_threats(self, threats: List):
        """Update threats in the table"""
        self.table.set_threats(threats)
        self.count_label.setText(f"{len(threats)} threats")

    def get_selected_items(self) -> List:
        """Get selected threat objects"""
        return self.table.get_selected_threats()

    def _on_analyze_clicked(self):
        """Handle analyze button click"""
        selected = self.table.get_selected_threats()
        if selected:
            self.analyze_requested.emit(selected)
