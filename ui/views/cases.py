"""
Cases View
Display and manage security cases
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QFrame, QLabel, QPushButton
)
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor
from typing import List

from ..styles import EdgeColors, get_severity_color, get_status_color
from ..widgets import DetailPanel


class CaseTable(QTableWidget):
    """
    Table widget for displaying case data
    """

    case_selected = pyqtSignal(str)  # Emits case_id

    COLUMNS = [
        ("Severity", 80),
        ("Type", 150),
        ("Status", 100),
        ("Created", 120),
        ("Affected User", 200),
        ("Description", 300)
    ]

    def __init__(self, parent=None):
        super().__init__(parent)

        self.cases = []
        self._setup_table()

    def _setup_table(self):
        """Initialize table configuration"""
        self.setColumnCount(len(self.COLUMNS))
        self.setHorizontalHeaderLabels([col[0] for col in self.COLUMNS])

        # Set column widths
        header = self.horizontalHeader()
        for i, (_, width) in enumerate(self.COLUMNS):
            if i == 5:  # Description column stretches
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
            else:
                self.setColumnWidth(i, width)

        # Table settings
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)

        # Signals
        self.itemSelectionChanged.connect(self._on_selection_changed)

    def set_cases(self, cases: List):
        """Populate table with case data"""
        self.cases = cases
        self.setRowCount(len(cases))

        for row, case in enumerate(cases):
            # Severity
            severity_item = QTableWidgetItem(case.severity.value)
            severity_item.setData(Qt.ItemDataRole.UserRole, case.case_id)
            color = get_severity_color(case.severity.value)
            severity_item.setForeground(QColor(color))
            severity_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.setItem(row, 0, severity_item)

            # Type
            type_item = QTableWidgetItem(case.case_type)
            self.setItem(row, 1, type_item)

            # Status
            status_item = QTableWidgetItem(case.status)
            status_color = get_status_color(case.status)
            status_item.setForeground(QColor(status_color))
            self.setItem(row, 2, status_item)

            # Created
            created_str = case.created_time.strftime("%Y-%m-%d %H:%M")
            created_item = QTableWidgetItem(created_str)
            self.setItem(row, 3, created_item)

            # Affected User
            user_item = QTableWidgetItem(case.affected_user or "N/A")
            self.setItem(row, 4, user_item)

            # Description
            desc_item = QTableWidgetItem(case.description[:100])
            desc_item.setToolTip(case.description)
            self.setItem(row, 5, desc_item)

    def get_selected_case(self):
        """Get currently selected case object"""
        selected_rows = set(item.row() for item in self.selectedItems())
        if selected_rows:
            row = list(selected_rows)[0]
            if row < len(self.cases):
                return self.cases[row]
        return None

    def _on_selection_changed(self):
        """Handle selection change"""
        case = self.get_selected_case()
        if case:
            self.case_selected.emit(case.case_id)


class CasesView(QWidget):
    """
    View for browsing security cases
    """

    def __init__(self, parent=None):
        super().__init__(parent)

        self.cases = []
        self._setup_ui()

    def _setup_ui(self):
        """Setup cases view layout"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        # Header
        header = QHBoxLayout()

        title = QLabel("Security Cases")
        title.setObjectName("sectionTitle")
        header.addWidget(title)

        header.addStretch()

        self.count_label = QLabel("0 cases")
        self.count_label.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY};")
        header.addWidget(self.count_label)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.setObjectName("secondary")
        header.addWidget(self.refresh_btn)

        layout.addLayout(header)

        # Main content with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Case table container
        table_container = QFrame()
        table_container.setObjectName("card")
        table_layout = QVBoxLayout(table_container)
        table_layout.setContentsMargins(16, 16, 16, 16)

        self.case_table = CaseTable()
        self.case_table.case_selected.connect(self._on_case_selected)
        table_layout.addWidget(self.case_table)

        splitter.addWidget(table_container)

        # Detail panel
        self.detail_panel = DetailPanel()
        self.detail_panel.close_btn.clicked.connect(self.detail_panel.hide)
        splitter.addWidget(self.detail_panel)

        # Set splitter sizes
        splitter.setSizes([700, 400])
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)

    def update_data(self, cases: List):
        """Update with new case data"""
        self.cases = cases
        self.case_table.set_cases(cases)
        self.count_label.setText(f"{len(cases)} cases")

    def _on_case_selected(self, case_id: str):
        """Handle case selection"""
        case = next((c for c in self.cases if c.case_id == case_id), None)
        if case:
            self.detail_panel.show_case(case)
