"""
Search Bar Widget
Search and filter functionality
"""

from PyQt6.QtWidgets import (
    QFrame, QHBoxLayout, QLineEdit, QComboBox, QPushButton, QLabel
)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer

from ..styles import EdgeColors


class SearchBar(QFrame):
    """
    Search bar with filtering options
    """

    search_changed = pyqtSignal(str)  # Emits search text
    filter_changed = pyqtSignal(dict)  # Emits filter settings

    def __init__(self, parent=None):
        super().__init__(parent)

        self.setObjectName("card")
        self.setMaximumHeight(60)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        # Search icon/label
        search_label = QLabel("Search")
        search_label.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY};")
        layout.addWidget(search_label)

        # Search input
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search by subject, sender, or ID...")
        self.search_input.setMinimumWidth(300)
        self.search_input.textChanged.connect(self._on_search_changed)
        layout.addWidget(self.search_input, 1)

        # Debounce timer for search
        self._search_timer = QTimer()
        self._search_timer.setSingleShot(True)
        self._search_timer.timeout.connect(self._emit_search)

        layout.addSpacing(16)

        # Severity filter
        severity_label = QLabel("Severity:")
        severity_label.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY};")
        layout.addWidget(severity_label)

        self.severity_combo = QComboBox()
        self.severity_combo.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.severity_combo.setMinimumWidth(100)
        self.severity_combo.currentTextChanged.connect(self._on_filter_changed)
        layout.addWidget(self.severity_combo)

        # Status filter
        status_label = QLabel("Status:")
        status_label.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY};")
        layout.addWidget(status_label)

        self.status_combo = QComboBox()
        self.status_combo.addItems(["All", "Not Remediated", "Remediated", "Auto-Remediated", "Pending"])
        self.status_combo.setMinimumWidth(120)
        self.status_combo.currentTextChanged.connect(self._on_filter_changed)
        layout.addWidget(self.status_combo)

        # Clear button
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setObjectName("secondary")
        self.clear_btn.clicked.connect(self.clear_filters)
        layout.addWidget(self.clear_btn)

    def _on_search_changed(self, text: str):
        """Handle search input change with debounce"""
        self._search_timer.stop()
        self._search_timer.start(300)  # 300ms debounce

    def _emit_search(self):
        """Emit search signal after debounce"""
        self.search_changed.emit(self.search_input.text())

    def _on_filter_changed(self):
        """Handle filter changes"""
        filters = self.get_filters()
        self.filter_changed.emit(filters)

    def get_filters(self) -> dict:
        """Get current filter settings"""
        return {
            'search': self.search_input.text(),
            'severity': self.severity_combo.currentText() if self.severity_combo.currentText() != "All" else None,
            'status': self.status_combo.currentText() if self.status_combo.currentText() != "All" else None
        }

    def clear_filters(self):
        """Reset all filters"""
        self.search_input.clear()
        self.severity_combo.setCurrentText("All")
        self.status_combo.setCurrentText("All")


class QuickFilterBar(QFrame):
    """
    Quick filter buttons for common filters
    """

    filter_selected = pyqtSignal(str)  # Emits filter name

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        self.buttons = {}

        filters = [
            ("all", "All"),
            ("critical", "Critical"),
            ("high", "High"),
            ("unremediated", "Unremediated"),
            ("today", "Today")
        ]

        for filter_id, label in filters:
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {EdgeColors.LIGHT};
                    color: {EdgeColors.TEXT_SECONDARY};
                    border: none;
                    border-radius: 16px;
                    padding: 6px 16px;
                    font-size: 10px;
                }}
                QPushButton:checked {{
                    background-color: {EdgeColors.PRIMARY};
                    color: {EdgeColors.TEXT_INVERSE};
                }}
                QPushButton:hover:!checked {{
                    background-color: #e5e6e7;
                }}
            """)
            btn.clicked.connect(lambda checked, f=filter_id: self._on_filter_clicked(f))
            layout.addWidget(btn)
            self.buttons[filter_id] = btn

        # Set "all" as default selected
        self.buttons["all"].setChecked(True)

        layout.addStretch()

    def _on_filter_clicked(self, filter_id: str):
        """Handle filter button click"""
        # Uncheck other buttons
        for btn_id, btn in self.buttons.items():
            btn.setChecked(btn_id == filter_id)

        self.filter_selected.emit(filter_id)

    def set_active_filter(self, filter_id: str):
        """Programmatically set active filter"""
        for btn_id, btn in self.buttons.items():
            btn.setChecked(btn_id == filter_id)
