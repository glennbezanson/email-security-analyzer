"""
Threats View
Display and manage detected threats
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QFrame
)
from PyQt6.QtCore import Qt, pyqtSignal
from typing import List

from ..widgets import ThreatListWidget, DetailPanel, SearchBar, QuickFilterBar


class ThreatsView(QWidget):
    """
    View for browsing and managing threats
    """

    analyze_requested = pyqtSignal(list)
    remediate_requested = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

        self.threats = []
        self.filtered_threats = []

        self._setup_ui()

    def _setup_ui(self):
        """Setup threats view layout"""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(16)

        # Search and filter bar
        self.search_bar = SearchBar()
        self.search_bar.search_changed.connect(self._on_search_changed)
        self.search_bar.filter_changed.connect(self._on_filter_changed)
        layout.addWidget(self.search_bar)

        # Quick filters
        self.quick_filters = QuickFilterBar()
        self.quick_filters.filter_selected.connect(self._on_quick_filter)
        layout.addWidget(self.quick_filters)

        # Main content with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Threat list
        self.threat_list = ThreatListWidget()
        self.threat_list.threat_selected.connect(self._on_threat_selected)
        self.threat_list.analyze_requested.connect(self.analyze_requested.emit)
        splitter.addWidget(self.threat_list)

        # Detail panel
        self.detail_panel = DetailPanel()
        self.detail_panel.analyze_requested.connect(lambda t: self.analyze_requested.emit([t]))
        self.detail_panel.remediate_requested.connect(self.remediate_requested.emit)
        self.detail_panel.close_btn.clicked.connect(self.detail_panel.hide)
        splitter.addWidget(self.detail_panel)

        # Set splitter sizes
        splitter.setSizes([700, 400])
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter)

    def update_data(self, threats: List):
        """Update with new threat data"""
        self.threats = threats
        self.filtered_threats = threats
        self._apply_filters()

    def get_selected_items(self) -> List:
        """Get selected threat objects"""
        return self.threat_list.get_selected_items()

    def _apply_filters(self):
        """Apply current filters to threat list"""
        filters = self.search_bar.get_filters()

        filtered = self.threats

        # Search filter
        search = filters.get('search', '').lower()
        if search:
            filtered = [
                t for t in filtered
                if search in t.subject.lower()
                or search in t.from_address.lower()
                or search in t.threat_id.lower()
            ]

        # Severity filter
        severity = filters.get('severity')
        if severity:
            filtered = [t for t in filtered if t.severity.value == severity]

        # Status filter
        status = filters.get('status')
        if status:
            filtered = [t for t in filtered if t.remediation_status.value == status]

        self.filtered_threats = filtered
        self.threat_list.set_threats(filtered)

    def _on_search_changed(self, text: str):
        """Handle search text change"""
        self._apply_filters()

    def _on_filter_changed(self, filters: dict):
        """Handle filter changes"""
        self._apply_filters()

    def _on_quick_filter(self, filter_id: str):
        """Handle quick filter selection"""
        from datetime import datetime, timedelta

        if filter_id == "all":
            self.search_bar.clear_filters()
        elif filter_id == "critical":
            self.search_bar.severity_combo.setCurrentText("CRITICAL")
        elif filter_id == "high":
            self.search_bar.severity_combo.setCurrentText("HIGH")
        elif filter_id == "unremediated":
            self.search_bar.status_combo.setCurrentText("Not Remediated")
        elif filter_id == "today":
            # Filter to today's threats
            today = datetime.utcnow().date()
            self.filtered_threats = [
                t for t in self.threats
                if t.received_time.date() == today
            ]
            self.threat_list.set_threats(self.filtered_threats)
            return

        self._apply_filters()

    def _on_threat_selected(self, threat_id: str):
        """Handle threat selection"""
        threat = next((t for t in self.threats if t.threat_id == threat_id), None)
        if threat:
            self.detail_panel.show_threat(threat)
