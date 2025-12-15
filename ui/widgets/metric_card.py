"""
Metric Card Widget
Displays key metrics on the dashboard
"""

from PyQt6.QtWidgets import (
    QFrame, QVBoxLayout, QHBoxLayout, QLabel
)
from PyQt6.QtCore import Qt

from ..styles import EdgeColors


class MetricCard(QFrame):
    """
    A card widget displaying a metric with title, value, and optional trend
    """

    def __init__(
        self,
        title: str,
        value: str = "0",
        subtitle: str = "",
        accent: bool = False,
        parent=None
    ):
        super().__init__(parent)

        self.setObjectName("cardAccent" if accent else "card")
        self.setMinimumHeight(100)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(8)

        # Title
        self.title_label = QLabel(title)
        self.title_label.setStyleSheet(f"""
            font-size: 10px;
            font-weight: 500;
            color: {EdgeColors.TEXT_SECONDARY};
            text-transform: uppercase;
            letter-spacing: 1px;
        """)
        layout.addWidget(self.title_label)

        # Value
        self.value_label = QLabel(value)
        self.value_label.setStyleSheet(f"""
            font-size: 30px;
            font-weight: bold;
            color: {EdgeColors.TEXT_PRIMARY};
        """)
        layout.addWidget(self.value_label)

        # Subtitle
        self.subtitle_label = QLabel(subtitle)
        self.subtitle_label.setStyleSheet(f"""
            font-size: 10px;
            color: {EdgeColors.TEXT_SECONDARY};
        """)
        layout.addWidget(self.subtitle_label)

        layout.addStretch()

    def set_value(self, value: str):
        """Update the metric value"""
        self.value_label.setText(value)

    def set_subtitle(self, subtitle: str):
        """Update the subtitle"""
        self.subtitle_label.setText(subtitle)

    def set_trend(self, trend: str, positive: bool = True):
        """Set trend indicator"""
        color = EdgeColors.SUCCESS if positive else EdgeColors.ERROR
        self.subtitle_label.setStyleSheet(f"""
            font-size: 10px;
            color: {color};
        """)
        self.subtitle_label.setText(trend)


class SeverityMetricCard(QFrame):
    """
    Card displaying severity breakdown with color indicators
    """

    def __init__(self, title: str = "Severity", parent=None):
        super().__init__(parent)

        self.setObjectName("card")
        self.setMinimumHeight(140)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Title
        title_label = QLabel(title)
        title_label.setStyleSheet(f"""
            font-size: 10px;
            font-weight: 500;
            color: {EdgeColors.TEXT_SECONDARY};
            text-transform: uppercase;
            letter-spacing: 1px;
        """)
        layout.addWidget(title_label)

        # Severity rows
        self.severity_widgets = {}

        for severity, color in [
            ("CRITICAL", EdgeColors.ERROR),
            ("HIGH", EdgeColors.WARNING),
            ("MEDIUM", EdgeColors.INFO),
            ("LOW", EdgeColors.MUTED)
        ]:
            row = QHBoxLayout()

            indicator = QLabel()
            indicator.setFixedSize(12, 12)
            indicator.setStyleSheet(f"""
                background-color: {color};
                border-radius: 6px;
            """)
            row.addWidget(indicator)

            label = QLabel(severity)
            label.setStyleSheet(f"""
                font-size: 10px;
                color: {EdgeColors.TEXT_PRIMARY};
            """)
            row.addWidget(label)

            row.addStretch()

            count = QLabel("0")
            count.setStyleSheet(f"""
                font-size: 10px;
                font-weight: 600;
                color: {EdgeColors.TEXT_PRIMARY};
            """)
            row.addWidget(count)

            self.severity_widgets[severity] = count
            layout.addLayout(row)

        layout.addStretch()

    def set_counts(self, counts: dict):
        """Update severity counts"""
        for severity, widget in self.severity_widgets.items():
            widget.setText(str(counts.get(severity, 0)))


class StatusCard(QFrame):
    """
    Card displaying connection/service status
    """

    def __init__(self, title: str, parent=None):
        super().__init__(parent)

        self.setObjectName("card")
        self.setMinimumHeight(80)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Status indicator
        self.indicator = QLabel()
        self.indicator.setFixedSize(12, 12)
        self.indicator.setStyleSheet(f"""
            background-color: {EdgeColors.MUTED};
            border-radius: 6px;
        """)
        layout.addWidget(self.indicator)

        # Content
        content = QVBoxLayout()
        content.setSpacing(4)

        self.title_label = QLabel(title)
        self.title_label.setStyleSheet(f"""
            font-size: 10px;
            font-weight: 500;
            color: {EdgeColors.TEXT_PRIMARY};
        """)
        content.addWidget(self.title_label)

        self.status_label = QLabel("Unknown")
        self.status_label.setStyleSheet(f"""
            font-size: 10px;
            color: {EdgeColors.TEXT_SECONDARY};
        """)
        content.addWidget(self.status_label)

        layout.addLayout(content)
        layout.addStretch()

    def set_status(self, status: str, connected: bool = True):
        """Update status display"""
        color = EdgeColors.SUCCESS if connected else EdgeColors.ERROR
        self.indicator.setStyleSheet(f"""
            background-color: {color};
            border-radius: 6px;
        """)
        self.status_label.setText(status)
