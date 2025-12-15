"""
Mail Flow Tracing View
Unified mail flow tracing from Exchange Online and Abnormal Security
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QComboBox, QDateEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QTextEdit, QGroupBox, QFrame,
    QProgressBar, QMessageBox, QTabWidget, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QDate
from PyQt6.QtGui import QColor
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum

from ..styles import EdgeColors, get_severity_color


class UnifiedStatus(Enum):
    """Unified delivery status across sources"""
    DELIVERED = "Delivered"
    QUARANTINED_EOP = "Quarantined (EOP)"
    QUARANTINED_ABNORMAL = "Quarantined (Abnormal)"
    REMEDIATED = "Remediated"
    BLOCKED = "Blocked"
    PENDING = "Pending"
    FAILED = "Failed"
    UNKNOWN = "Unknown"


@dataclass
class UnifiedMailEvent:
    """Unified mail event from any source"""
    message_id: str
    sender: str
    recipient: str
    subject: str
    received: datetime
    status: UnifiedStatus
    source: str  # "Exchange", "Abnormal", "Both"
    details: Dict[str, Any]

    # Optional fields
    threat_type: str = ""
    quarantine_type: str = ""
    policy_name: str = ""
    from_ip: str = ""

    def status_color(self) -> str:
        """Get color for status"""
        colors = {
            UnifiedStatus.DELIVERED: EdgeColors.SUCCESS,
            UnifiedStatus.QUARANTINED_EOP: EdgeColors.WARNING,
            UnifiedStatus.QUARANTINED_ABNORMAL: EdgeColors.WARNING,
            UnifiedStatus.REMEDIATED: EdgeColors.INFO,
            UnifiedStatus.BLOCKED: EdgeColors.ERROR,
            UnifiedStatus.PENDING: EdgeColors.TEXT_SECONDARY,
            UnifiedStatus.FAILED: EdgeColors.ERROR,
            UnifiedStatus.UNKNOWN: EdgeColors.TEXT_SECONDARY,
        }
        return colors.get(self.status, EdgeColors.TEXT_SECONDARY)


class MailFlowWorker(QThread):
    """Worker thread for mail flow queries"""

    finished = pyqtSignal(list)  # List of UnifiedMailEvent
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, search_type: str, query: str, start_date: datetime,
                 end_date: datetime, abnormal_client, exchange_client):
        super().__init__()
        self.search_type = search_type  # "recipient" or "sender_domain"
        self.query = query
        self.start_date = start_date
        self.end_date = end_date
        self.abnormal_client = abnormal_client
        self.exchange_client = exchange_client

    def run(self):
        events = []

        try:
            # Query Exchange Online
            self.progress.emit("Querying Exchange message trace...")
            exchange_events = self._query_exchange()
            events.extend(exchange_events)

            # Query Exchange Quarantine
            self.progress.emit("Querying Exchange quarantine...")
            quarantine_events = self._query_quarantine()
            events.extend(quarantine_events)

            # Query Abnormal Security
            self.progress.emit("Querying Abnormal Security...")
            abnormal_events = self._query_abnormal()
            events.extend(abnormal_events)

            # Merge duplicates (same message from multiple sources)
            self.progress.emit("Merging results...")
            merged = self._merge_events(events)

            # Sort by received date descending
            merged.sort(key=lambda x: x.received, reverse=True)

            self.finished.emit(merged)

        except Exception as e:
            self.error.emit(str(e))

    def _query_exchange(self) -> List[UnifiedMailEvent]:
        """Query Exchange message trace"""
        events = []

        if not self.exchange_client:
            return events

        try:
            if self.search_type == "recipient":
                traces = self.exchange_client.get_message_trace(
                    recipient=self.query,
                    start_date=self.start_date,
                    end_date=self.end_date
                )
            else:  # sender_domain
                traces = self.exchange_client.get_message_trace(
                    sender_domain=self.query,
                    start_date=self.start_date,
                    end_date=self.end_date
                )

            for trace in traces:
                status = UnifiedStatus.UNKNOWN
                if trace.status.value == "Delivered":
                    status = UnifiedStatus.DELIVERED
                elif trace.status.value == "Quarantined":
                    status = UnifiedStatus.QUARANTINED_EOP
                elif trace.status.value == "Failed":
                    status = UnifiedStatus.FAILED
                elif trace.status.value == "Pending":
                    status = UnifiedStatus.PENDING
                elif trace.status.value == "Filtered":
                    status = UnifiedStatus.BLOCKED

                events.append(UnifiedMailEvent(
                    message_id=trace.message_id,
                    sender=trace.sender,
                    recipient=trace.recipient,
                    subject=trace.subject,
                    received=trace.received,
                    status=status,
                    source="Exchange",
                    details={'trace': trace.to_dict()},
                    from_ip=trace.from_ip
                ))

        except Exception as e:
            self.progress.emit(f"Exchange trace error: {e}")

        return events

    def _query_quarantine(self) -> List[UnifiedMailEvent]:
        """Query Exchange quarantine"""
        events = []

        if not self.exchange_client:
            return events

        try:
            if self.search_type == "recipient":
                messages = self.exchange_client.get_quarantine_messages(
                    recipient=self.query
                )
            else:  # sender_domain
                messages = self.exchange_client.get_quarantine_messages(
                    sender_domain=self.query
                )

            for msg in messages:
                events.append(UnifiedMailEvent(
                    message_id=msg.message_id,
                    sender=msg.sender,
                    recipient=msg.recipient,
                    subject=msg.subject,
                    received=msg.received,
                    status=UnifiedStatus.QUARANTINED_EOP,
                    source="Exchange",
                    details={'quarantine': msg.to_dict()},
                    quarantine_type=msg.quarantine_type.value,
                    policy_name=msg.policy_name
                ))

        except Exception as e:
            self.progress.emit(f"Quarantine query error: {e}")

        return events

    def _query_abnormal(self) -> List[UnifiedMailEvent]:
        """Query Abnormal Security threats"""
        events = []

        if not self.abnormal_client:
            return events

        try:
            threats = self.abnormal_client.get_threats(
                start_time=self.start_date,
                end_time=self.end_date
            )

            for threat in threats:
                # Filter by search criteria
                if self.search_type == "recipient":
                    if self.query.lower() not in [r.lower() for r in threat.to_addresses]:
                        continue
                else:  # sender_domain
                    sender_domain = threat.from_address.split('@')[-1].lower()
                    if sender_domain != self.query.lower():
                        continue

                # Map remediation status to unified status
                status = UnifiedStatus.UNKNOWN
                if threat.remediation_status.value == "Auto-Remediated":
                    status = UnifiedStatus.REMEDIATED
                elif threat.remediation_status.value == "Manual":
                    status = UnifiedStatus.QUARANTINED_ABNORMAL
                elif threat.remediation_status.value == "Post-Remediated":
                    status = UnifiedStatus.REMEDIATED
                else:
                    status = UnifiedStatus.QUARANTINED_ABNORMAL

                for recipient in threat.to_addresses:
                    if self.search_type == "recipient" and self.query.lower() != recipient.lower():
                        continue

                    events.append(UnifiedMailEvent(
                        message_id=threat.internet_message_id or threat.threat_id,
                        sender=threat.from_address,
                        recipient=recipient,
                        subject=threat.subject,
                        received=threat.received_time,
                        status=status,
                        source="Abnormal",
                        details={'threat': threat.to_dict()},
                        threat_type=threat.attack_type.value
                    ))

        except Exception as e:
            self.progress.emit(f"Abnormal query error: {e}")

        return events

    def _merge_events(self, events: List[UnifiedMailEvent]) -> List[UnifiedMailEvent]:
        """Merge events with same message ID from different sources"""
        by_message_id: Dict[str, List[UnifiedMailEvent]] = {}

        for event in events:
            key = event.message_id.lower() if event.message_id else f"{event.sender}_{event.subject}_{event.received}"
            if key not in by_message_id:
                by_message_id[key] = []
            by_message_id[key].append(event)

        merged = []
        for msg_id, group in by_message_id.items():
            if len(group) == 1:
                merged.append(group[0])
            else:
                # Merge multiple sources
                base = group[0]
                sources = set(e.source for e in group)
                base.source = "Both" if len(sources) > 1 else base.source

                # Combine details
                for e in group[1:]:
                    base.details.update(e.details)
                    if e.threat_type:
                        base.threat_type = e.threat_type
                    if e.quarantine_type:
                        base.quarantine_type = e.quarantine_type

                # Use most severe status
                statuses = [e.status for e in group]
                if UnifiedStatus.QUARANTINED_ABNORMAL in statuses:
                    base.status = UnifiedStatus.QUARANTINED_ABNORMAL
                elif UnifiedStatus.REMEDIATED in statuses:
                    base.status = UnifiedStatus.REMEDIATED
                elif UnifiedStatus.QUARANTINED_EOP in statuses:
                    base.status = UnifiedStatus.QUARANTINED_EOP

                merged.append(base)

        return merged


class MailFlowView(QWidget):
    """
    Mail Flow Tracing View
    Search by recipient or sender domain to trace mail delivery
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.main_window = parent
        self.events: List[UnifiedMailEvent] = []
        self._setup_ui()

    def _setup_ui(self):
        """Setup the UI"""
        layout = QVBoxLayout(self)
        layout.setSpacing(12)
        layout.setContentsMargins(16, 16, 16, 16)

        # Header
        header = QLabel("Mail Flow Tracing")
        header.setStyleSheet(f"""
            font-size: 18px;
            font-weight: 600;
            color: {EdgeColors.TEXT_PRIMARY};
        """)
        layout.addWidget(header)

        subtitle = QLabel("Trace mail delivery across Exchange Online and Abnormal Security")
        subtitle.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY}; font-size: 10px;")
        layout.addWidget(subtitle)

        # Search controls
        search_frame = QFrame()
        search_frame.setStyleSheet(f"""
            QFrame {{
                background: {EdgeColors.LIGHT};
                border: 1px solid {EdgeColors.MUTED};
                border-radius: 6px;
                padding: 12px;
            }}
        """)
        search_layout = QVBoxLayout(search_frame)

        # Row 1: Search type and query
        row1 = QHBoxLayout()

        type_label = QLabel("Search by:")
        type_label.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY}; font-size: 10px;")
        row1.addWidget(type_label)

        self.search_type = QComboBox()
        self.search_type.addItem("Recipient Email", "recipient")
        self.search_type.addItem("Sender Domain", "sender_domain")
        self.search_type.setFixedWidth(150)
        row1.addWidget(self.search_type)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("user@company.com or domain.com")
        self.search_input.returnPressed.connect(self._do_search)
        row1.addWidget(self.search_input, 1)

        search_layout.addLayout(row1)

        # Row 2: Date range
        row2 = QHBoxLayout()

        date_label = QLabel("Date range:")
        date_label.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY}; font-size: 10px;")
        row2.addWidget(date_label)

        self.start_date = QDateEdit()
        self.start_date.setDate(QDate.currentDate().addDays(-7))
        self.start_date.setCalendarPopup(True)
        self.start_date.setFixedWidth(120)
        row2.addWidget(self.start_date)

        row2.addWidget(QLabel("to"))

        self.end_date = QDateEdit()
        self.end_date.setDate(QDate.currentDate())
        self.end_date.setCalendarPopup(True)
        self.end_date.setFixedWidth(120)
        row2.addWidget(self.end_date)

        row2.addStretch()

        self.search_btn = QPushButton("Search")
        self.search_btn.clicked.connect(self._do_search)
        self.search_btn.setFixedWidth(100)
        row2.addWidget(self.search_btn)

        search_layout.addLayout(row2)

        layout.addWidget(search_frame)

        # Progress
        self.progress_label = QLabel("")
        self.progress_label.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY}; font-size: 9px;")
        self.progress_label.hide()
        layout.addWidget(self.progress_label)

        # Results splitter
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(7)
        self.results_table.setHorizontalHeaderLabels([
            "Received", "Status", "Source", "From", "To", "Subject", "Type"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.setAlternatingRowColors(True)
        self.results_table.itemSelectionChanged.connect(self._on_selection_changed)
        self.results_table.setStyleSheet(f"""
            QTableWidget {{
                background: {EdgeColors.LIGHT};
                border: 1px solid {EdgeColors.MUTED};
                gridline-color: {EdgeColors.MUTED};
            }}
            QTableWidget::item {{
                padding: 6px;
            }}
            QHeaderView::section {{
                background: {EdgeColors.PRIMARY};
                color: white;
                padding: 6px;
                border: none;
                font-weight: 500;
            }}
        """)
        splitter.addWidget(self.results_table)

        # Detail panel
        detail_widget = QWidget()
        detail_layout = QVBoxLayout(detail_widget)
        detail_layout.setContentsMargins(0, 8, 0, 0)

        self.detail_tabs = QTabWidget()

        # Summary tab
        self.summary_text = QTextEdit()
        self.summary_text.setReadOnly(True)
        self.summary_text.setStyleSheet(f"""
            background: {EdgeColors.LIGHT};
            border: 1px solid {EdgeColors.MUTED};
            color: {EdgeColors.TEXT_PRIMARY};
            font-family: 'Consolas', monospace;
            font-size: 10px;
        """)
        self.detail_tabs.addTab(self.summary_text, "Summary")

        # Delivery path tab
        self.path_tree = QTreeWidget()
        self.path_tree.setHeaderLabels(["Event", "Time", "Details"])
        self.path_tree.setStyleSheet(f"""
            background: {EdgeColors.LIGHT};
            border: 1px solid {EdgeColors.MUTED};
        """)
        self.detail_tabs.addTab(self.path_tree, "Delivery Path")

        # Actions tab
        actions_widget = QWidget()
        actions_layout = QVBoxLayout(actions_widget)

        actions_label = QLabel("Available Actions")
        actions_label.setStyleSheet(f"font-weight: 600; color: {EdgeColors.TEXT_PRIMARY};")
        actions_layout.addWidget(actions_label)

        self.release_btn = QPushButton("Release from Quarantine")
        self.release_btn.clicked.connect(self._release_message)
        self.release_btn.setEnabled(False)
        actions_layout.addWidget(self.release_btn)

        self.delete_btn = QPushButton("Delete from Quarantine")
        self.delete_btn.clicked.connect(self._delete_message)
        self.delete_btn.setEnabled(False)
        self.delete_btn.setObjectName("danger")
        actions_layout.addWidget(self.delete_btn)

        actions_layout.addStretch()
        self.detail_tabs.addTab(actions_widget, "Actions")

        detail_layout.addWidget(self.detail_tabs)
        splitter.addWidget(detail_widget)

        splitter.setSizes([400, 200])
        layout.addWidget(splitter, 1)

        # Status bar
        status_bar = QHBoxLayout()
        self.status_label = QLabel("Enter a recipient email or sender domain to search")
        self.status_label.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY}; font-size: 9px;")
        status_bar.addWidget(self.status_label)
        status_bar.addStretch()

        self.count_label = QLabel("")
        self.count_label.setStyleSheet(f"color: {EdgeColors.TEXT_SECONDARY}; font-size: 9px;")
        status_bar.addWidget(self.count_label)

        layout.addLayout(status_bar)

    def _do_search(self):
        """Execute search"""
        query = self.search_input.text().strip()
        if not query:
            QMessageBox.warning(self, "Search", "Please enter a search query")
            return

        search_type = self.search_type.currentData()
        start = datetime.combine(self.start_date.date().toPyDate(), datetime.min.time())
        end = datetime.combine(self.end_date.date().toPyDate(), datetime.max.time())

        # Get clients from main window
        abnormal_client = getattr(self.main_window, 'abnormal_client', None)
        exchange_client = getattr(self.main_window, 'exchange_client', None)

        if not abnormal_client and not exchange_client:
            QMessageBox.warning(
                self, "Search",
                "No API clients configured. Please check settings."
            )
            return

        # Start search
        self.search_btn.setEnabled(False)
        self.progress_label.show()
        self.results_table.setRowCount(0)

        self.worker = MailFlowWorker(
            search_type, query, start, end,
            abnormal_client, exchange_client
        )
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_search_finished)
        self.worker.error.connect(self._on_search_error)
        self.worker.start()

    def _on_progress(self, message: str):
        """Update progress"""
        self.progress_label.setText(message)

    def _on_search_finished(self, events: List[UnifiedMailEvent]):
        """Handle search results"""
        self.search_btn.setEnabled(True)
        self.progress_label.hide()
        self.events = events

        self._populate_table()

        self.status_label.setText(f"Search complete")
        self.count_label.setText(f"{len(events)} messages found")

    def _on_search_error(self, error: str):
        """Handle search error"""
        self.search_btn.setEnabled(True)
        self.progress_label.hide()
        self.status_label.setText(f"Error: {error}")
        QMessageBox.critical(self, "Search Error", error)

    def _populate_table(self):
        """Populate results table"""
        self.results_table.setRowCount(len(self.events))

        for row, event in enumerate(self.events):
            # Received
            received_item = QTableWidgetItem(event.received.strftime("%Y-%m-%d %H:%M"))
            self.results_table.setItem(row, 0, received_item)

            # Status
            status_item = QTableWidgetItem(event.status.value)
            status_item.setForeground(QColor(event.status_color()))
            self.results_table.setItem(row, 1, status_item)

            # Source
            source_item = QTableWidgetItem(event.source)
            if event.source == "Both":
                source_item.setForeground(QColor(EdgeColors.ACCENT))
            self.results_table.setItem(row, 2, source_item)

            # From
            from_item = QTableWidgetItem(event.sender)
            self.results_table.setItem(row, 3, from_item)

            # To
            to_item = QTableWidgetItem(event.recipient)
            self.results_table.setItem(row, 4, to_item)

            # Subject
            subject_item = QTableWidgetItem(event.subject)
            self.results_table.setItem(row, 5, subject_item)

            # Type (threat type or quarantine type)
            type_str = event.threat_type or event.quarantine_type or ""
            type_item = QTableWidgetItem(type_str)
            self.results_table.setItem(row, 6, type_item)

        self.results_table.resizeColumnsToContents()
        self.results_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)

    def _on_selection_changed(self):
        """Handle selection change"""
        rows = self.results_table.selectionModel().selectedRows()
        if not rows:
            self.summary_text.clear()
            self.path_tree.clear()
            self.release_btn.setEnabled(False)
            self.delete_btn.setEnabled(False)
            return

        row = rows[0].row()
        if row >= len(self.events):
            return

        event = self.events[row]
        self._show_event_details(event)

    def _show_event_details(self, event: UnifiedMailEvent):
        """Show event details"""
        # Summary
        summary = f"""MESSAGE DETAILS
{'=' * 50}

Message ID: {event.message_id}
From:       {event.sender}
To:         {event.recipient}
Subject:    {event.subject}
Received:   {event.received.strftime('%Y-%m-%d %H:%M:%S')}

STATUS
{'=' * 50}
Status:     {event.status.value}
Source:     {event.source}
"""
        if event.threat_type:
            summary += f"Threat:     {event.threat_type}\n"
        if event.quarantine_type:
            summary += f"Quarantine: {event.quarantine_type}\n"
        if event.policy_name:
            summary += f"Policy:     {event.policy_name}\n"
        if event.from_ip:
            summary += f"From IP:    {event.from_ip}\n"

        # Add source-specific details
        if 'threat' in event.details:
            threat = event.details['threat']
            summary += f"""
ABNORMAL SECURITY
{'=' * 50}
Threat ID:  {threat.get('threat_id', 'N/A')}
Attack:     {threat.get('attack_type', 'N/A')}
Severity:   {threat.get('severity', 'N/A')}
Status:     {threat.get('remediation_status', 'N/A')}
"""

        if 'trace' in event.details:
            trace = event.details['trace']
            summary += f"""
EXCHANGE MESSAGE TRACE
{'=' * 50}
Trace ID:   {trace.get('message_trace_id', 'N/A')}
Status:     {trace.get('status', 'N/A')}
Size:       {trace.get('size', 0)} bytes
"""

        if 'quarantine' in event.details:
            quar = event.details['quarantine']
            summary += f"""
EXCHANGE QUARANTINE
{'=' * 50}
Identity:   {quar.get('identity', 'N/A')}
Type:       {quar.get('quarantine_type', 'N/A')}
Policy:     {quar.get('policy_name', 'N/A')}
Release:    {quar.get('release_status', 'N/A')}
Expires:    {quar.get('expires', 'N/A')}
"""

        self.summary_text.setText(summary)

        # Delivery path
        self.path_tree.clear()

        # Build path from available data
        path_events = []

        # Add received event
        path_events.append(("Received", event.received, f"From: {event.sender}"))

        if 'trace' in event.details:
            trace = event.details['trace']
            for te in trace.get('events', []):
                path_events.append((te['event'], te['date'], te['detail']))

        if 'threat' in event.details:
            threat = event.details['threat']
            path_events.append((
                f"Abnormal: {threat.get('attack_type', 'Detected')}",
                event.received,
                f"Severity: {threat.get('severity', 'Unknown')}"
            ))
            if threat.get('remediation_status'):
                path_events.append((
                    threat.get('remediation_status', 'Remediated'),
                    event.received,
                    "Message remediated by Abnormal Security"
                ))

        if 'quarantine' in event.details:
            quar = event.details['quarantine']
            path_events.append((
                f"Quarantined: {quar.get('quarantine_type', 'Unknown')}",
                event.received,
                f"Policy: {quar.get('policy_name', 'N/A')}"
            ))

        # Add final status
        path_events.append((f"Final: {event.status.value}", event.received, ""))

        for evt_name, evt_time, evt_detail in path_events:
            time_str = evt_time.strftime('%H:%M:%S') if isinstance(evt_time, datetime) else str(evt_time)
            item = QTreeWidgetItem([evt_name, time_str, evt_detail])
            self.path_tree.addTopLevelItem(item)

        self.path_tree.expandAll()

        # Enable/disable actions
        is_quarantined = event.status in [
            UnifiedStatus.QUARANTINED_EOP,
            UnifiedStatus.QUARANTINED_ABNORMAL
        ]
        has_identity = 'quarantine' in event.details and event.details['quarantine'].get('identity')

        self.release_btn.setEnabled(is_quarantined and has_identity)
        self.delete_btn.setEnabled(is_quarantined and has_identity)

    def _release_message(self):
        """Release message from quarantine"""
        rows = self.results_table.selectionModel().selectedRows()
        if not rows:
            return

        row = rows[0].row()
        event = self.events[row]

        if 'quarantine' not in event.details:
            QMessageBox.warning(self, "Release", "No quarantine data available")
            return

        identity = event.details['quarantine'].get('identity')
        if not identity:
            QMessageBox.warning(self, "Release", "No quarantine identity")
            return

        reply = QMessageBox.question(
            self, "Release Message",
            f"Release this message from quarantine?\n\nSubject: {event.subject}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            exchange_client = getattr(self.main_window, 'exchange_client', None)
            if exchange_client:
                success, msg = exchange_client.release_quarantine_message(identity)
                if success:
                    QMessageBox.information(self, "Released", "Message released successfully")
                    self._do_search()  # Refresh
                else:
                    QMessageBox.critical(self, "Error", f"Failed to release: {msg}")

    def _delete_message(self):
        """Delete message from quarantine"""
        rows = self.results_table.selectionModel().selectedRows()
        if not rows:
            return

        row = rows[0].row()
        event = self.events[row]

        if 'quarantine' not in event.details:
            return

        identity = event.details['quarantine'].get('identity')
        if not identity:
            return

        reply = QMessageBox.warning(
            self, "Delete Message",
            f"Permanently delete this message?\n\nSubject: {event.subject}\n\nThis cannot be undone!",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            exchange_client = getattr(self.main_window, 'exchange_client', None)
            if exchange_client:
                success, msg = exchange_client.delete_quarantine_message(identity)
                if success:
                    QMessageBox.information(self, "Deleted", "Message deleted")
                    self._do_search()  # Refresh
                else:
                    QMessageBox.critical(self, "Error", f"Failed to delete: {msg}")

    def set_clients(self, abnormal_client, exchange_client):
        """Set API clients"""
        pass  # Clients are accessed via main_window
