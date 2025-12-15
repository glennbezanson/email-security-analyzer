"""
Edge Solutions UI Styles and Branding
"""


class EdgeColors:
    """Edge Solutions brand color palette"""
    # Primary
    PRIMARY = "#486D87"      # Edge Blue - headers, nav, primary buttons
    ACCENT = "#C6D219"       # Edge Green - success, CTAs, highlights

    # Secondary
    DARK = "#4C5351"         # Dark Teal - text, dark backgrounds
    MUTED = "#7B7D72"        # Olive Gray - secondary text, borders
    LIGHT = "#F2F3F4"        # Cool Gray - backgrounds, cards
    MOSS = "#9DA03C"         # Moss Green - hover states

    # Semantic
    SUCCESS = "#C6D219"      # Edge Green
    INFO = "#486D87"         # Edge Blue
    WARNING = "#E6A817"      # Amber
    ERROR = "#C44536"        # Red

    # Text
    TEXT_PRIMARY = "#4C5351"
    TEXT_SECONDARY = "#7B7D72"
    TEXT_INVERSE = "#FFFFFF"


# Font family with fallbacks
FONT_FAMILY = "Brandon, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"

# Type Scale
FONT_SIZES = {
    'display': 46,  # H1, page titles
    'h2': 28,       # Section headings
    'h3': 18,       # Subsection titles
    'body': 14,     # General content
    'small': 12,    # Captions, metadata
    'tiny': 10,     # Labels, badges
}


# Main application stylesheet
EDGE_STYLESHEET = """
/* Global */
QWidget {
    font-family: 'Brandon', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    font-size: 10px;
    color: #4C5351;
}

QMainWindow {
    background-color: #F2F3F4;
}

/* Headers */
QLabel#pageTitle {
    font-size: 26px;
    font-weight: bold;
    color: #4C5351;
}

QLabel#sectionTitle {
    font-size: 16px;
    font-weight: 600;
    color: #4C5351;
}

/* Navigation / Tabs */
QTabWidget::pane {
    border: none;
    background-color: #FFFFFF;
    border-radius: 8px;
}

QTabBar::tab {
    background-color: transparent;
    color: #7B7D72;
    padding: 12px 24px;
    border: none;
    font-weight: 500;
}

QTabBar::tab:selected {
    color: #486D87;
    border-bottom: 3px solid #486D87;
}

QTabBar::tab:hover:!selected {
    color: #4C5351;
}

/* Buttons */
QPushButton {
    background-color: #486D87;
    color: #FFFFFF;
    border: none;
    border-radius: 4px;
    padding: 8px 16px;
    font-weight: 500;
    min-width: 80px;
}

QPushButton:hover {
    background-color: #3d5c73;
}

QPushButton:pressed {
    background-color: #324d61;
}

QPushButton:disabled {
    background-color: #486D87;
    opacity: 0.5;
}

QPushButton#secondary {
    background-color: transparent;
    color: #486D87;
    border: 2px solid #486D87;
}

QPushButton#secondary:hover {
    background-color: rgba(72, 109, 135, 0.1);
}

QPushButton#accent {
    background-color: #C6D219;
    color: #4C5351;
}

QPushButton#accent:hover {
    background-color: #9DA03C;
}

QPushButton#danger {
    background-color: #C44536;
    color: #FFFFFF;
}

QPushButton#danger:hover {
    background-color: #a33a2d;
}

/* Cards */
QFrame#card {
    background-color: #FFFFFF;
    border-radius: 8px;
    border: none;
}

QFrame#cardAccent {
    background-color: #FFFFFF;
    border-radius: 8px;
    border-left: 4px solid #C6D219;
}

QFrame#cardFeatured {
    background-color: #486D87;
    border-radius: 8px;
    color: #FFFFFF;
}

QFrame#cardWarning {
    background-color: #FFFFFF;
    border-radius: 8px;
    border-left: 4px solid #E6A817;
}

QFrame#cardError {
    background-color: #FFFFFF;
    border-radius: 8px;
    border-left: 4px solid #C44536;
}

/* Input Fields */
QLineEdit, QTextEdit, QComboBox, QSpinBox {
    border: 1px solid #7B7D72;
    border-radius: 4px;
    padding: 8px 16px;
    background-color: #FFFFFF;
    color: #4C5351;
}

QLineEdit:focus, QTextEdit:focus, QComboBox:focus, QSpinBox:focus {
    border-color: #486D87;
    border-width: 2px;
}

QLineEdit:disabled, QTextEdit:disabled, QComboBox:disabled {
    background-color: #F2F3F4;
    color: #7B7D72;
}

QComboBox::drop-down {
    border: none;
    padding-right: 8px;
}

QComboBox QAbstractItemView {
    border: 1px solid #7B7D72;
    border-radius: 4px;
    background-color: #FFFFFF;
    selection-background-color: rgba(72, 109, 135, 0.1);
}

/* Tables */
QTableWidget {
    background-color: #FFFFFF;
    border: none;
    border-radius: 8px;
    gridline-color: #F2F3F4;
}

QTableWidget::item {
    padding: 12px;
}

QTableWidget::item:selected {
    background-color: rgba(72, 109, 135, 0.1);
    color: #4C5351;
}

QHeaderView::section {
    background-color: #F2F3F4;
    color: #4C5351;
    font-weight: 600;
    padding: 12px;
    border: none;
}

/* Tree Views */
QTreeWidget {
    background-color: #FFFFFF;
    border: none;
    border-radius: 8px;
}

QTreeWidget::item {
    padding: 8px;
}

QTreeWidget::item:selected {
    background-color: rgba(72, 109, 135, 0.1);
    color: #4C5351;
}

/* Scrollbars */
QScrollBar:vertical {
    background-color: #F2F3F4;
    width: 8px;
    border-radius: 4px;
}

QScrollBar::handle:vertical {
    background-color: #7B7D72;
    border-radius: 4px;
    min-height: 40px;
}

QScrollBar::handle:vertical:hover {
    background-color: #4C5351;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background-color: #F2F3F4;
    height: 8px;
    border-radius: 4px;
}

QScrollBar::handle:horizontal {
    background-color: #7B7D72;
    border-radius: 4px;
    min-width: 40px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #4C5351;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

/* Status Badges */
QLabel#badgeSuccess {
    background-color: #C6D219;
    color: #4C5351;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 10px;
    font-weight: 500;
}

QLabel#badgeError {
    background-color: #C44536;
    color: #FFFFFF;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 10px;
    font-weight: 500;
}

QLabel#badgeWarning {
    background-color: #E6A817;
    color: #FFFFFF;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 10px;
    font-weight: 500;
}

QLabel#badgeInfo {
    background-color: #486D87;
    color: #FFFFFF;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 10px;
    font-weight: 500;
}

/* Progress Bar */
QProgressBar {
    background-color: #F2F3F4;
    border-radius: 4px;
    height: 8px;
    text-align: center;
}

QProgressBar::chunk {
    background-color: #486D87;
    border-radius: 4px;
}

/* Tooltips */
QToolTip {
    background-color: #4C5351;
    color: #FFFFFF;
    border: none;
    padding: 8px 12px;
    border-radius: 4px;
}

/* Splitter */
QSplitter::handle {
    background-color: #F2F3F4;
}

QSplitter::handle:horizontal {
    width: 4px;
}

QSplitter::handle:vertical {
    height: 4px;
}

/* Menu */
QMenuBar {
    background-color: #486D87;
    color: #FFFFFF;
    padding: 4px;
}

QMenuBar::item {
    padding: 6px 12px;
    border-radius: 4px;
}

QMenuBar::item:selected {
    background-color: #3d5c73;
}

QMenu {
    background-color: #FFFFFF;
    border: 1px solid #F2F3F4;
    border-radius: 4px;
    padding: 4px;
}

QMenu::item {
    padding: 8px 24px;
    border-radius: 4px;
}

QMenu::item:selected {
    background-color: rgba(72, 109, 135, 0.1);
}

QMenu::separator {
    height: 1px;
    background-color: #F2F3F4;
    margin: 4px 8px;
}

/* Status Bar */
QStatusBar {
    background-color: #F2F3F4;
    border-top: 1px solid #7B7D72;
    padding: 4px;
}

/* Tool Bar */
QToolBar {
    background-color: #F2F3F4;
    border-bottom: 1px solid #7B7D72;
    padding: 8px;
    spacing: 8px;
}

QToolBar::separator {
    width: 1px;
    background-color: #7B7D72;
    margin: 4px 8px;
}

QToolButton {
    background-color: transparent;
    border: none;
    padding: 8px 16px;
    border-radius: 4px;
    color: #4C5351;
}

QToolButton:hover {
    background-color: rgba(72, 109, 135, 0.1);
}

QToolButton:pressed {
    background-color: rgba(72, 109, 135, 0.2);
}

/* Group Box */
QGroupBox {
    font-weight: 600;
    border: 1px solid #7B7D72;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 16px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    padding: 0 8px;
    background-color: #F2F3F4;
}

/* Check Box */
QCheckBox {
    spacing: 8px;
}

QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border: 2px solid #7B7D72;
    border-radius: 4px;
}

QCheckBox::indicator:checked {
    background-color: #486D87;
    border-color: #486D87;
}

QCheckBox::indicator:hover {
    border-color: #486D87;
}

/* Radio Button */
QRadioButton {
    spacing: 8px;
}

QRadioButton::indicator {
    width: 18px;
    height: 18px;
    border: 2px solid #7B7D72;
    border-radius: 9px;
}

QRadioButton::indicator:checked {
    background-color: #486D87;
    border-color: #486D87;
}

QRadioButton::indicator:hover {
    border-color: #486D87;
}

/* Dialog */
QDialog {
    background-color: #F2F3F4;
}

QDialogButtonBox {
    button-layout: 0;
}
"""


def get_severity_color(severity: str) -> str:
    """Get color for severity level"""
    severity_colors = {
        'CRITICAL': EdgeColors.ERROR,
        'HIGH': EdgeColors.WARNING,
        'MEDIUM': EdgeColors.INFO,
        'LOW': EdgeColors.MUTED,
        'INFO': EdgeColors.TEXT_SECONDARY
    }
    return severity_colors.get(severity.upper(), EdgeColors.TEXT_SECONDARY)


def get_status_color(status: str) -> str:
    """Get color for status"""
    status_colors = {
        'Remediated': EdgeColors.SUCCESS,
        'Auto-Remediated': EdgeColors.SUCCESS,
        'Not Remediated': EdgeColors.ERROR,
        'Pending': EdgeColors.WARNING,
        'Open': EdgeColors.WARNING,
        'Closed': EdgeColors.SUCCESS
    }
    return status_colors.get(status, EdgeColors.TEXT_SECONDARY)


def create_badge_style(color: str, text_color: str = None) -> str:
    """Create inline style for a badge"""
    if text_color is None:
        text_color = EdgeColors.TEXT_INVERSE if color != EdgeColors.ACCENT else EdgeColors.TEXT_PRIMARY

    return f"""
        background-color: {color};
        color: {text_color};
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 10px;
        font-weight: 500;
    """
