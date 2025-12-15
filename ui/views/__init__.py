"""
UI Views
"""

from .dashboard import DashboardView
from .threats import ThreatsView
from .cases import CasesView
from .diagnostics import DiagnosticsView
from .analysis import AnalysisView
from .mailflow import MailFlowView

__all__ = [
    'DashboardView',
    'ThreatsView',
    'CasesView',
    'DiagnosticsView',
    'AnalysisView',
    'MailFlowView'
]
