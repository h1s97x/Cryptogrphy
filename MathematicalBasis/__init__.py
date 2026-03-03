# Updated imports to use new structure
try:
    from ui.widgets.CRT_ui import CRTWidget
except ImportError:
    CRTWidget = None
try:
    from ui.widgets.Euler_ui import EulerWidget
except ImportError:
    EulerWidget = None
try:
    from ui.widgets.Euclidean_ui import EuclideanWidget
except ImportError:
    EuclideanWidget = None