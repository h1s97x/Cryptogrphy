# Updated imports to use new structure
try:
    from ui.widgets.Crypto_1_ui import Crypto1Widget
except ImportError:
    Crypto1Widget = None
try:
    from ui.widgets.SEAL_ui import SEALWidget
except ImportError:
    SEALWidget = None
try:
    from ui.widgets.ZUC_ui import ZUCWidget
except ImportError:
    ZUCWidget = None
try:
    from ui.widgets.RC4_ui import RC4Widget
except ImportError:
    RC4Widget = None