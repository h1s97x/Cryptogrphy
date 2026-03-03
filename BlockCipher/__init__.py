# Updated imports to use new structure
try:
    from ui.widgets.AES_ui import AESWidget
except ImportError:
    AESWidget = None
try:
    from ui.widgets.DES_ui import DESWidget
except ImportError:
    DESWidget = None
try:
    from ui.widgets.Block_Mode_ui import BlockModeWidget
except ImportError:
    BlockModeWidget = None
try:
    from ui.widgets.SIMON_ui import SIMONWidget
except ImportError:
    SIMONWidget = None
try:
    from ui.widgets.SM4_ui import SM4Widget
except ImportError:
    SM4Widget = None
try:
    from ui.widgets.SPECK_ui import SPECKWidget
except ImportError:
    SPECKWidget = None