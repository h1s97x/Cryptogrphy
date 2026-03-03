# Updated imports to use new structure
try:
    from ui.widgets.AES_CBC_MAC_ui import AES_CBC_MACWidget
except ImportError:
    AES_CBC_MACWidget = None
try:
    from ui.widgets.SHA256_ui import SHA256Widget
except ImportError:
    SHA256Widget = None
try:
    from ui.widgets.SM3_ui import SM3Widget
except ImportError:
    SM3Widget = None
try:
    from ui.widgets.SHA1_ui import SHA1Widget
except ImportError:
    SHA1Widget = None
try:
    from ui.widgets.SHA3_ui import SHA3Widget
except ImportError:
    SHA3Widget = None
try:
    from ui.widgets.MD5_ui import MD5Widget
except ImportError:
    MD5Widget = None
try:
    from ui.widgets.HMAC_MD5_ui import MD5_HMACWidget
except ImportError:
    MD5_HMACWidget = None
try:
    from ui.widgets.Password_System_ui import PSWidget
except ImportError:
    PSWidget = None
try:
    from ui.widgets.Hash_Reverse_ui import HashReverseWidget
except ImportError:
    HashReverseWidget = None