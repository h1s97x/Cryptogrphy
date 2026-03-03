# Updated imports to use new structure
try:
    from ui.widgets.RSA_ui import RSAWidget
except ImportError:
    RSAWidget = None
try:
    from ui.widgets.RSA_Sign_ui import RSASignWidget
except ImportError:
    RSASignWidget = None
try:
    from ui.widgets.SM2_ui import SM2Widget
except ImportError:
    SM2Widget = None
try:
    from ui.widgets.SM2_Sign_ui import SM2SignWidget
except ImportError:
    SM2SignWidget = None
try:
    from ui.widgets.ECDSA_ui import ECDSAWidget
except ImportError:
    ECDSAWidget = None
try:
    from ui.widgets.ElGamal_ui import ElGamalWidget
except ImportError:
    ElGamalWidget = None
try:
    from ui.widgets.ECC_ui import ECCWidget
except ImportError:
    ECCWidget = None