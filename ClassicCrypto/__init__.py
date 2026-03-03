# Updated imports to use new structure
try:
    from ui.widgets.Hill_ui import HillWidget
except ImportError:
    HillWidget = None
try:
    from ui.widgets.Caesar_ui import CaesarWidget
except ImportError:
    CaesarWidget = None
try:
    from ui.widgets.Enigma_ui import EnigmaWidget
except ImportError:
    EnigmaWidget = None
try:
    from ui.widgets.Frequency_Analysis_ui import FAWidget
except ImportError:
    FAWidget = None
try:
    from ui.widgets.Monoalphabetic_Cipher_ui import MonoalphabeticWidget
except ImportError:
    MonoalphabeticWidget = None
try:
    from ui.widgets.Playfair_ui import PlayfairWidget
except ImportError:
    PlayfairWidget = None
try:
    from ui.widgets.Vigenere_ui import VigenereWidget
except ImportError:
    VigenereWidget = None
