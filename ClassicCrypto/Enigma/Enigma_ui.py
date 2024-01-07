from PyQt5.QtWidgets import QApplication

from ClassicCrypto.Enigma import Enigma
from Modules import Button, PlainTextEdit, Group, ErrorType
from Modules import CryptographyWidget


class EnigmaWidget(CryptographyWidget):
    def __init__(self):
        CryptographyWidget.__init__(self)
        self.menuBar().setHidden(True)
        self.setWindowTitle("Enigma")
        self.widgets_dict = {}
        self.groups_config = [
            Group(name="Key",
                     plain_text_edits=[
                         PlainTextEdit(id="Ring_Setting", label="Ring Setting (Str)",
                             default_text="EPEL"),
                         PlainTextEdit(id="Start_Position", label="Start Position (Str)",
                             default_text="CDSZ"),
                         PlainTextEdit(id="Plugs", label="Plugs (Str)",
                             default_text="AE BF CM DQ HU JN LX PR SZ VW")],
                  buttons=[]),
            Group(name="Encrypt",
                  plain_text_edits=[PlainTextEdit(id="Plaintext", label="Plaintext (Str)",
                                                  default_text="ENIGMA"),
                                    PlainTextEdit(id="_Ciphertext", label="Ciphertext (Str)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerEncrypt", name="Encrypt (PC)", clicked_function=self.computer_encrypt),
                      Button(id="CleanEncrypt", name="Clean", clicked_function=self.encrypt_clean)
                  ]),
            Group(name="Decrypt",
                  plain_text_edits=[PlainTextEdit(id="Ciphertext", label="Ciphertext (Str)", default_text="PFSJIJ"),
                                    PlainTextEdit(id="_Plaintext", label="Plaintext (Str)",
                                                  default_text="", read_only=True)],
                  buttons=[
                      Button(id="ComputerDecrypt", name="Decrypt (PC)", clicked_function=self.computer_decrypt),
                      Button(id="CleanDecrypt", name="Clean", clicked_function=self.decrypt_clean)
                  ])
        ]
        self.render()
        self.logging.log("Enigma algorithm has been imported.\n")

    def func_encrypt(self, str_data):
        self.logging.log("Ciphertext:     " + str_data)
        self.widgets_dict["_Ciphertext"].set_text(str_data)
        self.logging.log("\n")

    def func_decrypt(self, str_data):
        self.logging.log("Plaintext:      " + str_data)
        self.widgets_dict["_Plaintext"].set_text(str_data)
        self.logging.log("\n")

    # encrypt on computer
    def computer_encrypt(self):
        try:
            # print the login information to main logging.log widget
            self.logging.log("Encrypt on your computer.")
            self.encrypt_clean()
            ring_setting = self.widgets_dict["Ring_Setting"].get_text()
            start_position = self.widgets_dict["Start_Position"].get_text()
            plugs = self.widgets_dict["Plugs"].get_text()
            plaintext = self.widgets_dict["Plaintext"].get_text()

            ring_setting = ring_setting.replace(' ', '')
            start_position = start_position.replace(' ', '')
            plugs = plugs.replace(' ', '')
            plaintext = plaintext.replace(' ', '')
            if len(plugs) != len(set(plugs)):
                self.logging.log(ErrorType.NotMeetRequirementError.value + "There are duplicate elements\n")
                self.pop_message_box(ErrorType.NotMeetRequirementError.value+ "There are duplicate elements")
                return
            if len(ring_setting) != 4:
                self.logging.log(ErrorType.LengthError.value + "Ring setting length must be 4 bytes.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Ring setting length must be 4 bytes.")
                return
            if len(start_position) != 4:
                self.logging.log(ErrorType.LengthError.value + "Start position length must be 4 bytes.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Start position length must be 4 bytes.")
                return
            if len(plugs) % 2 != 0:
                self.logging.log(ErrorType.LengthError.value + "Plugs length must be even.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Plugs length must be even.")
                return
            for i in range(len(ring_setting)):
                if not ring_setting[i].isupper():
                    self.logging.log(ErrorType.CharacterError.value + " You should check the \"Ring Setting\" input box.\n")
                    self.pop_message_box(ErrorType.CharacterError.value + " You should check the \"Ring Setting\" input box.")
                    return
            for i in range(len(start_position)):
                if not start_position[i].isupper():
                    self.logging.log(ErrorType.CharacterError.value + " You should check the \"Start position\" input box.\n")
                    self.pop_message_box(ErrorType.CharacterError.value + " You should check the \"Start position\" input box.")
                    return
            for i in range(len(plugs)):
                if not plugs[i].isupper():
                    self.logging.log(ErrorType.CharacterError.value + " You should check the \"Plugs\" input box.\n")
                    self.pop_message_box(ErrorType.CharacterError.value + " You should check the \"Plugs\" input box.")
                    return
            for i in range(len(plaintext)):
                if not plaintext[i].isupper():
                    self.logging.log(ErrorType.CharacterError.value + " You should check the \"Plaintext\" input box.\n")
                    self.pop_message_box(ErrorType.CharacterError.value + " You should check the \"Plaintext\" input box.")
                    return
            # 明文不能为空
            if plaintext == '':
                self.logging.log(ErrorType.NotMeetRequirementError.value + " You should check the \"Plaintext\" input box.\n")
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + " You should check the \"Plaintext\" input box.")
                return

            plugs_temp = []
            for i in range(0, len(plugs)):
                if i % 2 == 1:
                    plugs_temp.append(str(plugs[i - 1]) + str(plugs[i]))
            self.logging.log("Plaintext:      " + plaintext)
            self.logging.log("Ring Setting:   " + ring_setting)
            self.logging.log("Start position: " + start_position)
            plugs_str = ''
            for i in range(0, len(plugs_temp)):
                plugs_str = plugs_str + plugs_temp[i] + " "
            self.logging.log("Plugs:          " + plugs_str)

            # initial Vigenere thread
            thread = Enigma.Thread(self, ring_setting, start_position, plugs_temp, plaintext, 0)
            thread.final_result.connect(self.func_encrypt)
            thread.final_result.connect(self.widgets_dict["Ciphertext"].set_text)
            # start Vigenere thread
            thread.start()
        except Exception as e:
            self.logging.log_error(e)

    # decrypt on computer
    def computer_decrypt(self):
        try:
            self.logging.log("Decrypt on your computer.")
            self.decrypt_clean()
            ring_setting = self.widgets_dict["Ring_Setting"].get_text()
            start_position = self.widgets_dict["Start_Position"].get_text()
            plugs = self.widgets_dict["Plugs"].get_text()
            ciphertext = self.widgets_dict["Ciphertext"].get_text()

            ring_setting = ring_setting.replace(' ', '')
            start_position = start_position.replace(' ', '')
            plugs = plugs.replace(' ', '')
            ciphertext = ciphertext.replace(' ', '')
            if len(ring_setting) != 4:
                self.logging.log(ErrorType.LengthError.value + "Ring setting length must be 4 bytes.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Ring setting length must be 4 bytes.")
                return
            if len(start_position) != 4:
                self.logging.log(ErrorType.LengthError.value + "Start position length must be 4 bytes.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Start position length must be 4 bytes.")
                return
            if len(plugs) % 2 != 0:
                self.logging.log(ErrorType.LengthError.value + "Plugs length must be even.\n")
                self.pop_message_box(ErrorType.LengthError.value + "Plugs length must be even.")
                return
            for i in range(len(ring_setting)):
                if not ring_setting[i].isupper():
                    self.logging.log(ErrorType.CharacterError.value + "You should check the \"Ring Setting\" input box.\n")
                    self.pop_message_box(ErrorType.CharacterError.value + "You should check the \"Ring Setting\" input box.")
                    return
            for i in range(len(start_position)):
                if not start_position[i].isupper():
                    self.logging.log(ErrorType.CharacterError.value + "You should check the \"Start position\" input box.\n")
                    self.pop_message_box(ErrorType.CharacterError.value + "You should check the \"Start position\" input box.")
                    return
            for i in range(len(plugs)):
                if not plugs[i].isupper():
                    self.logging.log(ErrorType.CharacterError.value + "You should check the \"Plugs\" input box.\n")
                    self.pop_message_box(ErrorType.CharacterError.value + "You should check the \"Plugs\" input box.")
                    return
            for i in range(len(ciphertext)):
                if not ciphertext[i].isupper():
                    self.logging.log(ErrorType.CharacterError.value + "You should check the \"Ciphertext\" input box.\n")
                    self.pop_message_box(ErrorType.CharacterError.value + "You should check the \"Ciphertext\" input box.")
                    return
            # 密文不能为空
            if ciphertext == '':
                self.logging.log(ErrorType.NotMeetRequirementError.value + "You should check the \"Ciphertext\" input box.\n")
                self.pop_message_box(ErrorType.NotMeetRequirementError.value + "You should check the \"Ciphertext\" input box.")
                return

            plugs_temp = []
            for i in range(len(plugs)):
                if i % 2 == 1:
                    plugs_temp.append(str(plugs[i - 1]) + str(plugs[i]))
            self.logging.log("Ciphertext:     " + ciphertext)
            self.logging.log("Ring Setting:   " + ring_setting)
            self.logging.log("Start position: " + start_position)
            plugs_str = ''
            for i in range(len(plugs_temp)):
                plugs_str = plugs_str + plugs_temp[i] + " "
            self.logging.log("Plugs:          " + plugs_str)

            thread = Enigma.Thread(self, ring_setting, start_position, plugs_temp, ciphertext, 1)
            thread.final_result.connect(self.func_decrypt)
            thread.start()
        except Exception as e:
            self.logging.log_error(e)

    # clean widget text
    def encrypt_clean(self):
        self.widgets_dict["_Ciphertext"].set_text("")

    # clean widget text
    def decrypt_clean(self):
        self.widgets_dict["_Plaintext"].set_text("")

if __name__ == '__main__':
    app = QApplication([])
    window = EnigmaWidget()
    app.exec_()