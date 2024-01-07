import logging
import csv
from PyQt5 import QtCore
from Util import TypeConvert, Path


class Thread(QtCore.QThread):
    intermediate_value = QtCore.pyqtSignal(str)
    final_result = QtCore.pyqtSignal(str)

    def __init__(self, parent, hash_result: str, hash_mode: str):
        super(Thread, self).__init__(parent)
        self.hash_result = hash_result
        self.hash_mode = hash_mode

    def hash_reverse_run(self):
        logging.info("HashReverse Begin")
        self.print_intermediate_value("Hash ")
        self.print_intermediate_value("Hash: " + self.hash_result)
        hash_str = self.hash_result.replace(" ", "")
        result = self.hash_reverse(hash_str)
        self.print_intermediate_value("Message: \n" + result)
        self.print_intermediate_value("Hash Reverse completed.\n")
        self.print_final_result(result)

    def print_intermediate_value(self, text):
        self.intermediate_value.emit(text)

    def print_final_result(self, text):
        self.final_result.emit(text)

    def run(self):
        self.hash_reverse_run()

    def hash_reverse(self, hash_str, hash_table_path=None):  # hash_table_path为了测试特设
        if hash_table_path is None:
            hash_table_path = Path.MENU_DIRECTORY + "table/"
        csv_table = open(hash_table_path + self.hash_mode + ".csv", 'r', encoding="utf-8")
        data = csv.DictReader(csv_table)
        for row in data:
            if row[self.hash_mode] == hash_str:
                return row['Message']
        return "Null"
