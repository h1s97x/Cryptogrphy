from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QTextEdit

class Logging:
    def __init__(self, log_widget):
        self.log_widget = log_widget

    def log(self, message):
        self.log_widget.append_log_message(message)

class LoggingWidget(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle("Logging Widget")
        self.setGeometry(300, 300, 500, 400)

        self.log_text_edit = QTextEdit(self)
        self.log_text_edit.setReadOnly(True)  # 设置为只读模式
        self.log_text_edit.setPlaceholderText("Log messages will be displayed here.")

        layout = QVBoxLayout(self)
        layout.addWidget(self.log_text_edit)

    def append_log_message(self, message):
        self.log_text_edit.append(message)

if __name__ == '__main__':
    app = QApplication([])

    logging_widget = LoggingWidget()
    logging = Logging(logging_widget)

    logging.log("This is a log message.")

    logging_widget.show()
    app.exec_()