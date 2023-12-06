#  导入模块
import sys
from PyQt5.QtWidgets import *
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont

class CryptographyWidget(QWidget):
    def __init__(self):
        123


# 创建父页面类
class Parents_Widget(QWidget):
    def __init__(self):
        super(Parents_Widget, self).__init__()
        # 页面基础设置
        # 设置窗口标题
        self.setWindowTitle('父页面')
        # 设置页面尺寸
        self.resize(500, 200)
        # 创建Label控件
        # 页面标题label
        self.label_0 = QLabel('页面间信号传递实例')
        # 设置label控件居中
        self.label_0.setAlignment(Qt.AlignCenter)
        # 设置字体样式
        self.label_0.setFont(QFont('宋体', 12, QFont.Bold))
        self.label_1 = QLabel('子页面状态：')
        # 创建单行文本输入框
        self.line_1 = QLineEdit()
        # 创建按钮
        self.create_button = QPushButton('创建子页面')
        self.close_button = QPushButton('关闭子页面')
        # 按钮初始方法
        self.button_init()
        # 创建布局管理器
        self.h1_layout = QHBoxLayout()  # 水平布局管理器
        self.h2_layout = QHBoxLayout()
        self.v_layout = QVBoxLayout()  # 垂直布局管理器
        # 页面初始化
        self.layout_init()

    # 页面布局方法
    def layout_init(self):
        # 水平布局管理器1
        self.h1_layout.addWidget(self.label_1)
        self.h1_layout.addWidget(self.line_1)
        # 水平布局管理器2
        self.h2_layout.addWidget(self.create_button)
        self.h2_layout.addWidget(self.close_button)
        # 垂直布局管理器
        self.v_layout.addStretch(1)
        self.v_layout.addWidget(self.label_0)
        self.v_layout.addSpacing(10)
        self.v_layout.addLayout(self.h1_layout)
        self.v_layout.addSpacing(10)
        self.v_layout.addLayout(self.h2_layout)
        self.v_layout.addStretch(1)
        # 设置最终布局
        self.setLayout(self.v_layout)

    # 按钮初始化方法
    def button_init(self):
        # 创建子页面按钮点击信号绑定槽函数
        self.create_button.clicked.connect(self.create_func)
        # 关闭子页面按钮点击信号绑定槽函数
        self.close_button.clicked.connect(self.close_func)

    # 创建子页面方法
    def create_func(self):
        # 创建子页面
        self.child_widget = Child_Widget()
        # 子页面自定义信号绑定显示子页面信息方法
        self.child_widget.status_signal.connect(
            self.child_widget_info)
        # 设置子页面名称
        self.child_widget.setWindowTitle('子页面')
        self.child_widget.show()

    # 子页面关闭方法
    def close_func(self):
        try:
            self.child_widget.close()
            self.child_widget.status_signal.connect(self.child_widget_info)
        except:
            self.line_1.setText('子页面不存在！')

    # 子页面信息显示方法
    def child_widget_info(self, info):
        if info == 'create':
            self.line_1.setText('子页面被创建')
        elif info == 'close':
            self.line_1.setText('子页面被关闭')
# 创建子页面类
class Child_Widget(QWidget):
    # 创建自定义子页面状态信号
    status_signal = pyqtSignal(str)
    def __init__(self):
        super(Child_Widget, self).__init__()
        # 设定子页面尺寸
        self.resize(300,300)
        # 设定子页面的窗口名称改变信号与自定义信号连接
        self.windowTitleChanged.connect(lambda :
                    self.status_signal.emit('create'))

    # 重写关闭方法,将子页面关闭事件与自定义信号连接
    def closeEvent(self, event):
        self.status_signal.emit('close')


if __name__ == '__main__':
    page = QApplication(sys.argv)
    # 实例父页面
    window = Parents_Widget()
    window.show()
    sys.exit(page.exec())
