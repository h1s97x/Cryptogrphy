### Pycharm中 程序依赖包的 批量导出、批量安装

[Pycharm中 程序依赖包的 批量导出、批量安装_pycharm 提取安装包-CSDN博客](https://blog.csdn.net/chenhepg/article/details/109527151)

1、python包的批量安装
pip install -r requirements.txt

2、python包的批量导出
pip freeze [options]
pip freeze > a.txt


3、python包的列表显示
pip list [options]
pip list > b.txt

4、特定安装包的详细显示
pip show [options] <package>
pip show matplotlib

### Python生成目录树

[简单粗暴，用python生成目录树_pycharm导出项目树结构-CSDN博客](https://blog.csdn.net/sinat_38682860/article/details/80255083)

#### CMD

```
> tree /?
以图形显示驱动器或路径的文件夹结构。
TREE [drive:][path] [/F] [/A]
   /F   显示每个文件夹中文件的名称。
   /A   使用 ASCII 字符，而不使用扩展字符。
```



```
tree /F E:\Programming\Python\DesignPattern > dirtree.txt
```

命令执行之后，在命令行所在目录下会生成一个名为 “ **dirtree.txt** ” 的文件，目录结构已在其中。

#### Python

```
# -*- coding: utf-8 -*-
import sys
from pathlib import Path
 
 
class DirectionTree(object):
    """生成目录树
    @ pathname: 目标目录
    @ filename: 要保存成文件的名称
    """
 
    def __init__(self, pathname='.', filename='tree.txt'):
        super(DirectionTree, self).__init__()
        self.pathname = Path(pathname)
        self.filename = filename
        self.tree = ''
 
    def set_path(self, pathname):
        self.pathname = Path(pathname)
 
    def set_filename(self, filename):
        self.filename = filename
 
    def generate_tree(self, n=0):
        if self.pathname.is_file():
            self.tree += '    |' * n + '-' * 4 + self.pathname.name + '\n'
        elif self.pathname.is_dir():
            self.tree += '    |' * n + '-' * 4 + \
                str(self.pathname.relative_to(self.pathname.parent)) + '\\' + '\n'
 
            for cp in self.pathname.iterdir():
                self.pathname = Path(cp)
                self.generate_tree(n + 1)
 
    def save_file(self):
        with open(self.filename, 'w', encoding='utf-8') as f:
            f.write(self.tree)
 
 
if __name__ == '__main__':
    dirtree = DirectionTree()
    # 命令参数个数为1，生成当前目录的目录树
    if len(sys.argv) == 1:
        dirtree.set_path(Path.cwd())
        dirtree.generate_tree()
        print(dirtree.tree)
    # 命令参数个数为2并且目录存在存在
    elif len(sys.argv) == 2 and Path(sys.argv[1]).exists():
        dirtree.set_path(sys.argv[1])
        dirtree.generate_tree()
        print(dirtree.tree)
    # 命令参数个数为3并且目录存在存在
    elif len(sys.argv) == 3 and Path(sys.argv[1]).exists():
        dirtree.set_path(sys.argv[1])
        dirtree.generate_tree()
        dirtree.set_filename(sys.argv[2])
        dirtree.save_file()
    else:  # 参数个数太多，无法解析
        print('命令行参数太多，请检查！')
```

使用方法：

- `python dirtree.py` ：打印当前目录的目录树；
- `python dirtree.py E:\Programming\Python\applications` ：打印指定目录的目录树；
- `python dirtree.py E:\Programming\Python\applications dirtree.txt` ：打印指定目录的目录树并保存成文件。

