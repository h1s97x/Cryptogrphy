[Python应该如何导入（import）模块及包 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/265591655)

## 一 .module

通常模块为一个文件，直接使用import来导入就好了。可以作为module的文件类有".py"、".pyo"、".pyc"、".pyd"、".so"、".dll"。

## 二. package

通常包总是一个目录，可以使用import导入包，或者from + import来导入包中的部分模块。包目录下为首的一个文件便是__init__.py。然后是一些模块文件和子目录，假如子目录中也有__init__.py 那么它就是这个包的子包了。



### package的导入

多个关系密切的模块应该组织成一个包，以便于维护和使用。这项技术能有效避免名字空间冲突。创建一个名字为包名字的文件夹并在该文件夹下创建一个`__init__.py` 文件，这样就定义了一个包。你可以根据需要在该文件夹下存放资源文件、已编译扩展及子包。举例来说，一个包可能有以下结构:

```text
Graphics/
      __init__.py
      Primitive/
         __init__.py
         lines.py
         fill.py
         text.py
         ...
      Graph2d/
         __init__.py
         plot2d.py
         ...
      Graph3d/
         __init__.py
         plot3d.py
         ...
      Formats/
         __init__.py
         gif.py
         png.py
         tiff.py
         jpeg.py
```

`import`语句使用以下几种方式导入包中的模块:

```text
import Graphics.Primitive.fill #导入模块
Graphics.Primitive.fill,只能以全名访问模块属性,
例如 Graphics.Primitive.fill.floodfill(img,x,y,color).  
from Graphics.Primitive import fill# 导入模块fill ,
只能以 fill.属性名这种方式访问模块属性,
例如fill.floodfill(img,x,y,color).  
from Graphics.Primitive.fill import floodfill #导入模块fill 
将函数floodfill放入当前名称空间
直接访问被导入的属性
例如 floodfill(img,x,y,color).
```

无论一个包的哪个部分被导入, 在文件`__init__.py`中的代码都会运行.这个文件的内容允许为空,不过通常情况下它用来存放包的初始化代码。导入过程遇到的所有`__init__.py`文件都被运行.因此 `import Graphics.Primitive.fill` 语句会顺序运行 `Graphics` 和 `Primitive` 文件夹下的`__init__.py`文件.

下边这个语句具有歧义:

```text
from Graphics.Primitive import *
```

这个语句的原意图是想将Graphics.Primitive包下的所有模块导入到当前的名称空间.然而,由于不同平台间文件名规则不同(比如大小写敏感问题), Python不能正确判定哪些模块要被导入.这个语句只会顺序运行 Graphics 和 Primitive 文件夹下的`__init__.py`文件. 要解决这个问题，应该在Primitive文件夹下面的`__init__.py`中定义一个名字all的列表，例如:

```text
# Graphics/Primitive/__init__.py  
__all__ = ["lines","text","fill",...]
```

这样,上边的语句就可以导入列表中所有模块.

下面这个语句只会执行Graphics目录下的`__init__`py文件，而不会导入任何模块:

```text
import Graphics  
Graphics.Primitive.fill.floodfill(img,x,y,color)  # 失败!  
```

不过既然`import Graphics` 语句会运行 Graphics 目录下的`__init__.py`文件,我们就可以采取下面的手段来解决这个问题：

```text
# Graphics/__init__.py  
import Primitive, Graph2d, Graph3d  
# Graphics/Primitive/__init__.py  
import lines, fill, text, ...
```

这样`import Graphics`语句就可以导入所有的子模块(只能用全名来访问这些模块的属性).