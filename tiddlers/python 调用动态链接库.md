模板如下：

```python
from ctypes import *
poc = cdll.LoadLibrary("./B.so")
libc = cdll.LoadLibrary('/usr/lib/libc.so.6')
seed = poc.find(num)
```

注意，这个 .so 里的 `find` 函数不能是 void，如果想接受返回值的话。

在 find 函数里的 printf 输出会晚于 pwntools 的交互。