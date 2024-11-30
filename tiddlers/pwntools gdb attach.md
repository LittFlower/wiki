在 exp 中使用 pwntools，想要 attach 到二进制程序上：

```python
from pwn import *

script = """
...
"""
gdb.attach(io, script) 
```

第二个参数可以填一个 command 字符串，这条 command 会在 gdb attach 上进程后立刻执行。