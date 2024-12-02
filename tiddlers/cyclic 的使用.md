`cyclic` 是个很好使的工具，可以用来生成可用于测试的字符串。

`cyclic [len]` 生成长度为 `len` 的字符串；

`cyclic -l [xxxxxxxx]` 搜索偏移

通过 cyclic 可以在没有构造 rop / cop 头绪的时候 “模糊测试” 一下，在 exp 里可以这么写：

```python
from pwn import *
junk_bytes = cyclic(112, n=8)  # 生成一段长度为 112 的有序字符串，步长为 8
offset = cyclic_find("faaaaaaa", n=8)  # 寻找 "faaaaaaa" 的偏移
```