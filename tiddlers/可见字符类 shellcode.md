```python
import itertools
from pwn import *

context.arch = "amd64"

s = "0123456789\x3a\x3b\x3c\x3d\x3e\x3f\x40" #可用字符

for x in range(3):
    for y in itertools.product(s, repeat=x+1):
        res = disasm("".join(y).encode())
        need_p = 1
        for kk in  (".byte", "rex", "ds", "bad", "ss"):
            if kk in res:
                need_p = 0
                break
        if need_p:
            print(res)
```

### 控制内存

`xor [rbx+t], 0xaabbccdd`