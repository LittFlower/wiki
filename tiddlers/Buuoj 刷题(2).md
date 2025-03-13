## hitb2018_gundam

glibc2.7 的堆题，程序可以分配一个 0x30 和 0x110 的堆块，存在一个没有任何检查的 UAF，2.7 版本下的 tcache 机制几乎没有任何安全校验保护，所以可以直接打 tcache double free 任意地址分配。分配到 __free_hook 修改为 onegadget 或者 system 释放一个 `/bin/sh` 即可拿下。 

## QCTF-2018_babyheap

2.27 的 off by null，先用经典三明治结构构造堆块重叠拿到 UAF，然后利用 unsortbin 踩出 libc 地址并 leak，最后打 tcache posioning 攻击 free hook。

三明治结构里可以“多夹几层”，比如这道题目我往里面多夹了一个 0x20 的小堆块用来后续 tcache posioning 攻击。

tcache 的管理范围在 0x408，为了触发 unlink，不能让堆块直接进 tcache。