## hitb2018_gundam

glibc2.7 的堆题，程序可以分配一个 0x30 和 0x110 的堆块，存在一个没有任何检查的 UAF，2.7 版本下的 tcache 机制几乎没有任何安全校验保护，所以可以直接打 tcache double free 任意地址分配。分配到 __free_hook 修改为 onegadget 或者 system 释放一个 `/bin/sh` 即可拿下。 

## QCTF-2018_babyheap

2.27 的 off by null，先用经典三明治结构构造堆块重叠拿到 UAF，然后利用 unsortbin 踩出 libc 地址并 leak，最后打 tcache posioning 攻击 free hook。

三明治结构里可以“多夹几层”，比如这道题目我往里面多夹了一个 0x20 的小堆块用来后续 tcache posioning 攻击。

tcache 的管理范围在 0x408，为了触发 unlink，不能让堆块直接进 tcache。

## ycb_2020_easypwn

glibc 2.23 的 fastbin attack。题目可以任意大小堆块分配，首先分配一个大堆块再释放掉使其进入 unsort bin，利用 unsort bin 切割时保留 fd/bk 的特性踩出 libc，然后泄漏出来。之后打 0x70 size 的 fastbin attack，由于 libc 对应的 4 个 onegadget 都不能直接用，那就用 realloc 调整栈帧再打。调用链是：`malloc -> malloc_hook -> realloc -> realloc_hook -> onegadget`，因为 malloc_hook 和 realloc_hook 离得很近，可以一次申请 fastbin fake chunk 修改他俩。

```asm
.text:00000000000846C0 realloc         proc near               ; DATA XREF: LOAD:0000000000006BA0↑o
.text:00000000000846C0 ; __unwind {
.text:00000000000846C0                 push    r15             ; Alternative name is '__libc_realloc'
.text:00000000000846C2                 push    r14
.text:00000000000846C4                 push    r13
.text:00000000000846C6                 push    r12
.text:00000000000846C8                 mov     r13, rsi
.text:00000000000846CB                 push    rbp
.text:00000000000846CC                 push    rbx
.text:00000000000846CD                 mov     rbx, rdi
.text:00000000000846D0                 sub     rsp, 38h
.text:00000000000846D4                 mov     rax, cs:__realloc_hook_ptr
.text:00000000000846DB                 mov     rax, [rax]
.text:00000000000846DE                 test    rax, rax
.text:00000000000846E1                 jnz     loc_848E8        ; 跳转执行 realloc_hook
.text:00000000000846E7                 test    rsi, rsi
.text:00000000000846EA                 jnz     short loc_846F5
.text:00000000000846EC                 test    rdi, rdi
.text:00000000000846EF                 jnz     loc_84960
```

realloc_hook 里有 6 次 push，还有一个 ` sub rsp, 0x38`，利用这些 gadget 调整栈帧即可。

## [BSidesCF 2019]RunitPlusPlus

题目逻辑是把输入的 shellcode 的前一半和后一半交换一下（使用异或实现），那直接手搓一个就好了。

## xp0intctf_2018_bof

按理说是很简单的 shellcode 签到题，不过我觉得这题可以栈迁移做，顺带练习一下。

[[栈迁移的经验总结]]

## [ZJCTF 2019]EasyHeap

本来可以用 unsort bin attack 直接在 `magic` 那里写一个大数字，然后执行后门函数，但是远程环境有点问题，flag 文件不在 `/home/ctf/flag` 里，，但是毕竟有无限制的任意堆溢出，所以可以直接打 fastbin posioning。

但是如果直接在 `free` 那里劫持 fake fast chunk 的话，必然会把 `_GLOBAL_OFFSET_TABLE_` 改了，然而程序里的 `system@plt` 这个时候还是没有重定位过的，所以会寄。

解决方案是，在 heaparray 处构造 fake chunk，然后改 `heaparray[0]` 为 `free@got`，然后就可以只把 `free@got` 处的 8 个字节改成 `system` 而不破坏重定位表。

## ciscn_2019_s_2

卡了一会，这个题的考点在于 `realloc` 的特性：如果 `size` 为 `0 ，则`realloc` 相当于一个 `free`。在这道题目里这个时候就存在 uaf 漏洞了。

先通过切割 unsortbin 泄漏 libc，然后打 tcache double free 和 tcache posioning 修改 _free_hook。

## xp0intctf_2018_tutorial1

签到题，直接发 `p64(0xBABABABA)` 就行。

## xp0intctf_2018_tutorial2

还是签到题，考点和上题类似。

## xp0intctf_2018_fast

glibc 2.27，题目给了一个裸的 UAF，可以打 tcache double free + tcache posioning，任意地址申请到读入的 flag 附近，然后把 flag 直接打印出来。