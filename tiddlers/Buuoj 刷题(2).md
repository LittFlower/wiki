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


