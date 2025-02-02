## 简介

关于 execve 和 system，在 Pwn 的时候经常作为题目 exp 的终端，前者经常用在 onegadget 或者 shellcode 里，后者则在 ROP 里见得更多一点。

这篇笔记主要关注 execve 和 system 在调用后的进程状态。

## execve

