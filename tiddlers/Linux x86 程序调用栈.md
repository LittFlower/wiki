![stack](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/figure/Data_stack.png)

每个程序在运行时都有虚拟地址空间，其中某一部分就是该程序对应的栈，用于保存函数调用信息和局部变量。

**程序的栈是从进程地址空间的高地址向低地址增长的**。
