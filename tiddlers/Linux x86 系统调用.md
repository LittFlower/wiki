### 系统调用

在电脑中，系统调用（英语：system call），指运行在用户空间的程序向操作系统内核请求需要更高权限运行的服务。系统调用提供用户程序与操作系统之间的接口。大多数系统交互式操作需求在内核态执行。如设备 IO 操作或者进程间通信。

**用户空间（用户态）和内核空间（内核态）**

操作系统的进程空间可分为用户空间和内核空间，它们需要不同的执行权限。其中系统调用运行在内核空间。

**库函数**

系统调用和普通库函数调用非常相似，只是系统调用由操作系统内核提供，运行于内核核心态，而普通的库函数调用由函数库或用户自己提供，运行于用户态。

**典型实现（Linux）**

Linux 在 x86 上的系统调用通过 `int 80h` 实现，用系统调用号来区分入口函数。

**操作系统实现系统调用的基本过程是**：

- 应用程序调用库函数（API）；
- API 将系统调用号存入 EAX，然后通过中断调用使系统进入内核态；
- 内核中的中断处理函数根据系统调用号，调用对应的内核函数（系统调用）；
- 系统调用完成相应功能，将返回值存入 EAX，返回到中断处理函数；
- 中断处理函数返回到 API 中；
- API 将 EAX 返回给应用程序。

**应用程序调用系统调用的过程是**：

- 把系统调用的编号存入 EAX；
- 把函数参数存入其它通用寄存器；
- 触发 0x80 号中断（int 0x80）。
