# 0x01

根据语言定义的语义，可以按照异常处理函数执行之后控制流返回的位置将其分为[[终止语义和恢复语义]]，C++ 异常处理普遍使用的是终止语义；

# 0x02

异常处理机制与处理器架构、操作系统、编程语言都相关：

- Intel 有 Itanium C++ ABI，AMD 有 SystemV AMD64 ABI，这证明不同的处理器架构厂商都有不同的标准，例如 x86-64 架构就沿用了 Itanium C++ ABI，那么[[什么是ABI]]?
- 不同的操作系统也选择了不同的异常处理流程，例如 Unix-Based System 使用了 Stack Unwinding 机制，而 windows 则使用了 SEH（Structure Exception Handler），这也存在不同；
- 不同的编程语言（编译器）使用了不同的 ABIs，它们使用的调用约定并不相同，这导致异常处理机制也存在差异，另外，Java 使用 `try-catch-finally` 块来处理异常，Python 使用 `try-except-finally`，而 C++ 使用 `try-catch` 块。编程语言定义了异常如何被捕获、处理以及传播，这也是相当明显的区别；
- unwind 库的实现也存在差异，例如 libgcc/llvm-libunwind/nongnu-libunwind，这几个库的实现各不相同，不过都提供 Itanium C++ ABI 的实现。

# 0x03

根据 Itanium C++ ABI，异常处理的基本流程其实就两步：搜索阶段和清理阶段。

搜索阶段