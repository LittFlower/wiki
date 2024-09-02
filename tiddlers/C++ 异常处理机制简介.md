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

**搜索阶段**：一旦出现异常，[[unwinder]] 会去了解这个异常是否可以由某个 EH handler 处理（即 `catch` 块）。unwinder 通过检查当前 IP 和检索相关的 unwind 元数据（如[[异常帧]]中的帧描述条目 (FDE)）来开始这一过程。后者包含（可能通过额外的间接层）指向特定语言 personality routine 函数的指针，以及指向[[特定语言数据区（LSDA）]]的指针。不同的调用框架可能会使用不同的 personality routine。unwinder 将调用当前调用框架的 personality routine，该函数将检索并解析 LSDA，以确定当前调用框架中是否包含针对抛出的特定的异常类型的有效异常处理程序。为此，会将当前 IP 与一个全是[[调用点（call-site）]]的有序列表进行比较。这个列表里的调用点与可处理的异常类型列表及其相应的 [[landing pad]] 相关联。如果找不到处理程序，就会使用 unwind 元数据中编码的调用帧大小计算前一个堆栈帧的地址。新调用帧保存的 IP 会被检索出来，然后重复这一过程，直到找到带有有效处理程序的调用帧或堆栈耗尽为止。在后一种情况下，通常会调用一个默认处理程序来终止程序。

**清理阶段**：这个阶段，unwinder 还是会去调用 personality routine，后者会从异常帧开始逐层调整栈指针。根据 LSDA，personality routine 可能会先恢复先前被调用者保存的寄存器，然后把程序控制流转交给某个 “landing pad”。
