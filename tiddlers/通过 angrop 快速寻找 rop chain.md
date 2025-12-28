项目地址：https://github.com/angr/angrop

代码模板：

```python
import angr
import angrop
from multiprocessing import cpu_count

# 1. 加载二进制文件
proj = angr.Project("", load_options={'main_opts':{'base_addr': 0}})

# 2. 初始化 ROP 分析
# fast_mode=False 启用更深入的分析
rop = proj.analyses.ROP(fast_mode=False, max_sym_mem_access=1)

# 3. 查找 Gadgets (利用多核处理)
rop.find_gadgets(processes=cpu_count(), show_progress=True)

# 4. 生成 ROP 链 (例如调用函数 0xfacefeed)
# 参数为 [0xdeadbeef, 0x40, 0x7b]
chain = rop.func_call(0xfacefeed, [0xdeadbeef, 0x40, 0x7b], needs_return=False)

# 5. 打印 Payload 代码
chain.print_payload_code()
chain.payload_str()
```


重点是生成 rop chain 这一步，有以下可替代操作：

以下是可用的主要方法及其功能说明:

### 1. 寄存器操作 (Register Operations)

这些方法用于直接控制寄存器的值。

* **`set_regs(**registers)`**
* **功能**: 生成一个 ROP 链，将指定的寄存器设置为特定值。
* **示例**: `chain = rop.set_regs(rax=0x1234, rbx=0x41414141)`
* **参数**: 关键字参数，键为寄存器名，值为目标值。


* **`move_regs(**registers)`**
* **功能**: 生成一个 ROP 链，将一个寄存器的值移动到另一个寄存器。
* **示例**: `chain = rop.move_regs(rax='rcx')` (将 rcx 的值移给 rax)。
* **参数**: 关键字参数，键为目标寄存器，值为源寄存器字符串。



### 2. 系统调用与执行 (Execution & Syscalls)

用于执行系统调用或特定的 shellcode 逻辑。

* **`do_syscall(syscall_num, args, needs_return=True, **kwargs)`**
* **功能**: 执行指定的系统调用。它会自动根据架构设置系统调用号和参数。
* **示例**: `chain = rop.do_syscall(59, [bin_sh_addr, 0, 0])` (执行 sys_execve)。
* **参数**:
* `syscall_num`: 系统调用号 (int)。
* `args`: 系统调用参数列表。
* `needs_return`: 是否需要在系统调用后继续执行 ROP 链。




* **`execve(path=None, path_addr=None)`**
* **功能**: 专门用于生成执行 `execve("/bin/sh", 0, 0)` 的 ROP 链。这是一个快捷方法。
* **示例**: `chain = rop.execve()` 或 `chain = rop.execve(path=b"/bin/ls")`。
* **参数**:
* `path`: 要执行的二进制路径（默认为 `/bin/sh`）。
* `path_addr`: 存放路径字符串的内存地址（可选）。





### 3. 内存操作 (Memory Operations)

* **`add_to_mem(addr, value, data_size=None)`**
* **功能**: 生成一个 ROP 链，将指定内存地址处的值加上一个数值。通常用于修改 GOT 表或其他数据结构。
* **示例**: `chain = rop.add_to_mem(0x8048000, 0x10)`。
* **参数**:
* `addr`: 目标内存地址。
* `value`: 要增加的值。
* `data_size`: 数据大小（位），默认为架构字长。

* **`write_to_mem(addr, value, data_size=None)`**
* **功能**: 生成一个 ROP 链，将指定内存地址处的值写入一个数值。
* **示例**: `chain = rop.write_to_mem(0x8048000, 0x10)`。
* **参数**:
* `addr`: 目标内存地址。
* `value`: 要写入的值。
* `data_size`: 数据大小（位），默认为架构字长。



### 4. 栈与控制流操作 (Stack & Control Flow)

用于控制栈指针或改变执行流。

* **`pivot(thing)`**
* **功能**: 生成栈迁移（Stack Pivot）链，将栈指针（SP/ESP/RSP）移动到指定位置。
* **示例**: `chain = rop.pivot(0x401000)`。
* **参数**: `thing` 可以是一个地址或寄存器。


* **`shift(length, preserve_regs=None)`**
* **功能**: 移动栈指针指定的字节数（例如 `add rsp, 0x20; ret`）。
* **示例**: `chain = rop.shift(0x10)`。


* **`retsled(size, preserve_regs=None)`**
* **功能**: 生成一个 `ret` 滑梯（NOP sled 的 ROP 版本），即一连串的 `ret` 指令。

* **`func_call(func_name, args=[])`**
* **功能**: call func


### 5. 全局配置 (Configuration)

这些方法用于动态调整 ROP 生成器的设置。

* **`set_badbytes(badbytes)`**
* **功能**: 设置生成链时必须避开的“坏字节”（如 `\x00` 或 `\n`）。
* **示例**: `rop.set_badbytes([0x00, 0x0a])`。


* **`set_roparg_filler(roparg_filler)`**
* **功能**: 设置用于填充栈上无用位置的字节（Padding）。
* **示例**: `rop.set_roparg_filler(0x41414141)`。



这些方法都可以在 `rop` 对象上直接调用。你可以将它们生成的链相加（`chain1 + chain2`）来组合复杂的功能。