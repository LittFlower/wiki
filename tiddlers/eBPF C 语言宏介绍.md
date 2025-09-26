ebpf 设计了一套指令，通过数组的形式帮助开发者用 C 语言来编写 eBPF 汇编，具体实现方式是 C 语言宏，定义在 [`<bpf/bpf_insn.h>`](https://github.com/torvalds/linux/blob/master/samples/bpf/bpf_insn.h) 文件里。

这里简单总结一下这些宏的用法。



| 类别 (Category) | 原语 (Primitive) | 作用 (Function) | 伪代码/示例 | 参数说明 |
| :--- | :--- | :--- | :--- | :--- |
| **算术与逻辑运算** | `BPF_ALU64_REG(OP, DST, SRC)` | 对两个 **64 位**寄存器进行指定的算术或逻辑运算。 | `DST = DST op SRC` | `OP`: 运算类型 (如 `BPF_ADD`, `BPF_XOR`) <br> `DST`: 目标寄存器 <br> `SRC`: 源寄存器 |
| **算术与逻辑运算** | `BPF_ALU32_REG(OP, DST, SRC)` | 对两个 **32 位**寄存器进行算术/逻辑运算 (高32位清零)。 | `(u32)DST = (u32)DST op (u32)SRC` | 同上 |
| **算术与逻辑运算** | `BPF_ALU64_IMM(OP, DST, IMM)` | 对一个 **64 位**寄存器和一个立即数进行运算。 | `DST = DST op IMM` | `OP`: 运算类型 <br> `DST`: 目标寄存器 <br> `IMM`: 32位立即数 |
| **算术与逻辑运算** | `BPF_ALU32_IMM(OP, DST, IMM)` | 对一个 **32 位**寄存器和一个立即数进行运算 (高32位清零)。 | `(u32)DST = (u32)DST op IMM` | 同上 |
| **数据移动** | `BPF_MOV64_REG(DST, SRC)` | 将 `SRC` 寄存器的值复制到 `DST` 寄存器 (64位)。 | `DST = SRC` | `DST`: 目标寄存器 <br> `SRC`: 源寄存器 |
| **数据移动** | `BPF_MOV32_REG(DST, SRC)` | 将 `SRC` 寄存器的值复制到 `DST` 寄存器 (32位，高32位清零)。 | `(u32)DST = (u32)SRC` | 同上 |
| **数据移动** | `BPF_MOV64_IMM(DST, IMM)` | 将一个立即数赋值给 `DST` 寄存器 (64位)。 | `DST = IMM` | `DST`: 目标寄存器 <br> `IMM`: 32位立即数 |
| **数据移动** | `BPF_MOV32_IMM(DST, IMM)` | 将一个立即数赋值给 `DST` 寄存器 (32位，高32位清零)。 | `(u32)DST = IMM` | 同上 |
| **内存操作** | `BPF_LDX_MEM(SIZE, DST, SRC, OFF)` | **从内存加载 (Load)**：从内存地址 `SRC + OFF` 读取数据到 `DST` 寄存器。 | `DST = *(SIZE*)(SRC + OFF)` | `SIZE`: 数据宽度 (`BPF_B`, `BPF_H`, `BPF_W`, `BPF_DW`) <br> `DST`: 目标寄存器 <br> `SRC`: 基地址寄存器 <br> `OFF`: 16位有符号偏移 |
| **内存操作** | `BPF_STX_MEM(SIZE, DST, SRC, OFF)` | **向内存存储 (Store Register)**：将 `SRC` 寄存器的值写入内存地址 `DST + OFF`。 | `*(SIZE*)(DST + OFF) = SRC` | `SIZE`: 数据宽度 <br> `DST`: 基地址寄存器 <br> `SRC`: 源数据寄存器 <br> `OFF`: 16位有符号偏移 |
| **内存操作** | `BPF_ST_MEM(SIZE, DST, OFF, IMM)` | **向内存存储 (Store Immediate)**：将立即数 `IMM` 写入内存地址 `DST + OFF`。 | `*(SIZE*)(DST + OFF) = IMM` | `SIZE`: 数据宽度 <br> `DST`: 基地址寄存器 <br> `OFF`: 16位有符号偏移 <br> `IMM`: 32位立即数 |
| **控制流** | `BPF_JMP_REG(OP, DST, SRC, OFF)` | **条件跳转 (Register)**：比较 `DST` 和 `SRC` 寄存器，若满足条件则跳转。 | `if (DST op SRC) goto pc + OFF` | `OP`: 比较类型 (如 `BPF_JEQ`, `BPF_JGT`) <br> `DST`: 目标寄存器 <br> `SRC`: 源寄存器 <br> `OFF`: 16位相对跳转偏移 |
| **控制流** | `BPF_JMP_IMM(OP, DST, IMM, OFF)` | **条件跳转 (Immediate)**：比较 `DST` 寄存器和立即数 `IMM`，若满足条件则跳转。 | `if (DST op IMM) goto pc + IMM` | `OP`: 比较类型 <br> `DST`: 目标寄存器 <br> `IMM`: 32位立即数 <br> `OFF`: 16位相对跳转偏移 |
| **控制流** | `BPF_JMP32_REG(...)` / `_IMM(...)` | 同上，但进行的是 **32 位**数值的比较。 | | |
| **控制流** | `BPF_RAW_INSN(...)` | **构造原始指令**：用于构建任意 eBPF 指令，最常用于调用辅助函数。 | `call BPF_FUNC_map_lookup_elem` | `CODE`: 完整指令码 (如 `BPF_JMP | BPF_CALL`) <br> `DST`, `SRC`, `OFF`, `IMM`: 指令的各个字段 |
| **控制流** | `BPF_EXIT_INSN()` | **退出程序**：终止当前 eBPF 程序的执行，`R0` 的值将作为返回值。 | `exit()` | 无 |
| **特殊加载指令**| `BPF_LD_IMM64(DST, IMM)` | **加载 64 位立即数**。**注意：这会生成两条指令**。 | `DST = (u64)IMM` | `DST`: 目标寄存器 <br> `IMM`: 64位立即数 |
| **特殊加载指令**| `BPF_LD_MAP_FD(DST, MAP_FD)` | **加载 Map 文件描述符**。这是一个伪指令，内核加载器会将其解析为真实的 Map 地址。 | `DST = &map[MAP_FD]` | `DST`: 目标寄存器 <br> `MAP_FD`: 用户空间的 Map 文件描述符 |
| **特殊加载指令**| `BPF_LD_ABS(SIZE, IMM)` | **直接从数据包加载** (绝对偏移，用于 cBPF 兼容)。 | `R0 = *(SIZE*)(skb->data + IMM)` | `SIZE`: 数据宽度 <br> `IMM`: 32位绝对偏移 |
| **原子操作** | `BPF_ATOMIC_OP(SIZE, OP, DST, SRC, OFF)` | **原子操作**：在共享内存 (`DST+OFF`) 上执行线程安全的读-改-写。<br>**`OP` 类型**: <br> `BPF_ADD`: 原子加 <br> `BPF_AND`: 原子与 <br> `BPF_OR`: 原子或 <br> `BPF_XOR`: 原子异或 <br> `BPF_ADD \| BPF_FETCH`: 原子加并返回旧值 <br> `BPF_XCHG`: 原子交换 <br> `BPF_CMPXCHG`: 原子比较并交换 | `*(SIZE*)(DST + OFF) op= SRC` <br> `old = atomic_fetch_add(...)` <br> `old = atomic_xchg(...)` <br> `old = atomic_cmpxchg(r0, ...)` | `SIZE`: 数据宽度 (`BPF_W` 或 `BPF_DW`) <br> `OP`: 原子操作类型 <br> `DST`: 基地址寄存器 <br> `SRC`: 源寄存器 <br> `OFF`: 16位偏移 |


对应的源码：

```c
/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* eBPF instruction mini library */
#ifndef __BPF_INSN_H
#define __BPF_INSN_H

struct bpf_insn;

/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */

#define BPF_ALU64_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_ALU32_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */

#define BPF_ALU64_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_ALU32_IMM(OP, DST, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Short form of mov, dst_reg = src_reg */

#define BPF_MOV64_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

#define BPF_MOV32_REG(DST, SRC)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })

/* Short form of mov, dst_reg = imm32 */

#define BPF_MOV64_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

#define BPF_MOV32_IMM(DST, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_ALU | BPF_MOV | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */
#define BPF_LD_IMM64(DST, IMM)					\
	BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_LD_IMM64_RAW(DST, SRC, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_DW | BPF_IMM,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = (__u32) (IMM) }),			\
	((struct bpf_insn) {					\
		.code  = 0, /* zero is reserved opcode */	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = ((__u64) (IMM)) >> 32 })

#ifndef BPF_PSEUDO_MAP_FD
# define BPF_PSEUDO_MAP_FD	1
#endif

/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */
#define BPF_LD_MAP_FD(DST, MAP_FD)				\
	BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)


/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */

#define BPF_LD_ABS(SIZE, IMM)					\
	((struct bpf_insn) {					\
		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,	\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = IMM })

/* Memory load, dst_reg = *(uint *) (src_reg + off16) */

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Memory store, *(uint *) (dst_reg + off16) = src_reg */

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/*
 * Atomic operations:
 *
 *   BPF_ADD                  *(uint *) (dst_reg + off16) += src_reg
 *   BPF_AND                  *(uint *) (dst_reg + off16) &= src_reg
 *   BPF_OR                   *(uint *) (dst_reg + off16) |= src_reg
 *   BPF_XOR                  *(uint *) (dst_reg + off16) ^= src_reg
 *   BPF_ADD | BPF_FETCH      src_reg = atomic_fetch_add(dst_reg + off16, src_reg);
 *   BPF_AND | BPF_FETCH      src_reg = atomic_fetch_and(dst_reg + off16, src_reg);
 *   BPF_OR | BPF_FETCH       src_reg = atomic_fetch_or(dst_reg + off16, src_reg);
 *   BPF_XOR | BPF_FETCH      src_reg = atomic_fetch_xor(dst_reg + off16, src_reg);
 *   BPF_XCHG                 src_reg = atomic_xchg(dst_reg + off16, src_reg)
 *   BPF_CMPXCHG              r0 = atomic_cmpxchg(dst_reg + off16, r0, src_reg)
 */

#define BPF_ATOMIC_OP(SIZE, OP, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_ATOMIC,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = OP })

/* Legacy alias */
#define BPF_STX_XADD(SIZE, DST, SRC, OFF) BPF_ATOMIC_OP(SIZE, BPF_ADD, DST, SRC, OFF)

/* Memory store, *(uint *) (dst_reg + off16) = imm32 */

#define BPF_ST_MEM(SIZE, DST, OFF, IMM)				\
	((struct bpf_insn) {					\
		.code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc + off16 */

#define BPF_JMP_REG(OP, DST, SRC, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_X,		\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Like BPF_JMP_REG, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_REG(OP, DST, SRC, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_JMP32 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = 0 })

/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */

#define BPF_JMP_IMM(OP, DST, IMM, OFF)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_OP(OP) | BPF_K,		\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Like BPF_JMP_IMM, but with 32-bit wide operands for comparison. */

#define BPF_JMP32_IMM(OP, DST, IMM, OFF)			\
	((struct bpf_insn) {					\
		.code  = BPF_JMP32 | BPF_OP(OP) | BPF_K,	\
		.dst_reg = DST,					\
		.src_reg = 0,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Raw code statement block */

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)			\
	((struct bpf_insn) {					\
		.code  = CODE,					\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = OFF,					\
		.imm   = IMM })

/* Program exit */

#define BPF_EXIT_INSN()						\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_EXIT,			\
		.dst_reg = 0,					\
		.src_reg = 0,					\
		.off   = 0,					\
		.imm   = 0 })

#endif
```