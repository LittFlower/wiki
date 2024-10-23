## 0x00. Abstract

对于 C 和 C++ 等编程语言来说，内存访问错误（包括缓冲区溢出和 use after free）仍然是一个严重问题。存在许多内存错误检测器，但大多数检测器要么速度慢，要么局限于有限的错误集，或者两者兼而有之。本文介绍了 AddressSanitizer，一种新的内存错误检测器。这个工具可以查找对堆、堆栈和全局变量的越界访问，以及 use after free。它采用专门的内存分配器和代码工具，足够简单，可以在任何编译器、二进制翻译系统甚至硬件中实现。AddressSanitizer 在不牺牲全面性的情况下实现了效率。它的平均速度仅为 73%，但它可以在错误发生时准确地检测到错误。它在 Chromium 浏览器中发现了 300 多个以前未知的错误，以及其他软件中的许多错误。

## 0x01. Introduction

AddressSanitizer 由两部分组成：**检测模块**和**运行时库**。**检测模块**修改代码以检查每次内存访问的*影子态 (shadow state)*，并在堆栈和全局对象周围创建*中毒红区*以检测向上或向下溢出。当前的实现基于 LLVM 编译器基础设施。**运行时库**替换了 `malloc`、`free` 和相关函数，在分配的堆区域周围创建*中毒红区*，延迟已释放堆区域的重用，并进行错误报告。

总的来说，这篇文章做了以下几件事：

- 说明了内存错误检测器可以利用*影子内存 shadow memory*的全面性，并且开销比传统方法低得多；
- 提出一种新颖的影子态编码方式，可实现紧凑的影子内存（高达 128-to-1），用于检测越界和 use-after-free 错误；
- 描述一个针对新实现的影子编码的专用内存分配器；
- 评估一个新的公开可用的工具，该工具可以有效地识别内存错误。

## 0x02. Related work

### 影子内存（shadow memory）

总的来说，按照对应用程序地址的处理可以把现有的工具分为两种：

- 通过直接缩放和偏移（其中完整应用程序地址空间映射到单个影子地址空间）；
- 通过涉及查表的额外转换来映射到影子地址空间。

直接缩放和偏移的例子有：

- TaintTrace
- LIFT

使用多级转换的例子有：

- Valgrind
- Dr.Memory

还有一些比较 trick 的工具：

- Umbra：兼顾布局灵活性和效率，使用可动态调整的缩放和偏移来直接映射地址而非使用查表的方式；
- BoundLess：利用 64 位寄存器的高 16 位来做到内存复用，但是在慢速路径下会退化；
- LBC：使用存储在应用程序内存中的特殊值执行快速路径的检查，并在慢速路径上依赖于两级影子内存。

### 实现

大部分内存检测工具都基于二进制文件，这些工具可以发现堆内存的越界和 UAF，还可以识别未初始化的读取，不过没办法识别堆栈和全局变量的越界错误，好消息是基本不会误报。例如：Valgrind，Dr.Memory，Discover，BoundsChecker 等等

而使用编译时检测的工具虽然可以检测堆栈对象的越界访问，但是无法检测所有的堆栈缓冲区溢出错误，而且可能误报，例如 Mudflap。

还有一些依赖于静态分析的检测工具，但是只支持 C 语言，例如 CClured，还有不开源的，例如 Insure++。

还有一些内存检测工具基于专门的内存分配器，使用 CPU 页面保护。每个分配的区域都被放置到一个专用页面（或一组页面）中。右侧（和/或左侧）的额外一页被分配并标记为不可访问。随后访问这些页面的页面错误将被报告为越界错误。这些工具会产生大量内存开销，并且在 `malloc` 密集型应用程序上可能会非常慢（因为每个 `malloc` 调用都需要至少一个系统调用）。此外，这些工具可能会遗漏某些类别的错误（例如，从 5 字节的内存区域的开头读取偏移量为 6 处的内存）。如果工具报告出错误，错误消息中会提供负责的说明。例如：Electric Fence、Duma、GuardMalloc 和 Page Heap 等工具。

其他一些工具依赖于对 `malloc` 的实现，包括 DieHarder（DieHard malloc 的后代）和 Dmalloc，有概率、有延迟发现内存错误。他们修改后的 `malloc` 函数在返回给用户的内存区域的周围添加了*中毒红区*，并用特殊的 magic 值填充新分配的内存。 free 函数还将 magic 值写入内存区域。

但是这种依赖于 magic number 的实现有一些问题，当 magic number 被读取时，这些工具没办法立刻知道这件事情，现有的 DieHard 只能靠比较程序输出来检测不正确的行为，所以这个报错是概率性的、延迟性的；同理，当 redzone 里填充的 magic number 被覆盖，稍后在空闲时检查这个 redzone 会发现这件事情，但是这些工具没办法知道越界写入或者 UAF 是什么时候发生的（（... ~~对于 malloc 密集的大型程序这就相当于给你报了个“你的程序有一个错误”~~

还有个问题，debug malloc 工具不分析堆栈变量或者全局变量可能存在的内存错误。

现有的堆栈上的金丝雀保护其实只能防止攻击者利用缓冲区溢出劫持程序执行流，无法检测堆栈上的局部变量的越界访问。

## 0x03. AddressSanitizer Algorithm

AddressSanitizer 的内存检测方法类似于 Valgrind 的工具 AddCheck，仍然使用影子内存来记录应用程序的每个字节，通过对比来确定程序可能存在的各种内存溢出问题。不过前者更加高效、快速，而且可以检测堆栈、堆和全局变量中的溢出错误。

### Shadow Memory

AddressSanitizer 的主要原理是对程序中的虚拟内存提供粗粒度的影子内存（每 8 个字节的内存对应 1 个字节的影子内存）。

具体来说，由于 `malloc()` 分配的内存空间一般是 8 字节对齐的，通过分析这 8 个字节各自的可访问性，一共有 9 个状态。这 9 个状态可以放在影子内存的 1 个字节内。

AddressSanitizer 依然使用直接缩放和偏移的方案，即将 1/8 的虚拟地址空间专用于其影子内存，并使用映射将剩余 7/8 的地址映射到 1/8 上。给定应用程序内存地址 Addr，影子字节的地址计算为 `(Addr >> 3) + Offset`，这里的 `Offset` 是必须为每个平台静态选择的（与 Umbra 的完全动态不同）。

影子内存中每个字节存取一个数字 k，如果 k = 0，则表示该影子内存对应的 8 个字节的内存都能访问；如果 k 在 0 到 7 之间，表示前 k 个字节可以访问；如果 k 为负数，表示这 8 个字节不可寻址，不同的数字表示不同的不可寻址的类型（e.g. Stack buffer overflow, Heap buffer overflow)。具体的映射策略如下图所示。

x64: `Shadow = (Mem >> 3) + 0x7fff8000;`

|     起始地址    |      结束地址   |  对应区段    |
| -------------- | -------------- | --------- | 
| 0x10007fff8000 | 0x7fffffffffff | HighMem    |         
| 0x02008fff7000 | 0x10007fff7fff |	HighShadow |  
| 0x00008fff7000 | 0x02008fff6fff |	ShadowGap  |
| 0x00007fff8000 | 0x00008fff6fff |	LowShadow  |
| 0x000000000000 | 0x00007fff7fff |	LowMem     |

x32: `Shadow = (Mem >> 3) + 0x20000000;`

|     起始地址    |      结束地址   |  对应区段    |
| -------------- | -------------- | --------- | 
| 0x40000000 | 0xffffffff |	HighMem |
| 0x28000000 | 0x3fffffff |	HighShadow |
| 0x24000000 | 0x27ffffff |	ShadowGap |
| 0x20000000 | 0x23ffffff |	LowShadow |
| 0x00000000 | 0x1fffffff |	LowMem |

### 实现

在读写内存前，会对要读写的内存对应的影子内存的内容进行检查。

8 字节全部可读写：

```c
ShadowAddr = (Addr >> 3) + Offset;
if (*ShadowAddr != 0)
	ReportAndCrash(Addr);
```

1-，2-，4- 字节访问时，我们需要把 k 和 Addr 的低 3 字节进行比较

```c
ShadowAddr = (Addr >> 3) + Offset;
k = *ShadowAddr;
if (k != 0 && ((Addr & 7) + AccessSize > k))
	ReportAndCrash(Addr);
```

将 AddressSanitizer 检测放置在 LLVM 优化流程的最末端。通过这种方式，我们仅检测那些在 LLVM 优化器执行的所有标量和循环优化中“幸存”下来的内存访问。例如，对由 LLVM 优化掉的本地堆栈对象的内存访问将不会被检测。同时，我们不必检测 LLVM 代码生成器生成的内存访问（例如，寄存器溢出）。错误报告代码（`ReportAndCrash(Addr)`）最多执行一次，但在代码中插入了很多地方，因此必须紧凑一些。

### 运行时

运行时库的主要目的是管理影子内存。在应用程序启动时，整个阴影区域都会被映射，以便程序的其他部分无法使用它。影子内存的 Bad 段始终受到保护。

`malloc` 和 `free` 函数被专门的实现所取代。`malloc` 函数在返回区域周围分配额外的 redzone。红区被标记为不可寻址或中毒。红区越大，检测到的上溢或下溢就越大。分配器内的内存区域被组织为与一系列对象大小相对应的空闲列表数组。当与用户所请求的内存块大小相对应的空闲内存块为空时，将从操作系统分配一组带有其红区的内存区域（例如 mmap）。对于 n 个区域，我们分配 n + 1 个红区，这样一个区域的右红区通常是另一个区域的左红区：

```
+—————————+
| redzone |
+—————————+
|   mem   |
+—————————+
| redzone |
+—————————+
|   mem   |
+—————————+
| redzone |
+—————————+
```

这个思路非常简单，通过 redzone 可以防止上溢和下溢。

此外，左边的 redzone 用于存储分配器的内部数据（如分配大小、线程 ID 等）；因此，红区的最小大小当前为 32 字节。该内部数据不会被缓冲区下溢损坏，因为这种下溢是在实际存储读写之前立即检测到的。

```c
struct ChunkHeader {
  // 1-st 8 bytes.
  u32 chunk_state       : 8;  // Must be first.
  u32 alloc_tid         : 24;
  u32 free_tid          : 24;
  u32 from_memalign     : 1;
  u32 alloc_type        : 2;
  u32 rz_log            : 3;
  u32 lsan_tag          : 2;
  // 2-nd 8 bytes
  // This field is used for small sizes. For large sizes it is equal to
  // SizeClassMap::kMaxSize and the actual size is stored in the
  // SecondaryAllocator's metadata.
  u32 user_requested_size : 29;
  // align < 8 -> 0
  // else      -> log2(min(align, 512)) - 2
  u32 user_requested_alignment_log : 3;
  u32 alloc_context_id;
};
```

free 函数也被 hook 了，它会标记整个内存区域为“中毒状态”并将其隔离，这样该区域就不会很快被 ptmalloc 拿去分配。目前，隔离区以 FIFO 队列的形式实现，该队列随时保存固定数量的内存。

默认情况下，`malloc` 和 `free` 会记录当前的调用堆栈，以便提供更多信息丰富的错误报告。`malloc` 调用堆栈存储在它左侧的 redzone 中（redzone 越大，可存储的帧数越大），而 `free` 调用堆栈存储在内存区域本身的开头。

### 局部和全局变量

为了检测对全局变量和堆栈对象的越界访问，AddressSanitizer 必须在此类对象周围创建中毒红区。对于全局变量，红区是在编译时创建的，红区的地址在应用程序启动时传递到运行时库。运行时库函数会标记红区并记录地址以供进一步的错误报告。对于堆栈对象，红区是在运行时创建并中毒的。

比如：

```c
void foo() {
	char a[10];
	// <your function>
	return;
}
```

会被优化成：

```c
void foo() {
	char rz1[32];
	char a[10];
	char rz2[32-10+32];
	unsigned *shadow = (unsigned*) (((long)rz1 >> 8) + Offset); // poison the redzones around arr.
	shadow[0] = 0xffffffff; // rz1
	shadow[1] = 0xffff0200; // arr and rz2
	shadow[2] = 0xffffffff; // rz2
	// un-poison all.
	shadow[0] = shadow[1] = shadow[2] = 0;
}
```

### 准确性

理论上，asan 不会产生 false positive（误报），但是会存在 false negative（遗漏），下面结合具体例子进行说明。

- 首先，如果越界访问跳的特别远，越过了红区的话，那就测不出来；
- 其次，如果在“释放”和后续使用之间分配和释放了大量内存，导致最开始释放的 chunk 已经被复用了，则可能无法检测到 UAF。
- 再者，如果对于未对齐的字节进行读写，也可能导致测不出来，这个其实有办法解决，但是会导致快速路径变慢。

### 线程安全

AddressSanitizer 是线程安全的。

仅当相应的应用程序内存不可访问时（在 `malloc` 或 `free` 期间、创建或销毁栈帧期间、模块初始化期间），影子内存才会被修改。对影子内存的所有其他访问都是读取，`malloc` 和 `free` 函数使用线程的本地缓存来避免每次调用时锁定（正如大多数现代 `malloc` 实现所做的那样）。如果原始程序在内存访问和删除内存之间存在竞争，AddressSanitizer 有时可能会将其检测为 UAF 错误，但不保证如此。

asan 会记录每个 `malloc` 和 `free` 的线程 ID，并与线程创建调用堆栈一起在错误消息中报告。


## 总结

传统观点认为，影子内存要么通过多级映射方案产生高开销，要么通过占用大的连续区域来施加过高的地址空间要求。这个新颖的阴影状态的算法充分减少了影子内存的空间占用，使我们可以使用简单的映射，并且可以以较低的开销实现需求。

## Bypassing AddressSanitizer

显而易见的是，ASan 的检查很大一部分是基于影子内存中，此时影子内存的 k 值。假设如果全段影子内存的 k 全为0，我们就可以完全无视掉 ASan，而 2019 年 0ctf 的 babyaegis，正是给了一个写 0 的机会，给了我们一次对一个指针再次读写的机会。

另外，还有几种方法，例如

Adjacent Buffers in the Same Struct/Class:

```c
#include <stdio.h>
#include <stdlib.h>
class Test{
public:
	Test(){
		 command[0] = 'l';
		 command[1] = 's';
		 command[2] = '\0';
	}
	void a(){
	 scanf("%s", buffer);
	 system(command);
	}
private:
	char buffer[10];
	char command[10];
};
int main(){
	Test aTest = Test();
	aTest.a();
}
```

```bash
$ g++ -O -g -fsanitize=address test1.c
clang: warning: treating 'c' input as 'c++' when in C++ mode, this behavior is deprecated [-Wdeprecated]

$ ./a.out
aaaaaaaaaa/bin/sh;
sh-3.2$ id
uid=1000(flower) gid=1000(flower) 组=1000(flower),950(mihomo),986(uucp),994(input),998(wheel)
```

还可以参考文献：[Bypassing AddressSanitizer](https://dl.packetstormsecurity.net/papers/general/BreakingAddressSanitizer.pdf).