# arm64 内核中 “PTE 物理地址固定” 的源码级分析、KSMA 视角与 2026 年修复方向

## 背景

这份笔记抛开某一道具体题目的利用链，只讨论一个更一般的内核问题：

- 为什么在某些 arm64 Linux 启动布局里，负责 kernel text 或其他关键内核映射的页表页会表现出低熵、可预测，甚至在同一 handout/boot flow 下几乎固定的物理地址。
- 为什么这类现象可以用 KSMA 风格的思路来理解。
- 到 2026 年，上游和研究界针对这类问题正在怎么修。

结论先说：

1. 这不是 “arm64 天生不会随机化 PTE 物理地址”。
2. 这也不是 “KASLR 完全失效”。
3. 根因通常是：早期 kernel page tables 属于 early boot 产物，它们的分配路径、布局和消费顺序熵很低。
4. KSMA 的价值在于指出：相比随机化后的 kernel object，更值得打的是这种低熵的页表控制面。

## 不该怎么理解

### 不是 arm64 架构保证 PTE 物理地址固定

arm64 硬件只要求：

- `TTBR0/TTBR1` 指向页表根。
- 页表项按格式提供下一层页表或最终页框的物理地址。
- CPU 按页表格式做地址翻译。

硬件并不规定：

- 某张页表页必须放在哪个物理页。
- 某级页表页必须稳定不变。
- 内核必须对这些页表页做随机化。

所以 “PTE 物理地址固定” 是内核启动实现和内存分配路径的问题，不是 ARM64 ISA 的硬约束。

### 也不是 KASLR 自动覆盖了页表页随机化

arm64 的 `CONFIG_RANDOMIZE_BASE=y` 随机的是 kernel image 的虚拟装载偏移，即 kernel text 在高半区的虚拟基址。它不等于：

- kernel image 物理基址随机化；
- early page tables 物理位置随机化；
- linear map alias 随机化；
- 负责特定 text 页的 leaf PTE page 随机化。

所以出现 “kernel VA 每轮变化，但负责这段映射的 PTE page 仍然稳定” 是完全可能的。

## 源码级根因：为什么早期页表低熵

下面以 Linux arm64 `v7.0.3` 为例说明。比赛定制内核可能是 `-dirty` 变体，但这一部分的架构逻辑与上游基线是对得上的。

### 1. arm64 的 kernel mappings 由 `swapper_pg_dir` 负责

arm64 官方内存布局文档说明：

- `TTBR1` 用于 kernel/global mappings。
- `swapper_pg_dir` 是内核全局页表根。
- kernel 还拥有固定的 linear map 区域。

这意味着：如果攻击者能定位并修改 kernel mappings 对应的页表结构，就可能绕过对随机化后内核对象地址的直接依赖。

## 2. 线性映射与物理基址的关系由 `memory.h` 和 `init.c` 决定

`arch/arm64/include/asm/memory.h` 定义了：

- `PAGE_OFFSET`
- `PAGE_END`
- `KIMAGE_VADDR`
- `DIRECT_MAP_PHYSMEM_END`

这些宏决定了 kernel linear map 在虚拟地址空间中的位置。

`arch/arm64/mm/init.c` 的 `arm64_memblock_init()` 则根据 `memblock_start_of_DRAM()` 和对齐规则计算 `memstart_addr`，也就是 linear map 对应的物理起点。

因此，`phys -> direct map virtual alias` 的转换不是随机发生的，而是早期内核按固定规则建立的。

## 3. 早期页表页来自 `memblock`，不是运行期随机分配

最关键的点在 `arch/arm64/mm/mmu.c`：

```c
static phys_addr_t __init early_pgtable_alloc(enum pgtable_type pgtable_type)
{
    phys_addr_t phys;

    phys = memblock_phys_alloc_range(PAGE_SIZE, PAGE_SIZE, 0,
                                     MEMBLOCK_ALLOC_NOLEAKTRACE);
    if (!phys)
        panic("Failed to allocate page table page\n");

    return phys;
}
```

这说明 early page-table pages 是通过 `memblock_phys_alloc_range()` 分配的：

- 分配发生在 early boot；
- 分配器是 `memblock`；
- 不是后期普通 buddy allocator；
- 不受普通运行期页分配扰动的主要影响。

如果平台、DRAM 起点、kernel 物理装载方式和 early boot 顺序都固定，那么这里产出的页表页物理地址往往也会稳定。

## 4. `init_pg_dir` 附近的页表页按顺序被消费

`arch/arm64/kernel/pi/map_kernel.c` 里，`map_kernel()` 有一个极关键的初始化：

```c
phys_addr_t pgdp = (phys_addr_t)init_pg_dir + PAGE_SIZE;
```

后面 `map_segment()`/`map_range()` 会用这个游标继续为：

- `_text`
- `_stext`
- `_etext`
- `rodata`
- `inittext`
- `data`

等区域建立早期映射。

这说明：

1. `init_pg_dir` 本身是一块早期静态页表区域的起点；
2. lower-level page tables 紧跟在后面顺序占用；
3. kernel image 的映射页表不是“临时随机散落”在内存里，而是早期按确定性顺序构造出来的。

如果某个 handout 中：

- RAM 基址固定；
- `-kernel Image` 物理装载方式固定；
- 内核镜像物理基址固定；
- 没有额外的 early random padding；

那么负责某一段 kernel text 的 leaf PTE page 极容易成为低熵目标。

## 5. 常规映射建立阶段继续沿用这套早期布局

`arch/arm64/mm/mmu.c` 里的 `paging_init()` 会调用 `map_mem(swapper_pg_dir)`。

而 `map_mem()` 会：

- 遍历 memblock 记录的所有 DRAM bank；
- 建立 linear map；
- 对 kernel text/rodata 区域做特别处理，避免 writable alias。

因此，负责 kernel text 的那张 leaf PTE page 并不是利用运行中被“随机新建”的，而是启动阶段按确定性路径建立并保留下来的结构。

## KSMA 视角：为什么页表目标比随机化后的对象更值得打

### KSMA 的一般思想

KSMA 的核心直觉不是某个 magic 地址，而是一个目标选择原则：

**不要优先盯着被 KASLR 随机化的 kernel object 本体，而要优先盯着控制这些对象如何被映射、如何被解释的页表元数据。**

这是因为：

- kernel object 的虚拟地址通常需要 leak；
- 盲写对象容易崩；
- 一次弱写原语改对象本体，收益有限；
- 改页表，收益是整个虚拟页的映射语义变化。

### 为什么这能解释 “PTE 物理地址固定”

经典 KSMA 和相关防御补丁关注的是：

- `swapper_pg_dir`
- `init_pg_dir`
- `tramp_pg_dir`
- 早期 static/boot page tables

之所以关注这些对象，是因为它们 historically 低熵、可预测，而且常常靠近内核镜像或其他早期静态布局。

所以当一个具体环境里出现：

- kernel VA KASLR 生效；
- 但某张 text-mapping leaf PTE page 的物理地址可预测；

这并不是与 KSMA 无关，反而正体现了 KSMA 的判断：**真正该打的不是随机化后的 `cap_capable`、`cred`、函数指针，而是控制这些地址翻译的页表控制面。**

### 这类题型与经典 KSMA 的差别

经典 KSMA 常见做法是：

- 在更高层页表里做镜像；
- 构造新的可利用映射；
- 绕过 W^X / KASLR / 访问隔离。

而很多 CTF 化利用更干净：

- 不构造新映射；
- 直接改一个 leaf PTE；
- 把某个关键 kernel VA page 重定向到另一张同页内偏移的代码页；
- 用 “换页不换偏移” 的方式劫持语义。

它们共享的根因是一样的：页表页低熵、可预测、而且比随机化后的对象有更高杠杆。

## 为什么一些 handout 里它会表现成“固定”

当下面几个条件同时成立时，“某张 leaf PTE page 每轮 boot 固定”并不奇怪：

1. 机器模型固定，例如 QEMU `virt`。
2. RAM 起点固定。
3. 用 `-kernel Image` 直载，kernel image 物理落点固定。
4. 早期 `memblock` 分配顺序固定。
5. `init_pg_dir + PAGE_SIZE` 后续的 lower-level page-table consumption 顺序固定。
6. 没有在 boot 后重建 text-mapping page tables。

这时即便 kernel text 的虚拟基址被 KASLR 随机化，攻击者仍可能：

1. 通过已知的 image 物理布局或页表层级关系，定位负责某段 text 映射的 leaf PTE page；
2. 通过 arm64 direct map 的固定别名把这个物理地址换算成可写的 kernel virtual alias；
3. 直接写那项 PTE。

因此，“PTE 地址固定”本质上是：

- early boot page-table placement 的低熵；
- image physical layout 的低熵；
- direct map 规则的确定性；

三者组合后的结果。

## 2026 年的修复方向

到 2026 年，这类问题的修复已经不再只是“把 `swapper_pg_dir` 藏起来”这么简单，而是向两个方向发展。

### 方向一：降低页表位置可预测性

目标是让攻击者更难从：

- 固定 image PA
- 固定 early page-table layout
- 固定 direct map

直接算出页表页位置。

可行手段包括：

1. boot 后重建关键映射的 page tables  
   例如为 kernel text 重新分配新的 leaf PTE pages，把旧页表内容拷过去，切换上级表项，再 flush TLB。

2. 让 kernel image 物理落点不固定  
   如果启动器支持 image PA 随机化，负责该段映射的 early PT layout 也会更不稳定。

3. 对 early page-table 区域加入额外随机 padding 或 relocation  
   本质上是提升 early page-table placement 的熵。

### 方向二：保护页表完整性，即便地址被知道也不能直接改

这是更关键的方向，因为真实攻击者往往不怕多做一个 leak。

主要思路：

1. 将 page-table pages 在线性映射中的别名设为只读。
2. 只允许通过专用 helper/fixmap/受控修改路径写页表。
3. 对 early page tables 做额外只读或隔离保护。
4. 使用 arm64 正在推进的 `kpkeys hardened page tables` 之类机制，减少任意内核写直接落到页表上的机会。

### 为什么只修“固定”不够

如果只是把那张 leaf PTE page 从一个固定地址迁到另一个随机地址：

- 没有 leak 时，利用确实变难；
- 但只要未来有了 leak，仍然可以继续改页表。

所以更稳妥的做法是双修：

1. 降低页表页的可预测性；
2. 让 direct map 或其他别名不再允许任意写直接落到页表上。

## 对题外分析最有价值的几个结论

### 1. “arm64 不随机 PTE 地址” 这个说法不严谨

更准确的说法是：

**主流 Linux/arm64 默认不会把 early kernel page tables 当成一个强随机化对象来保护。**

### 2. “KASLR 生效” 不等于 “页表结构也高熵”

kernel text 的虚拟基址变化，不能推出：

- image 物理地址变化；
- leaf PTE page 物理地址变化；
- direct map alias 变化。

### 3. KSMA 的真正启发是目标选择

KSMA 最值得借鉴的不是某个固定技巧，而是这个判断：

**弱写原语优先打 low-entropy page-table metadata，而不是 high-entropy randomized kernel objects。**

### 4. 真正的修复应该兼顾可预测性和完整性

只让页表更难算出来，不能彻底解决问题。  
只把顶层 `swapper_pg_dir` 只读，也未必能挡住更低层 leaf PTE page。  
需要针对：

- `init_pg_dir`
- `swapper_pg_dir`
- `tramp_pg_dir`
- leaf page-table pages
- linear-map writable alias

整体考虑。

## 参考资料

### 本地环境信息

- 内核版本字符串：`Linux version 7.0.3-actf-mali-dirty`
- `.config` 中启用了 `CONFIG_RANDOMIZE_BASE=y`
- `.config` 中使用 `CONFIG_ARM64_4K_PAGES=y`

### 官方文档与源码

- arm64 memory layout 文档  
  https://www.kernel.org/doc/html/v5.19/arm64/memory.html
- `arch/arm64/include/asm/memory.h`  
  https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/arm64/include/asm/memory.h?h=v7.0.3
- `arch/arm64/mm/init.c`  
  https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/arm64/mm/init.c?h=v7.0.3
- `arch/arm64/mm/mmu.c`  
  https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/arm64/mm/mmu.c?h=v7.0.3
- `arch/arm64/kernel/pi/map_kernel.c`  
  https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/tree/arch/arm64/kernel/pi/map_kernel.c?h=v7.0.3

### KSMA / arm64 相关讨论与修复方向

- arm64 早期关于 KSMA 可预测页表的讨论  
  https://www.spinics.net/lists/arm-kernel/msg656958.html
- 引入 `init_pg_dir`、降低 `swapper_pg_dir` 暴露面的讨论  
  https://www.spinics.net/lists/arm-kernel/msg660769.html
- 将 `swapper_pg_dir` 放入 `.rodata`、保护早期页表的讨论  
  https://www.spinics.net/lists/arm-kernel/msg672198.html
- 2026 年围绕 hardened early page tables / kpkeys 的讨论  
  https://www.spinics.net/lists/kernel/msg6068770.html
  https://www.spinics.net/lists/kernel/msg6068771.html

## 一句话总结

arm64 里 “PTE 物理地址固定” 不是架构必然，而是 early boot page-table placement 的低熵表现；KSMA 的意义在于告诉你，这类低熵页表控制面往往比随机化后的内核对象更值得攻击；到 2026 年，合理修复已经转向“双修”策略：既降低早期页表可预测性，也强化页表本身的写保护。
