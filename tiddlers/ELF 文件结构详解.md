## 简介

**本文在不特殊声明的情况下，默认架构为 x86-64，操作系统内核为 linux**

ELF（Executable and Linkable Format） 是 linux 平台上的目标文件，主要有以下三种类型：

- 可重定位文件（Relocatable File），后缀名 `.o`，这种文件一般和其他目标文件一起被链接器链接成**可执行文件**或者**共享目标文件**
- 可执行文件（Executable File），一般无后缀名，就是我们平常在 linux 中可以运行的程序
- 共享目标文件（Shared Object File），后缀名 `.so`，就是我们常说的“库文件”


ELF 的文件结构如下图所示：

![ELF文件结构](https://pic1.imgdb.cn/item/682b1ea858cb8da5c8fc750b.png)

这是一张很经典的用来讲解 ELF 文件结构的图，ELF 文件结构主要是从两方面解析：执行视图和链接视图。从 ELF 文件的全名也可看出，一个合法的 ELF 文件既有可能参与链接，也有可能直接执行。

## 文件结构

### 宏观视图

**链接视图**

![](https://pic1.imgdb.cn/item/682b1f6658cb8da5c8fc7708.png)

1. 文件开始处是 ELF Header
2. 接下来是程序头部表，不过在链接视图下（也就是 ELF 文件参与链接时），这个部分是可选的
3. 若干个节区（Section，简称“节”）
4. 节区头部表，包含了描述文件节区的信息，每个节区在表中都有一个表项，会给出节区名称、节区大小等信息。用于链接的目标文件必须有节区头部表。

**执行视图**

![](https://pic1.imgdb.cn/item/682b201758cb8da5c8fc79a7.png)

1. 文件开始处是 ELF Header
2. 程序头部表，它会告诉系统如何创建进程。用于生成进程的目标文件必须具有程序头部表。
3. 若干个段
4. 节区头部表，这个部分是可选的。

注意，所谓“链接视图”和“执行视图”其实是看待 ELF 文件的两种不同的视角，实际上在一个合法的 ELF 文件中，二者是完全重合的，也就是本文第一张图。

我们把上面两种视图结合起来分析，其实 sections 和 segments 在 ELF 中占用的是一样的地方，其中，sections 是程序员可见的，是给**链接器**使用的概念，而 segments 是程序员不可见的，是给**加载器**使用的概念。一般来讲，**一个 segement 可以包含多个 sections**

另外，尽管这些图中是按照 ELF 头，程序头部表，节区，节区头部表的顺序排列的，但实际上**除了 ELF 头部表以外，其它部分都没有严格的的顺序**。

### 数据结构

这部分可以直接参考 elf.h 里的源码。

```c
/* 32-bit ELF base types. */
typedef __u32	Elf32_Addr;    // unsigned int
typedef __u16	Elf32_Half;    // unsigned short
typedef __u32	Elf32_Off;     // unsigned int
typedef __s32	Elf32_Sword;   // __signed__ int 
typedef __u32	Elf32_Word;    // unsigned int

/* 64-bit ELF base types. */
typedef __u64	Elf64_Addr;    // unsigned long long
typedef __u16	Elf64_Half;    // unsigned short
typedef __s16	Elf64_SHalf;   // __signed__ short
typedef __u64	Elf64_Off;     // unsigned long long
typedef __s32	Elf64_Sword;   // __signed__ int
typedef __u32	Elf64_Word;    // unsigned int
typedef __u64	Elf64_Xword;   // unsigned long long
typedef __s64	Elf64_Sxword;  // __signed__ long long
```

很清楚了。


### ELF Header

源码如下

```c
#define EI_NIDENT	16

typedef struct elf32_hdr {
  unsigned char	e_ident[EI_NIDENT];
  Elf32_Half	e_type;
  Elf32_Half	e_machine;
  Elf32_Word	e_version;
  Elf32_Addr	e_entry;  /* Entry point */
  Elf32_Off	e_phoff;
  Elf32_Off	e_shoff;
  Elf32_Word	e_flags;
  Elf32_Half	e_ehsize;
  Elf32_Half	e_phentsize;
  Elf32_Half	e_phnum;
  Elf32_Half	e_shentsize;
  Elf32_Half	e_shnum;
  Elf32_Half	e_shstrndx;
} Elf32_Ehdr;

typedef struct elf64_hdr {
  unsigned char	e_ident[EI_NIDENT];	/* ELF "magic number" */
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr e_entry;		/* Entry point virtual address */
  Elf64_Off e_phoff;		/* Program header table file offset */
  Elf64_Off e_shoff;		/* Section header table file offset */
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
} Elf64_Ehdr;
```

以 64 位架构为例分析一下：


| 字段名   | 解释                                                                               | 字节数 |
| ----------- | ------------------------------------------------------------------------------------ | ------ |
| e_ident     | ELF的一些标识信息，固定值                                                 | 16     |
| e_type      | 目标文件类型：1-可重定位文件，2-可执行文件，3-共享目标文件 | 2      |
| e_machine   | 文件的目标系统架构                                                          | 2      |
| e_version   | 目标文件版本：1-当前版本                                                  | 4      |
| e_entry     | 程序入口的虚拟地址，没有可为0                                          | 8      |
| e_phoff     | 程序头表(segment header table)的偏移量，没有可为0                       | 8      |
| e_shoff     | 节区头表(section header table)的偏移量，没有可为0                       | 8      |
| e_flags     | 与文件相关的，特定于处理器的标志                                     | 4      |
| e_ehsize    | ELF头部的大小，单位字节                                                    | 2      |
| e_phentsize | 程序头表每个表项的大小，单位字节                                     | 2      |
| e_phnum     | 程序头表表项的个数                                                          | 2      |
| e_shentsize | 节区头表每个表项的大小，单位字节                                     | 2      |
| e_shnum     | 节区头表表项的数目                                                          | 2      |
| e_shstrndx  | 某些节区中包含固定大小的项目，如符号表。对于这类节区，此成员给出每个表项的长度字节数 | 2      |


### program header table

```c
/* These constants define the permissions on sections in the program
   header, p_flags. */
#define PF_R		0x4
#define PF_W		0x2
#define PF_X		0x1

typedef struct elf32_phdr {
  Elf32_Word	p_type;
  Elf32_Off	p_offset;
  Elf32_Addr	p_vaddr;
  Elf32_Addr	p_paddr;
  Elf32_Word	p_filesz;
  Elf32_Word	p_memsz;
  Elf32_Word	p_flags;
  Elf32_Word	p_align;
} Elf32_Phdr;

typedef struct elf64_phdr {
  Elf64_Word p_type;        /* 段类型 */
  Elf64_Word p_flags;       /* 段的权限标记 */
  Elf64_Off p_offset;		/* 从文件开始到该段开头的第一个字节的偏移 */
  Elf64_Addr p_vaddr;		/* 该段第一个字节在内存中的虚拟地址 */
  Elf64_Addr p_paddr;		/* 该字段仅用于物理地址寻址相关的系统中 */
							/* 由于”System V”忽略了应用程序的物理寻址 */
							/* 可执行文件和共享目标文件的该项内容并未被限定 */
  Elf64_Xword p_filesz;		/* 文件镜像中该段的大小，可能为0 */
  Elf64_Xword p_memsz;		/* 内存镜像中该段的大小，可能为0 */
  Elf64_Xword p_align;		/* 可加载的程序的段的 p_vaddr 以及 p_offset 的大小必须是 page 的整数倍。该成员给出了段在文件以及内存中的对齐方式。如果该值为 0 或 1 的话，表示不需要对齐。除此之外，p_align 应该是 2 的整数指数次方，并且 p_vaddr 与 p_offset 在模 p_align 的意义下，应该相等。 */
} Elf64_Phdr;
```

依然是以 x64 为例，对于执行视图下的 ELF 文件，它的程序头表记录了程序的所有段，每个记录有 8 个属性，对于这 8 种属性的介绍可以看注释。

关于段的类型，下面是一些常见类型的介绍：

- PHDR：保存程序头表
- INTERP：此类型段给出了一个以 NULL 结尾的字符串的位置和长度，该字符串将被当作解释器调用。这种段类型仅对可执行文件有意义（也可能出现在共享目标文件中）。此外，这种段在一个文件中最多出现一次。而且这种类型的段存在的话，它必须在所有可加载段项的前面。
- LOAD：此类型段为一个可加载的段，大小由 p_filesz 和 p_memsz 描述。文件中的字节被映射到相应内存段开始处。如果 p_memsz 大于 p_filesz，“剩余”的字节都要被置为0。p_filesz 不能大于 p_memsz。可加载的段在程序头部中按照 p_vaddr 的升序排列。
- DYNAMIC：段保存了由动态链接器（即，INTERP中指定的解释器）使用的信息。
- NOTE：保存了专有信息。

此外，还有一些名称为 GNU_STACK、GNU_EH_FRAME、GNU_RELRO 的段。

关于段的内容，由于一个段可以包含多个节区，所以详见下一节。

一个小细节：通常情况下，没有被初始化的数据在段的尾部，因此，p_memsz 才会比 p_filesz 大。

### section header table

```c
/* sh_type */
#define SHT_NULL	0               // 非活动的，这种类型的节头中的其它成员取值无意义。
#define SHT_PROGBITS	1           // 包含程序定义的信息，它的格式和含义都由程序来决定。
#define SHT_SYMTAB	2               // 符号表
#define SHT_STRTAB	3               // 字符串表
#define SHT_RELA	4               // 包含显式指定位数的重定位项，目标文件可以有多个重定位节
#define SHT_HASH	5               // 符号哈希表
#define SHT_DYNAMIC	6               // 动态链接的信息
#define SHT_NOTE	7               // 包含以某种方式标记文件的信息
#define SHT_NOBITS	8               // 不占用文件的空间的节区，其它方面和SHT_PROGBITS相似
#define SHT_REL		9               // 包含重定位表项，不过没有显式指定位数
#define SHT_SHLIB	10              // 保留节区，语义未定义
#define SHT_DYNSYM	11              // 完整的符号表，可能包含很多对动态链接不必要的符号。目标文件可以包含一个 SHT_DYNSYM 节区，其中保存动态链接符号的一个最小集合，以节省空间。
#define SHT_NUM		12              // 没找到资料。。。
#define SHT_LOPROC	0x70000000
#define SHT_HIPROC	0x7fffffff
#define SHT_LOUSER	0x80000000
#define SHT_HIUSER	0xffffffff

/* sh_flags */
#define SHF_WRITE		0x1
#define SHF_ALLOC		0x2                  // 该部分在进程执行期间占用内存
#define SHF_EXECINSTR		0x4                
#define SHF_RELA_LIVEPATCH	0x00100000
#define SHF_RO_AFTER_INIT	0x00200000
#define SHF_MASKPROC		0xf0000000

/* special section indexes */
#define SHN_UNDEF	0
#define SHN_LORESERVE	0xff00
#define SHN_LOPROC	0xff00
#define SHN_HIPROC	0xff1f
#define SHN_LIVEPATCH	0xff20
#define SHN_ABS		0xfff1
#define SHN_COMMON	0xfff2
#define SHN_HIRESERVE	0xffff
 
typedef struct elf32_shdr {
  Elf32_Word	sh_name;
  Elf32_Word	sh_type;
  Elf32_Word	sh_flags;
  Elf32_Addr	sh_addr;
  Elf32_Off	sh_offset;
  Elf32_Word	sh_size;
  Elf32_Word	sh_link;
  Elf32_Word	sh_info;
  Elf32_Word	sh_addralign;
  Elf32_Word	sh_entsize;
} Elf32_Shdr;

typedef struct elf64_shdr {
  Elf64_Word sh_name;		/* Section name, index in string tbl */
  Elf64_Word sh_type;		/* Type of section */
  Elf64_Xword sh_flags;		/* Miscellaneous section attributes */
  Elf64_Addr sh_addr;		/* Section virtual addr at execution */
  Elf64_Off sh_offset;		/* Section file offset */
  Elf64_Xword sh_size;		/* Size of section in bytes */
  Elf64_Word sh_link;		/* Index of another section */
  Elf64_Word sh_info;		/* Additional section information */
  Elf64_Xword sh_addralign;	/* Section alignment */
  Elf64_Xword sh_entsize;	/* Entry size if section holds table */
} Elf64_Shdr;
```

以 64 位 ELF 为例，节头表的每个字段的含义和取值范围以及对应取值的含义都可以看注释。


### Sections and Segements


在链接视图下，节区包含目标文件中除了 ELF 头部、程序头部表、节区头部表的所有信息，而加载视图下，段可以细分为多个节区，所以这里把节区（下文简称的节都是指节区）和段放在一起讲。

首先看节，对于一个合法的节，满足以下条件：
- 每个节区都有对应的节头来描述它。但是反过来，节区头部并不一定会对应着一个节区。
- 每个节区在目标文件中是连续的，但是大小可能为 0。
- 任意两个节区不能重叠，即一个字节不能同时存在于两个节区中。
- 目标文件中可能会有闲置空间（inactive space），各种头和节不一定会覆盖到目标文件中的所有字节，闲置区域的内容未指定。

注意：
- 以 “.” 开头的节区名称是系统保留的，由于节是对程序员可见的（一开始就提到过），所以应用程序也可以自己注册节区。为了避免与系统节区冲突，应用程序应该尽量使用没有前缀的节区名称。
- 目标文件格式可以包含多个名字相同的节区。
- 保留给处理器体系结构的节区名称一般命名规则为：处理器体系结构名称简写+ 节区名称。其中，处理器名称应该与 e_machine 中使用的名称相同。例如 .FOO.psect 节区是 FOO 体系结构中的 psect 节区。

一些比较常见的节的介绍如下：
- .bss：这个节保存的是未初始化的全局定义。根据定义，当程序开始运行时，系统会将这些数据初始化为零。该部分的类型为 SHT_NOBITS。属性类型为 SHF_ALLOC 和 SHF_WRITE。
- .data：这个节保存初始化数据，用于生成程序的内存。该部分的类型为 SHT_PROGBITS。属性类型为 SHF_ALLOC 和 SHF_WRITE。
- .dynamic：该部分包含动态链接信息。该部分的属性包括 SHF_ALLOC 位。是否设置 SHF_WRITE 位取决于处理器。该部分的类型为 SHT_DYNAMIC。
- .dynstr：该部分包含动态链接所需的字符串，最常见的是表示符号表项相关名称的字符串。该部分的类型为 SHT_STRTAB。使用的属性类型是 SHF_ALLOC。
- .dynsym：该部分保存动态连接符号表。该部分的类型为 SHT_DYNSYM。使用的属性是 SHF_ALLOC。
- .fini：该部分包含有助于进程终止代码的可执行指令。当程序正常退出时，系统会安排执行该部分的代码。该部分的类型为 SHT_PROGBITS。使用的属性是 SHF_ALLOC 和 SHF_EXECINSTR。
- .got：该部分包含全局偏移表。该部分的类型为 SHT_PROGBITS。其属性与处理器有关。
- .hash：该部分包含一个符号哈希表。该部分的类型为 SHT_HASH。使用的属性是 SHF_ALLOC。
- .init：这部分包含有助于进程初始化代码的可执行指令。当程序开始运行时，系统会在调用主程序入口点之前执行该部分的代码。该部分的类型为 SHT_PROGBITS。使用的属性是 SHF_ALLOC 和 SHF_EXECINSTR。
- .interp：该部分包含程序解释器的路径名。如果文件中有包含该部分的可加载段，则该部分的属性将包括 SHF_ALLOC 位。否则，就不会设置这个位。该部分的类型为 SHT_PROGBITS。
- .plt：该部分包含过程链接表（procedure linkage table）。该部分的类型为 SHT_PROGBITS。其属性与处理器有关。
- .rel(a)NAME：该部分包含重定位信息，如果文件有包含重定位的可加载段，该部分的属性将包括 SHF_ALLOC 位，否则就不会有。按照惯例，"NAME" 由被重定位的部分提供，例如 .text 的重定位部分通常称为 .rel(a).text。该部分的类型为 SHT_REL。
- .rodata：该部分保存只读数据，通常用于进程映像中的非写段。该部分的类型为 SHT_PROGBITS。使用的属性是 SHF_ALLOC。
- .shstrtab：该部分包含部分名称。该部分的类型为 SHT_STRTAB。不使用属性类型。
- .strtab：这部分存放字符串，最常见的是表示与符号表项相关名称的字符串。如果文件有一个包含符号字符串表的可加载段，该部分的属性将包括 SHF_ALLOC 位。否则，不会设置这个位。该部分的类型为 SHT_STRTAB。
- .symtab：该部分包含一个符号表。如果文件有一个包含符号表的可加载段，该部分的属性将包括 SHF_ALLOC 位，否则不会设置该位。该部分的类型为 SHT_SYMTAB。


这里重点说一下符号表、字符串表、重定位表等动态链接是经常使用的部分，一个经典的应用场景就是 [[ret2dlresolve 手法总结]]。

#### 字符串表

常见的字符串表有 .dynstr，.shstrtab 和 .strtab，其中：
- .dynstr：是动态字符串表，是动态符号表 .dynsym 的辅助节
- .shstrtab：是ELF文件的“目录索引”，用于定位各节的名称。
- .strtab：是静态字符串表，是静态符号表 .symtab 的辅助节。


#### 符号表

符号名是函数名和变量名的统称。

目标文件的符号表保存着定位和重新定位程序的符号定义和引用所需的信息。


```c
typedef struct elf32_sym {
  Elf32_Word	st_name;
  Elf32_Addr	st_value;
  Elf32_Word	st_size;
  unsigned char	st_info;
  unsigned char	st_other;
  Elf32_Half	st_shndx;
} Elf32_Sym;

typedef struct elf64_sym {
  Elf64_Word st_name;		/* 一个字符串表的索引值，如果为0说明符号没有名称 */
  unsigned char	st_info;	/* 指定符号的类型和绑定的属性 */
  unsigned char	st_other;	/* 定义了符号的可见性 */
  Elf64_Half st_shndx;		/* 每个符号表条目都与某个部分相关。该成员保存相关的段头表索引。 */
  Elf64_Addr st_value;		/* 相关符号的地址 */
  Elf64_Xword st_size;		/* 符号的大小 */
} Elf64_Sym;
```

注意到，32 位和 64 位下符号表的结构中成员是相同的，只是顺序不同。

常见的符号表包括：.symtab 和 .dynsym，这两个节都是我们常说的“符号表”，只不过前者在所有目标文件上都会存在，除非进行 strip 剥离，而后者只会出现在动态链接的目标文件上，且无法被剥离，这是因为后者在动态链接解析符号的过程中起到了非常关键的作用，如果被剥离程序将无法运行。


### 重定位表

重定位表包括 .rel 和 .rela，是将符号引用与符号定义连接起来的过程，在动态链接解析函数符号的过程中非常重要。

```c
/* The following are used with relocations */
#define ELF32_R_SYM(x) ((x) >> 8)
#define ELF32_R_TYPE(x) ((x) & 0xff)

#define ELF64_R_SYM(i)			((i) >> 32)
#define ELF64_R_TYPE(i)			((i) & 0xffffffff)

typedef struct elf32_rel {
  Elf32_Addr	r_offset;
  Elf32_Word	r_info;
} Elf32_Rel;

typedef struct elf64_rel {
  Elf64_Addr r_offset;	/* Location at which to apply the action */
  Elf64_Xword r_info;	/* index and type of relocation */
} Elf64_Rel;

typedef struct elf32_rela {
  Elf32_Addr	r_offset;
  Elf32_Word	r_info;
  Elf32_Sword	r_addend;
} Elf32_Rela;

typedef struct elf64_rela {
  Elf64_Addr r_offset;	/* Location at which to apply the action */
  Elf64_Xword r_info;	/* index and type of relocation */
  Elf64_Sxword r_addend;	/* Constant addend used to compute value */
} Elf64_Rela;
```


