本文环境为 x86-64，32 位太老了就不学了。

## 前置知识

简单回顾一下 ELF 文件格式，具体的看 [[ELF 文件结构详解]]


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


