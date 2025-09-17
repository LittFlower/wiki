使用条件：

1. 禁用了所有的 write 相关函数
2. 至少能使用 open 或 openat 打开文件
3. 程序没有关闭输出流

常见的零拷贝函数有 `sendfile`、`sendto`、`sendmsg`、`splice`，其中重点说一下 `splice`，这个函数的两端必须有一端是管道，不能全是文件描述符，因此必须和 `pipe` 配合。

poc 如下：

```c
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>

int main() {
    int file_fd;
    int pipe_fd[2];

    file_fd = open("flag.txt", O_RDONLY);

    if (pipe(pipe_fd) == -1) {
        close(file_fd);
        return 1;
    }

    // 第一次 splice: 从文件移动到管道的写入端
    // ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);
    if (splice(file_fd, NULL, pipe_fd[1], NULL, SSIZE_MAX, SPLICE_F_MOVE) == -1) {
        perror("[-] Error in first splice (file to pipe)");
        close(file_fd);
        close(pipe_fd[0]);
        close(pipe_fd[1]);
        return 1;
    }

    // 关闭写入端，否则第二次 splice 会一直阻塞等数据
    close(file_fd);
    close(pipe_fd[1]);

    // 第二次 splice: 从管道的读取端移动到标准输出
    if (splice(pipe_fd[0], NULL, STDOUT_FILENO, NULL, SSIZE_MAX, SPLICE_F_MOVE) == -1) {
        close(pipe_fd[0]);
        return 1;
    }

    close(pipe_fd[0]);
    return 0;
}
```