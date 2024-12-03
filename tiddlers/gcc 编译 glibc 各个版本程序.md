```bash
gcc -std=c99 -g -Wno-unused-result -Wno-free-nonheap-object ./test.c -o test -ldl \
    -Xlinker -rpath=/home/flower/.../libs/2.27-3ubuntu1.5_amd64/ \
    -Xlinker -I/home/flower/.../libs/2.27-3ubuntu1.5_amd64/ld-linux-x86-64.so.2 \
    -Xlinker /home/flower/.../libs/2.27-3ubuntu1.5_amd64/libc.so.6
```