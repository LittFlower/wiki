# 家庭作业部分

1. 判断是不是小段法机器

```c
#include <stdio.h>

int is_little_endian() {
    int i = 1;
    return *(char *)&i;
}

int main() {
    int ret = is_little_endian();
    printf("%d",ret);
    return 0;
}
```

通过强转指针类型，用 `char` 型指针去检查 `i` 所在字中的第一个字节，如果是 0 则证明地址低位存放高字节，为大端法，如果是 1 则证明地址低位存放低字节，为小端法。


