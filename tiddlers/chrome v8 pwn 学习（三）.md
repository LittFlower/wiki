这一章来介绍一下 v8 的内置定义。

参考文章：[chrome v8 pwn 学习 (1)](https://hornos3.github.io/2024/12/01/chrome-v8-pwn-%E5%AD%A6%E4%B9%A0-1/)

## Builtins

### Builtins Definitions

在v8中有很多的内置类型、方法与函数，包括基本类型（整数浮点数布尔值数组字符串等）等。这些内置类型在builtins-definitions.h中进行了定义（新版本位于builtins/builtins-definitions.h），下面是示例代码片段：



