这一章来介绍一下 v8 的内置定义。

参考文章：[chrome v8 pwn 学习 (1)](https://hornos3.github.io/2024/12/01/chrome-v8-pwn-%E5%AD%A6%E4%B9%A0-1/)

这一部分的知识主要是用在出题的时候，具体情景下我们可能需要自定义一些 v8 的函数，这个时候这部分知识就很有用了。

## Builtins

### Builtins Definitions

在v8中有很多的内置类型、方法与函数，包括基本类型（整数浮点数布尔值数组字符串等）等。这些内置类型在 builtins-definitions.h 中进行了定义（新版本位于builtins/builtins-definitions.h），下面是示例代码片段：

```
  /* ES6 #sec-array.prototype.pop */                                           \
  CPP(ArrayPop)                                                                \
  TFJ(ArrayPrototypePop, SharedFunctionInfo::kDontAdaptArgumentsSentinel)      \
  /* ES6 #sec-array.prototype.push */                                          \
  CPP(ArrayPush)                                                               \
  TFJ(ArrayPrototypePush, SharedFunctionInfo::kDontAdaptArgumentsSentinel)     \
  /* ES6 #sec-array.prototype.shift */                                         \
  CPP(ArrayShift)                                                              \
  /* ES6 #sec-array.prototype.unshift */                                       \
  CPP(ArrayUnshift)                                                            \
  /* Support for Array.from and other array-copying idioms */                  \
  TFS(CloneFastJSArray, kSource)                                               \
  TFS(CloneFastJSArrayFillingHoles, kSource)                                   \
```

这里的 `TFJ` 和 `TFS` 都是 v8 中定义的 TurboFan 优化宏定义，相较于直接调用底层 C++ 代码执行的 CPP 定义更加高效，`CPP` 宏的第一个参数是方法名，第二个参数中的 `kDontAdaptArgumentsSentinel` 指的是需要在 C++ 实现代码中通过 Receiver 自行完成函数参数的接收。

