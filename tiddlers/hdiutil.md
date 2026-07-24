## 1. 分析 hdiutil 的代码边界和涉及模块

可能包含的模块：

- Mach-O executable
- Framework / dylib
- XPC service
- launchd service
- bundle 中的 helper executable
- Objective-C 动态 operation class
- block callback
- 子进程 executable

先让 agent 分析这个程序涉及的模块范围，确定静态分析的范围

1. mac 上的原生程序 /usr/bin/hdiutil 和一些 framework 有sip保护，不能直接扔给 idalib headless 分析


把所有涉及到的程序模块的信息都保存下来

## 2. 确认漏洞模型

让 agent 分析第一步得到的程序模块有哪些已知历史漏洞