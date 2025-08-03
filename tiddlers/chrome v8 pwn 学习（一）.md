## 简介

> V8 是一个由 Google 开发的开源 JavaScript 引擎，用于 Google Chrome 及 Chromium 中，项目以V8发动机其命名。此项目由Lars Bak主导开发。
> ——摘自维基百科

JavaScript 是解释语言，需要先翻译成字节码后在 VM 上运行。V8 中实现了一个 VM。出于性能考虑，目前的引擎普遍采用一种叫做 Just-in-time (JIT) 的编译技术，V8 也是。JIT 的思想在于，如果一段代码反复执行，那么将其编译成机器代码运行，会比每次都解释要快得多。

v8 这个引擎编译出来的二进制文件为 d8，我们 Pwner 攻击的主要目标一般就是这个。

v8 的开源仓库在[这里](https://chromium.googlesource.com/v8/v8/)

## 环境搭建

### 最新版本

首先，由于需要大量在 google 的网站和 github 上下载代码，所以需要配置好代理，这里略过不表。

随后，先安装 depot_tools，arch linux 可以使用 aur 仓库里打包好的软件包，其他发行版可能需要 clone 项目[仓库](https://chromium.googlesource.com/chromium/tools/depot_tools.git)。这个工具包是用来管理 v8 代码的。

然后安装 ninja，arch linux 的 extra 仓库里有这个包，直接下就行，其他发行版可以自己 [clone](https://github.com/ninja-build/ninja.git) 编译。


然后编译 v8 代码即可，v8 的编译结果可以有两种，release 或者 debug 版本，我们一般使用 debug 版本方便调试。

```bash
$ fetch v8 && cd v8&& gclient sync
$ tools/dev/v8gen.py x64.debug
$ ninja -C out.gn/x64.debug
```

最终的可执行文件就在 out.gn 目录下。


### 配置题目环境

上面的方法一般只能编译最新版本的 v8 代码，而平常遇到的题目使用的可能是某个特殊的 commit，这就需要我们更灵活的配置环境。

回到 v8 目录，一般题目都会给出特殊的 commit id 和一个 diff 文件，所以，需要先把源码的版本 reset 到和题目一样的版本，然后再应用题目的 diff 文件：

```bash
$ git reset --hard <your_commit_id>
$ gclient sync
$ git apply < test.diff
```

然后重新编译即可：

```bash
$ tools/dev/v8gen.py x64.debug
$ ninja -C out.gn/x64.debug
```

### 报错修复

2025 年了，大部分的软件包依赖的都是 python3，不过 v8 这块一些比较老的 commit 可能依赖的还是 python2.7，而且哪怕你的发行版上安装了 python2，你的默认全局 python 依然是 python3，这就很难受了，这里提供一些解决措施。

首先，在 `gclient sync` 这一步时，由于系统 python 指向的是 python3，所以可能会报错类似下面这样：

```
Error: Command 'python v8/build/linux/sysroot_scripts/install-sysroot.py --arch=x86' returned non-zero exit status 1 in /home/flower/CTFhub/Tools/Pwn
File "/home/flower/CTFhub/Tools/Pwn/v8/build/linux/sysroot_scripts/install-sysroot.py", line 79
print GetSysrootDict(DEFAULT_TARGET_PLATFORM,
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
SyntaxError: Missing parentheses in call to 'print'. Did you mean print(...)?
```


我自己使用的解决方法有两个，一个是使用 pyenv 切换到 Python2.7，另一个办法是临时在当前 shell 中 `export PYTHON=python2`。

其次在 `tools/dev/v8gen.py x64.debug` 这里，第一次跑可能能需要安装 sysroot，这个报错信息里有：

```
$ tools/dev/v8gen.py x64.debug -vv
################################################################################
/usr/bin/python2 -u tools/mb/mb.py gen -f infra/mb/mb_config.pyl -m developer_default -b x64.debug out.gn/x64.debug

Writing """\
is_debug = true
target_cpu = "x64"
v8_enable_backtrace = true
v8_enable_slow_dchecks = true
v8_optimized_debug = false
""" to /home/flower/CTFhub/Tools/Pwn/v8/out.gn/x64.debug/args.gn.

/home/flower/CTFhub/Tools/Pwn/v8/buildtools/linux64/gn gen out.gn/x64.debug --check
-> returned 1
ERROR at //build/config/compiler/BUILD.gn:1138:22: Script returned non-zero exit code.
clang_revision = exec_script("//tools/clang/scripts/update.py",
^----------
Current dir: /home/flower/CTFhub/Tools/Pwn/v8/out.gn/x64.debug/
Command: python /home/flower/CTFhub/Tools/Pwn/v8/tools/clang/scripts/update.py --print-revision --verify-version=9.0.0
Returned 1.
stderr:

Traceback (most recent call last):
File "/home/flower/CTFhub/Tools/Pwn/v8/tools/clang/scripts/update.py", line 16, in <module>
import pipes
ModuleNotFoundError: No module named 'pipes'

See //BUILD.gn:260:5: which caused the file to be included.
"//build/config/compiler:wexit_time_destructors",
^-----------------------------------------------
GN gen failed: 1
Traceback (most recent call last):
File "tools/dev/v8gen.py", line 307, in <module>
sys.exit(gen.main())
File "tools/dev/v8gen.py", line 301, in main
return self._options.func()
File "tools/dev/v8gen.py", line 169, in cmd_gen
gn_outdir,
File "tools/dev/v8gen.py", line 211, in _call_cmd
stderr=subprocess.STDOUT,
File "/usr/lib/python2.7/subprocess.py", line 223, in check_output
raise CalledProcessError(retcode, cmd, output=output)
subprocess.CalledProcessError: Command '['/usr/bin/python2', '-u', 'tools/mb/mb.py', 'gen', '-f', 'infra/mb/mb_config.pyl', '-m', 'developer_default', '-b', 'x64.debug', 'out.gn/x64.debug']' returned non-zero exit status 1
```

然后对于找不到 `pipes` 这个模块，显然是因为系统使用了 python3 运行这个脚本，所以这里修改脚本的 bang 为 `#!/usr/bin/env python2` 就可以了，也可以 `export PYTHON=python2`

最后，`ninja -C out.gn/x64.debug` 编译时，可能会遇到

```
../../src/base/macros.h:246:7: error: builtin __has_trivial_copy is deprecated; use __is_trivially_copyable instead [-Werror,-Wdeprecated-builtins]
246 |       __has_trivial_copy(T) && __has_trivial_destructor(T);
|       ^
../../src/base/macros.h:246:32: error: builtin __has_trivial_destructor is deprecated; use __is_trivially_destructible instead [-Werror,-Wdeprecated-builtins]
246 |       __has_trivial_copy(T) && __has_trivial_destructor(T);
```

这种报错，也很简单，修改一下 `out.gn/x64.debug/args.gn` 的配置即可：

```gn
extra_cflags = [ "-Wno-deprecated-builtins" ]
treat_warnings_as_errors = false
```

这样就不会把 warnings 当成 errors 导致编译失败啦。

然后基本上就可以编译出一个符合题目环境要求的 d8 版本了。


### 调试

#### natives-syntax

`--allow-natives-syntax` 这个参数可以允许 d8 执行带有调试函数的 js 脚本。

也可以在 gdb 里用 `set args --allow-natives-syntax ./test.js` 达到一样的效果。

#### gdb

d8 实现了一些辅助调试的函数，并且提供了 gdb 脚本，以供在 gdb 中调用。在你的 gdbinit 文件中添加以下两行即可：

```gdbinit
source /path/to/v8/tools/gdbinit
source /path/to/v8/tools/gdb-v8-support.py
```

