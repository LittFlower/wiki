## 是什么环境变量

参考这篇文章：[[如何在 Linux 中设置环境变量]]

## 几种配置方式

- /etc/profile
- /etc/environment
- ~/.zshrc or ~/.bash 等

这些文件的生效顺序如下：

- /etc/environment
- /etc/profile
- /etc/bashrc
- ~/.profile
- ~/.bashrc

## 配置文件

### 总览

| 配置文件         | 应用范围        | 加载时机                  | 作用                   |
|------------------|----------------|---------------------------|------------------------|
| `/etc/environment` | 全局（所有用户） | 系统初始化                | 定义基本环境变量        |
| `/etc/profile`     | 全局（所有用户） | 登录 shell                | 全局环境配置            |
| `/etc/bashrc`      | 全局（所有用户） | 非登录交互式 Bash shell   | Bash shell 配置        |
| `~/.profile`       | 当前用户        | 登录 shell                | 用户环境配置            |
| `~/.zshrc`         | 当前用户        | 所有交互式 Zsh shell      | 用户 Zsh 配置           |

### /etc/environment

#### 系统级服务启动时

在系统启动过程中或用户登录阶段使用。

在一些服务（如 systemd 管理的服务）启动时，/etc/environment 会被解析，服务进程会继承这些全局环境变量。

解析和加载是通过 PAM 模块（Pluggable Authentication Module）完成的。

- 具体来说，pam_env 模块会读取 /etc/environment 中的变量。
- 这是系统初始化过程中加载的最早阶段之一，服务会在启动时继承这些变量。

#### 用户登录时

当用户登录系统时，/etc/environment 会再次被解析，用来设置用户会话的基础环境变量。

这同样是通过 PAM 完成的（PAM 会话模块加载）。

- 不论是通过 GUI（如 LightDM、GDM 等桌面登录管理器），还是通过终端登录，都会执行此步骤。

#### 