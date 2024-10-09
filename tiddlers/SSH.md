## 简介

OpenSSH（OpenBSD Secure Shell）是一组使用安全 Shell （SSH） 协议通过计算机网络提供加密通信会话的计算机程序。说直白点就是一个安全的远程 shell 程序。

OpenSSH 是专有 SSH 的开源替代方案，是 OpenBSD 的项目的一部分。

## 安装与启动

以下介绍了几个主流 Linux 发行版 SSH 的安装方法。

安装 OpenSSH 是在大多数 Linux 发行版上进行远程管理和连接的重要步骤。以下是几种主流发行版中安装 OpenSSH 的方法：

1. **Ubuntu/Debian 系**

在 Ubuntu 和基于 Debian 的系统上，可以使用 `apt` 包管理器安装 OpenSSH。

```bash
sudo apt update
sudo apt install openssh-server
```

安装完成后，服务会自动启动。可以使用以下命令检查 OpenSSH 服务状态：

```bash
sudo systemctl status ssh
```

如果服务没有自动启动，可以手动启动：

```bash
sudo systemctl start ssh
```

并设置为开机启动：

```bash
sudo systemctl enable ssh
```

2. **Fedora/CentOS/RHEL 系**

对于 Fedora、CentOS 和 Red Hat Enterprise Linux (RHEL) 系统，可以使用 `dnf` 或 `yum`
来安装 OpenSSH。

在 **Fedora** 上：

```bash
sudo dnf install openssh-server
```

在 **CentOS/RHEL** 上：

```bash
sudo yum install openssh-server
```

安装后，启动并启用服务：

```bash
sudo systemctl start sshd
sudo systemctl enable sshd
```

3. **Arch Linux**

在 Arch Linux 及其衍生发行版（如 Manjaro）上，使用 `pacman` 来安装 OpenSSH：

```bash
sudo pacman -S openssh
```

安装后，启动并启用服务：

```bash
sudo systemctl start sshd
sudo systemctl enable sshd
```
4. **openSUSE**

在 openSUSE 上，可以使用 `zypper` 包管理器安装 OpenSSH：

```bash
sudo zypper install openssh
```

安装完成后，启动并启用服务：

```bash
sudo systemctl start sshd
sudo systemctl enable sshd
```

5. **Gentoo**

在 Gentoo 上，使用 `emerge` 来安装 OpenSSH：

```bash
sudo emerge --ask net-misc/openssh
```

安装完成后，可以启动并启用服务：

```bash
sudo rc-service sshd start
sudo rc-update add sshd default
```

6. **Alpine Linux**

在轻量级的 Alpine Linux 上，使用 `apk` 包管理器安装 OpenSSH：

```bash
sudo apk add openssh
```

安装后，启动并启用服务：

```bash
sudo rc-service sshd start
sudo rc-update add sshd
```

## 客户端用法

### 密码认证

连接服务器：

```bash
$ ssh -p <port> <username>@<address>
```

### 公钥认证

也可以只使用公钥认证，公钥可以任意分享，私钥则必须安全的保存于本地磁盘。

** 生成密钥对 **

通过运行 ssh-keygen 命令可以生成密钥对，默认为3072位的 RSA（以及 SHA256），ssh-keygen 手册页称其“一般被认为充足”且应当兼容于几乎所有客户端和服务器：

```bash
$ ssh-keygen
Generating public/private rsa key pair.
Enter file in which to save the key (/home/<username>/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/<username>/.ssh/id_rsa.
Your public key has been saved in /home/<username>/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:gGJtSsV8BM+7w018d39Ji57F8iO6c0N2GZq3/RY2NhI username@hostname
The key's randomart image is:
+---[RSA 3072]----+
|   ooo.          |
|   oo+.          |
|  + +.+          |
| o +   +     E . |
|  .   . S . . =.o|
|     . + . . B+@o|
|      + .   oo*=O|
|       .   ..+=o+|
|           o=ooo+|
+----[SHA256]-----+
```
也可以用 -C 开关对公钥添加可选的注释栏，从而在 ~/.ssh/known_hosts、~/.ssh/authorized_keys 以及 ssh-add -L 输出等处更轻松地辨识它。例如：

```bash
$ ssh-keygen -C "$(whoami)@$(uname -n)-$(date -I)"
```

### 客户端配置

配置 `~/.ssh/config` 如下:

```bash
Host <myserver>
	Hostname <address>
	User <username>
	IdentityFile <pemFile>
```
