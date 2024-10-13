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

3. **Arch Linux**

在 Arch Linux 及其衍生发行版（如 Manjaro）上，使用 `pacman` 来安装 OpenSSH：

```bash
sudo pacman -S openssh
```

4. **openSUSE**

在 openSUSE 上，可以使用 `zypper` 包管理器安装 OpenSSH：

```bash
sudo zypper install openssh
```

5. **Gentoo**

在 Gentoo 上，使用 `emerge` 来安装 OpenSSH：

```bash
sudo emerge --ask net-misc/openssh
```

6. **Alpine Linux**

在轻量级的 Alpine Linux 上，使用 `apk` 包管理器安装 OpenSSH：

```bash
sudo apk add openssh
```

## 客户端用法

### 密码认证

密码认证的登陆流程：

![](https://pic.imgdb.cn/item/670b8ef3d29ded1a8ce798a2.png)


连接服务器：

```bash
$ ssh -p <port> <username>@<address>
```

### 公钥认证

ssh 的认证逻辑大概是这样的：

1. Client 将自己的公钥存放在 Server 上，追加在文件 authorized_keys 中。
2. Server 端接收到 Client 的连接请求后，会在 authorized_keys 中匹配到 Client 的公钥 pubKey，并生成随机数 R，用 Client 的公钥对该随机数进行加密得到 pubKey，然后将加密后信息发送给 Client。
3. Client 端通过私钥进行解密得到随机数 R，然后对随机数 R 和本次会话的 SessionKey 利用 MD5 生成摘要 Digest1，发送给 Server 端。
4. Server 端会也会对 R 和 SessionKey 利用同样摘要算法生成 Digest2。
5. Server 端会最后比较 Digest1 和 Digest2 是否相同，完成认证过程。

也可以只使用公钥认证，公钥可以任意分享，私钥则必须安全的保存于本地磁盘。

**生成密钥对**

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
可以方便的配置多个远程服务器进行连接。

## 服务端用法

首先在客户端本地生成一个 SSH 密钥对，方法同上。

然后分发公钥到目标服务器的 `~/.ssh/authorized_keys` 上：

`ssh-copy-id username@remote_host`

之后就可以通过 `ssh username@remote_host` 登陆了。

写个简单的脚本，自动化如下：

```bash
#!/bin/bash

# 定义远程服务器列表
SERVERS=("server1.example.com" "server2.example.com" "server3.example.com")
USER="your_username"

# 检查是否存在公钥，不存在则生成
if [ ! -f ~/.ssh/id_rsa.pub ]; then
    echo "公钥不存在，正在生成..."
    ssh-keygen -t rsa -b 4096 -N "" -f ~/.ssh/newKey
fi

# 分发公钥到每个服务器
for SERVER in "${SERVERS[@]}"; do
    echo "正在分发公钥到 $SERVER..."
    ssh-copy-id "$USER@$SERVER"
    if [ $? -eq 0 ]; then
        echo "成功将公钥添加到 $SERVER"
    else
        echo "无法将公钥添加到 $SERVER"
    fi
done

echo "公钥分发完成"
```

## SSHFS

SSHFS（SSH Filesystem）允许你通过 SSH 协议将远程文件系统挂载到本地，使得远程文件像本地文件一样访问和操作。以下是使用 SSHFS 进行基本文件共享的步骤和示例。

### 安装 SSHFS

首先，确保在客户端和服务器上安装了 SSHFS。

在 ArchLinux 上安装 SSHFS：

```bash
sudo pacman -S sshfs
```

在 Debian/Ubuntu 上安装 SSHFS：

```bash
sudo apt-get update
sudo apt-get install sshfs
```

### 基本使用步骤

#### 创建本地挂载点

选择一个目录作为挂载点，例如 `/mnt/remote`：

```bash
mkdir -p ~/mnt/remote
```

#### 挂载远程文件系统

使用 sshfs 命令挂载远程目录：

```bash
sshfs username@remote_host:/path/to/remote/directory ~/mnt/remote
```

**参数说明**：

- `username@remote_host`：远程服务器的用户名和主机名/IP。
- `/path/to/remote/directory`：远程服务器上要挂载的目录路径。
- `~/mnt/remote`：本地挂载点。

#### 验证挂载

挂载成功后，可以通过 ls 或其他文件操作命令访问远程文件：

```bash
ls ~/mnt/remote
```

#### 卸载远程文件系统

当不再需要访问远程文件时，可以卸载：

```bash
fusermount -u ~/mnt/remote
```

或者在 macOS 上：

### 挂载选项示例
sshfs 提供了多种挂载选项，可以根据需求进行配置。例如，使用缓存和身份验证选项：

```bash
sshfs -o reconnect,ServerAliveInterval=15,ServerAliveCountMax=3 username@remote_host:/path/to/remote/directory ~/mnt/remote
```

常用选项说明：
	
- `o reconnect`：断线后自动重新连接。
- `ServerAliveInterval` 和 `ServerAliveCountMax`：保持连接活跃，防止断开。
- `o IdentityFile=~/.ssh/id_rsa`：指定使用的私钥文件。

### 自动挂载（可选）
为了在系统启动时自动挂载远程文件系统，可以将挂载命令添加到 ~/.bashrc 或使用 systemd 服务。

#### 使用 systemd 服务示例：

创建文件 ~/.config/systemd/user/remote.mount，内容如下：

```ini
[Unit]
Description=SSHFS Mount for Remote Directory

[Mount]
What=username@remote_host:/path/to/remote/directory
Where=/home/your_username/mnt/remote
Type=fuse.sshfs
Options=defaults,_netdev,users,idmap=user,IdentityFile=/home/your_username/.ssh/id_rsa,reconnect,ServerAliveInterval=15,ServerAliveCountMax=3

[Install]
WantedBy=default.target
```

注意事项：

- 确保 SSH 无需密码登录（使用前述公钥验证）。
- 调整 Where 和 What 路径为实际使用的路径。
- 根据需要调整挂载选项。

