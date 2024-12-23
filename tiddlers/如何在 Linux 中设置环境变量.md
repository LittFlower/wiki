![如何在 Linux 中设置环境变量](https://chinese.freecodecamp.org/news/content/images/size/w2000/2023/01/Copy-of-Copy-of-read-write-files-python--3-.png)

**原文：** [How to Set an Environment Variable in Linux](https://www.freecodecamp.org/news/how-to-set-an-environment-variable-in-linux/)

在编程时，你使用变量来临时存储信息，如字符串和数字。

变量可以在整个代码中反复使用，或者由你的操作系统提供数值。你可以编辑它们、覆盖它们，并删除它们。

在本教程中，我将教你什么是环境变量以及如何在 Linux 中设置它们。

## 什么是环境变量

环境变量是特定环境中的变量。例如，操作系统中的每个用户都有自己的环境，一个管理员用户拥有与其他用户不同的环境。

你可能会声明一个只有你的用户需要的环境变量（例如一个秘密令牌），不需要暴露给其他用户。

下面是 Linux 中环境变量的一些例子：

* `USER` - 这指的是当前登录的用户。
* `HOME` - 这显示了当前用户的主目录。
* `SHELL` - 这存储了当前用户的 shell 路径，如 bash 或 zsh。
* `LANG` - 这个变量指向当前的语言 /locales 设置。
* `MAIL` - 这显示了当前用户的邮件存储的位置。

这些环境变量根据当前的用户会话而变化。

用于显示为当前会话定义的所有环境变量的命令是 `env`。

下面是我的会话的输出：

```
root@Zaira:~# env
SHELL=/bin/bash
PWD=/root
LOGNAME=root
HOME=/root
LANG=C.UTF-8
LESSOPEN=| /usr/bin/lesspipe %s
USER=root
SHLVL=1
XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
MAIL=/var/mail/root
_=/usr/bin/env
```

`env` 命令的输出

## 如何打印 Linux 中的环境变量

有两种方法可以打印已经定义的环境变量：

* `printenv VARIABLE_NAME`
* `echo $varname`

让我们用这两种方法来打印变量 `SHELL` 的值。下面是一个使用 `printenv` 打印的例子：

```
root@Zaira:~# printenv SHELL
/bin/bash
```

使用 `printenv` 打印环境变量值

这是一个使用 `echo` 的例子：

```
root@Zaira:~# echo $SHELL
/bin/bash
```

使用 `echo` 打印环境变量值

## 如何在 Linux 中设置环境变量

定义环境变量的基本语法如下：

```
export VARIABLE_NAME=value
```

我们来定义一个环境变量，列出它，并打印它的值。

* 定义变量 `JAVA_HOME`：

```
root@Zaira:~# export JAVA_HOME=/usr/bin/java
```

* 通过列出它来验证：

```
root@Zaira:~# env
SHELL=/bin/bash
JAVA_HOME=/usr/bin/java
PWD=/root
LOGNAME=root
HOME=/root
LANG=C.UTF-8
LESSCLOSE=/usr/bin/lesspipe %s %s
TERM=xterm-256color
global22=yolo
LESSOPEN=| /usr/bin/lesspipe %s
USER=root
SHLVL=1
XDG_DATA_DIRS=/usr/local/share:/usr/share:/var/lib/snapd/desktop
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
MAIL=/var/mail/root
_=/usr/bin/env
```

我们的变量 JAVA\_HOME 在 #2 行中被定义

* 打印它的值：

```
root@Zaira:~# echo $JAVA_HOME
/usr/bin/java
```

然而，使用这种方法定义的变量只存储在当前会话中。在下一个会话中不能使用它们。

让我们通过打开一个新的会话并打印变量的值来验证。

```
zaira@Zaira:/etc$ echo $JAVA_HOME
```

输出是空的

但是，我们可以让这些定义持久化，如下一节所示。

## 如何在 Linux 中使环境变量持久化

为了使 `JAVE_HOME` 变量持久化，编辑文件 `.bashrc` 并在其中定义其值。

`.bashrc` 是一个脚本文件，每当用户登录的时候就会执行。它是隐藏的，默认位于用户的主目录中。

我对我的 `.bashrc` 文件做了如下编辑：

```
vi ~/.bashrc
```

![image](https://chinese.freecodecamp.org/news/content/images/2023/01/image.png)

在 `.bashrc` 文件的末尾添加环境变量的定义

为了使这些变化生效，使用 `source` 命令更新 `.bashrc` 文件：

```
source .bashrc
```

让我们通过打开一个新的会话来验证。

```
root@Zaira:~# echo $JAVA_HOME
/usr/bin/java
```

这就是我们的变量！

## 如何在 Linux 中创建一个持久的全局变量

有时你可能需要定义一个所有用户都可以访问的全局环境变量。

为此，我们需要首先声明一个变量，并在读取环境变量的相关文件中进行修改。

让我们一步一步来。

1. 我以用户 `Zaira` 的身份登录。我正在创建一个全局变量 `GLOBAL_VARIABLE`，像这样：

```
zaira@Zaira:~$ export GLOBAL_VARIABLE="This is a global variable"
```

2\. 编辑以下文件：

* `/etc/environment` - 这个文件用来设置全系统的环境变量。

![image-1](https://chinese.freecodecamp.org/news/content/images/2023/01/image-1.png)

更新 `/etc/environment` 文件

为了使这些变化生效，请使用命令 `source /etc/environment`。

* `/etc/profile` - 只要登录了 bash shell，就会读取该文件中设置的变量。编辑这个文件并使用 `export` 命令：

![image-2](https://chinese.freecodecamp.org/news/content/images/2023/01/image-2.png)

更新 `/etc/profile`

是时候进行测试了！

现在，我将用户切换为根用户，并验证我是否可以访问变量 `GLOBAL_VARIABLE`。

```
root@Zaira:~# echo $GLOBAL_VARIABLE
This is a global variable
```

通过根用户访问全局变量

成功了！我能够通过 `root` 用户访问由用户 `Zaira` 定义的全局变量。这一点也适用于其他用户。所以现在你也知道如何定义全局环境变量了。

## 总结

在本教程中，你学会了如何在 Linux 中创建和定义环境变量。你还学会了如何使它们持久化，以便你可以在多个会话中使用它们。

你在这里学到的最喜欢的东西是什么？请在 [Twitter](https://twitter.com/hira_zaira) 上告诉我。

你可以在[这里](https://www.freecodecamp.org/news/author/zaira/)阅读我的其他文章。

图片来自 Freepik，作者 [catalyststuff](https://www.freepik.com/free-vector/hacker-operating-laptop-cartoon-icon-illustration-technology-icon-concept-isolated-flat-cartoon-style_11602236.htm#query=programmer\&position=2\&from_view=search\&track=sph)。
