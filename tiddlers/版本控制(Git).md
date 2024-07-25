# Git 的优雅与丑陋

Git 的命令行抽象接口很丑陋，以至于大多数时候只能死记硬背地使用它们，但是它的底层设计和思想确实十分优雅的。从数据模型到接口的一种“自底向上”方法更加易于学习。

# Git 的数据模型

## 快照

git 通过“快照”来管理其历史记录。一个快照就是对当前需要 git 管理的根目录的一次记录。

## 历史记录

每一次提交 (commit) 就是一次快照。 

对历史记录的建模实际上就是去关联快照，git 采取了 **有向无环图** 的形式。

git 中的快照是不可改变的。（当然这并不是说其完全无法修改）

## 细粒度数据模型

前面介绍了“快照是一个对当前根目录的完全记录”，也就是说，一个可能的结构如图：

```
<root> (tree)
|
+- foo (tree)
|  |
|  + bar.txt (blob, contents = "hello world")
|
+- baz.txt (blob, contents = "git is wonderful")
```


这其中涉及到两个数据模型，`tree` 和 `blob`，以下用伪代码的方式给出他们和与之相关的概念的定义：

```
// 文件是一组数据
type blob = array<bytes>

// 一个包含文件或目录的目录
type tree = map<string, tree | blob>

// 每个提交都包含一个父辈，元数据和顶层树
type commit = struct {
    parent: array<commit>
    author: string
    message: string
    snapshot: tree
}

```

## 对象和内存寻址

“对象”是 Git 在硬盘中真正存储的数据。

`type object = blob | tree | commit`

git 在储存数据时，所有的对象都会基于 SHA-1 哈希寻址，也就是说，所有的对象在引用其他对象时，不会直接使用其对应的硬盘上的数据，而是以哈希值作为引用。

例如，最开头例子里的 root tree 引用了 foo tree 和 baz.txt，所以它看上去应该是这样的：

```
100644 blob 4448adbf7ecd394f42ae135bbeed9676e894af85    baz.txt
040000 tree c68d233a33c5c06e0340e4c224f0afca87c8ce87    foo
```

而 baz.txt 本身并没有引用任何数据，所以你直接 `git cat-file -p 4448...` 会直接得到其内容: `git is wonderful`。

## 引用

引用是给提交使用人类可读的命名。

现在已经有一个基础的概念模型了，所有的快照都可以通过 SHA-1 哈希值标记。git 通过引用来进一步向提交（快照，commit）打标签。也就是说，引用是指向提交的指针。引用是可变的。

```
references = map<string, string>

def update_reference(name, id):
    references[name] = id

def read_reference(name):
    return references[name]

def load_reference(name_or_id):
    if name_or_id in references:
        return load(references[name_or_id])
    else:
        return load(name_or_id)
```

`HEAD` 引用总是指向当前正在查看的提交。


## 仓库

所有的 git 命令都是在对提交树进行操作。

定义为对象和引用。

## 暂存区

用于指定下次快照要包含哪些改动。

# 命令行接口

## 基础操作

1. `git add` 添加文件到暂存区
2. `git status` 查询 git 状态
3. `git log --all --graph --decorate` 以有向无环图形式展示提交日志
4. `git commit` 提交暂存区为快照（[[如何编写高质量的 commit 消息]]）
5. `git checkout` 用于改变 `HEAD` 指向的引用位置，实际上会改变工作区的内容，不填参数默认同步回 `HEAD` 引用处快照，也可以用来切换分支
6. `git diff <file>` 将现有的 file 与 HEAD 处比较，查看做了哪些修改，也可以查看给定两次提交之间的差异
7. `git branch` 可以用来访问新分支，或者列出当前分支(`-vv`)

## 进阶操作


1. `^` 和 `~<num>` 可以用作相对分支的标记，将 HEAD 移动到父提交
2. `git merge` 可以用来合并分支，如果自动合并冲突，使用 `git mergetools` 手动处理，然后 `git merge --continue` 即可正常合并
3. `git rebase` 变基操作，可以形成简洁的线性提交历史记录
> `git rebase <a> <b>` 是变基操作，会把 b 分支的提交应用到 a 上，因此只适合个人分支使用，以免造成仓库历史记录混乱；而 `git merge <a> <b>` 会生成一个新提交，其包含 a b，从操作树上可以直观地看出差别

4. `git reset` 可以撤销本地变更，但是撤销不彻底，会留下 refile
5. `git revert` 可以“撤销”远程变更，其会引入了一个新更改 —— 而这些更改刚好是用来撤销之前的更改的，其完全没有删除原有变更
6. `git filter-branch` 彻底清除某一个提交记录，建议用 `git filter-repo`

## 远程仓库

本地仓库储存在是 .git 里。

1. `git remote` 列出当前仓库所知的所有远程仓库
   - `git remote add <repo_name> <url>` 即可添加远程仓库
3. `git pull` 拉取远程至本地 == `git fetch <remote>` + `git merge`
4. `git push <remote> <local branch>:<remote branch>`
5. `git clone` 克隆远程仓库到本地

## 杂项

1. `git config` 配置 git
2. `git clone --shallow` 获取最新的快照，速度更快
3. `git add -p` 可以交互式地选择是否保留更改
4. `git blame` 确定快照的细粒度修改的提交
5. `git show` 查询指定提交的信息
6. `git stash` 将工作目录恢复到上次提交的地方，`git stash pop` 撤销；另外，这两个命令可以实现将 stash 储存的改动自由地选择提交到的分支
7. `git bisect` 对历史进行二分查找
8. `.gitignore` 可以指定忽略一些文件

## 资源

1. [learning Git game online](https://learngitbranching.js.org/?locale=zh_CN) 这个网站以游戏方式较为全面介绍了 Git 的多种使用方法

