项目地址：https://github.com/shareAI-lab/learn-claude-code

## 0x0. 关于 Agent 和 Harness

Agent = 模型 + Harness

现在（2025年及之后）常说的“开发 Agent” 可能大概率都是开发 Harness，因为训练模型是 DeepMind、OpenAI、腾讯 AI Lab、Anthropic 在做的事。

模型调用御三家的 API，开发者设计一个良好的 Harness 辅助模型完成决策。

## 0x1. 工具与执行

### Agent Loop


> "One loop & Bash is all you need"
>

如图：

```
    +----------+      +-------+      +---------+
    |   User   | ---> |  LLM  | ---> |  Tool   |
    |  prompt  |      |       |      | execute |
    +----------+      +---+---+      +----+----+
                          ^               |
                          |   tool_result |
                          +---------------+
                          (loop continues)
```

维护一个 `messages[]`，用来存储消息，这玩意其实就是常说的“上下文”。

1. 将用户提示词和**工具初始定义**整理到 `messages[]` 里
2. 将 `messages[]` 发给 LLM，拿到 `response`
3. 将 `response` 里的 `tool_use` 提取出来，然后**用 Bash 处理**，将运行结果作为 `tool_result` 添加到 `messages[]` 里，重复第 2 步
4. 直到 `response` 里不再调用 tool

代码实现参考项目仓库，非常清晰。

```python
def agent_loop(query):
    messages = [{"role": "user", "content": query}]
    while True:
        response = client.messages.create(
            model=MODEL, system=SYSTEM, messages=messages,
            tools=TOOLS, max_tokens=8000,
        )
        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason != "tool_use":
            return

        results = []
        for block in response.content:
            if block.type == "tool_use":
                output = run_bash(block.input["command"])
                results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": output,
                })
        messages.append({"role": "user", "content": results})
```


### Tool Use

bash 很好，但还不够。bash 的优点是可以完成绝大部分 Linux 常见任务，而不需要给模型发送过多的工具定义（schema）。过多的工具定义会增加模型理解的负担

bash 的缺点是缺少约束，功能太强以至于会暴露过多的安全面。

仅仅使用 bash 当然可以完成读写文件这类任务，但这被认为是不安全的。使用 `read_file` `write_file` `edit_file` 这类封装提供安全性。

```
+--------+      +-------+       +------------------+
|  User  | ---> |  LLM  | ----> | Tool Dispatch    |
| prompt |      |       |       | {                |
+--------+      +---+---+       |   bash: run_bash |
                    ^           |   read: run_read |
                    |           |   write: run_wr  |
                    +-----------+   edit: run_edit |
                    tool_result | }                |
                                +------------------+

The dispatch map is a dict: {tool_name: handler_function}.
One lookup replaces any if/elif chain.
```


封装这几个必要的工具，其余流程不变。

几个问题：

1. 模型是如何确认 agent 支持哪些工具的？如何处理模型调用“臆想”中的工具？

发送给模型时提前声明好工具定义，agent 处理 tool_use 再校验一次工具名，不存在则添加报错到 `messages[]` 里。



## 0x2. 规划与协调


### TodoWrite

多步任务中, 模型会丢失进度 -- 重复做过的事、跳步、跑偏。通过实现并长期维护一个 todo list，可以辅助模型保持注意力。

感觉其实就是一个用来持久化状态的数据结构。


```
    +----------+      +-------+      +---------+
    |   User   | ---> |  LLM  | ---> | Tools   |
    |  prompt  |      |       |      | + todo  |
    +----------+      +---+---+      +----+----+
                          ^               |
                          |   tool_result |
                          +---------------+
                                |
                    +-----------+-----------+
                    | TodoManager state     |
                    | [ ] task A            |
                    | [>] task B <- doing   |
                    | [x] task C            |
                    +-----------------------+
                                |
                    if rounds_since_todo >= 3:
                      inject <reminder>
```

具体实现方式是通过把这个 `TodoManager` 作为一个 tool 实现，让模型自觉去调用这个 `TodoManager` 管理任务计划，假如模型不自觉（也就是三轮以上没有调用 todo）就通过注入 `reminder` 的方式强制提醒它。

模型每次调用玩 `todo update` 工具，后者会更新 `item[]` 然后把新的状态作为 `tool_result` 继续发给模型辅助下一次决策。


### Subagent

`subagent` 的设计思想参考 linux "parent/child" 进程设计，父子进程上下文之间完全隔离，父模型给子模型

```
Parent agent                     Subagent
+------------------+             +------------------+
| messages=[...]   |             | messages=[]      | <-- fresh
|                  |  dispatch   |                  |
| tool: task       | ----------> | while tool_use:  |
|   prompt="..."   |             |   call tools     |
|                  |  summary    |   append results |
|   result = "..." | <---------- | return last text |
+------------------+             +------------------+

Parent context stays clean. Subagent context is discarded.
```

新加一个 `task` 工具，负责开 subagent，这个工具不传递给 subagent 避免递归调用。显然如果一个任务需要多次分解，应该由父 agent 开多个子 agent 而不是由父 agent 开一个子 agent 再由这个子 agent 循环开多个子 agent。

当父代理通过 Task 工具创建子代理时，子代理从全新的消息历史开始，只包含系统提示词和委派的任务描述。

这个任务描述也是由父 agent 的模型思考生成的，然后转发给子 agent。

子 agent 的上下文也没必要保存，直接把结果发送回父 agent 即可。


### Skills

所谓 `skills` 就是封装好的知识（工作流），对于 agent 来说，用到什么知识，临时加载什么知识。通过 `tool_result` 注入，而不是塞到 system prompt 里。

实现方案是分两层：第一层: 系统提示中放 Skill 名称 (低成本)。第二层: tool_result 中按需放完整内容。


每个 skill 也是分层实现的：第一层是 YAML frontmatter（名称、描述、globs），第二层才是 markdown 正文（实际指令）。

对于 agent：

1. 它通过 `SkillLoader` 扫描 skills 文件夹，并获取 `frontmatter` 作为 meta data，这可以让模型知道现在有什么 skills
2. 当模型要调用某个 skill，则调用 `load_skill` **工具**单独获取这个 skill 的详细内容，然后添加到 `tool_result` 里。

这样就相当于给 LLM 实现了一个按需加载的知识库。


问题：

1. 为什么不放到 system prompt 里？

浪费 token，降低缓存命中率，而且干扰模型判断。


### Task System

TodoManager 只是内存中的扁平清单: 没有顺序、没有依赖、状态只有做完没做完。真实目标是有结构的 -- 任务 B 依赖任务 A, 任务 C 和 D 可以并行, 任务 E 要等 C 和 D 都完成。

没有显式的关系, Agent 分不清什么能做、什么被卡住、什么能同时跑。而且内存是是易失的，无法信赖。

解决方法是对 `TodoManager` 做 DAG 排序（任务图），然后落到磁盘上。

1. 维护一个 `.tasks` 文件夹，每个任务是一个 JSON 文件，有状态、前置依赖 (`blockedBy`)。状态包括：`completed`、`pending`、`in_progress`。
2. 维护一个 `TaskManager` 类，负责管理前面说到的任务图和 `.tasks/`，主要实现增删查改的操作
	* `create`：Create a new task.
	* `update`: Update a task's status or dependencies.
	* `list_all`: List all tasks with status summary.
	* `get`: Get full details of a task by ID.
3. 实现四个工具 `task_create` `task_update` `task_list` `task_get`，暴露给 LLM

关于任务图（DAG），

DAG 的节点是一个独立 JSON 节点，大概如下：

```
  {
    "id": 1,
    "subject": "...",
    "description": "...",
    "status": "pending",
    "blockedBy": [],
    "owner": ""
  }
```

>  维护流程：
>
>  1. TaskManager.create() 创建新节点，默认 status = pending，blockedBy = []，然后写入 `.tasks/task_<id>.json`。
>  2. TaskManager.update() 可通过 addBlockedBy 给某个 task 增加依赖边，也可通过 removeBlockedBy 删除依赖边。
>  3. 当某个 task 被更新为 completed 时，update() 会调用 `_clear_dependency(task_id)`。
>  4. `_clear_dependency()` 遍历所有 .tasks/task_*.json，如果其他 task 的 blockedBy 包含已完成的 task id，就把它移除并保存。
>  5. task_list() 只是读取所有 JSON，按 id 排序展示状态；如果 blockedBy 非空，就显示 (blocked by: [...])。

DAG 的边不是正向存储为 `dependsOn` -> `children`，而是反向存在每个节点的 `blockedBy` 字段里。比如 task 2 的 `blockedBy: [1]` 表示 task 2 依赖 task1，只有 task 1 完成后 task 2 才不再被阻塞。

另外，个人感觉这个文件夹其实可以有更好的支持原子写入的实现方式，直接用文件夹可能会导致后续多 agent 并发时出错。
