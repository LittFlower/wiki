# headless-graph-prerender（demo 分支）

这是一个 TiddlyWiki 插件原型，用来演示“构建期无头图索引 + 运行期增量索引 + 自定义 filter/widget”的思路。它不是生产实现，也没有接入 TidGi 的插件安装/同步流程。

分支：`demo/headless-graph-prerender`

## 目录

```
plugins/headless-graph-prerender/
  plugin.info
  commands/prerender-graph.js     # --prerender-graph
  startup/index-daemon.js         # 内存索引 + 300ms 防抖增量更新
  filters/graph-operators.js      # hg-backlinks / hg-related / hg-orphans / hg-path
  widgets/backlink-panel.js       # <$backlink-panel>
  readme.tid / styles.tid

demo/headless-graph-prerender/
  wiki/                           # 10 个条目的演示 wiki
  run-demo.js                     # 1,200 条合成条目的索引/查询/增量/命令演示

tests/headless-graph-prerender.test.js
```

## 快速开始

```bash
npm install

# 索引、filter、增量更新和命令的完整演示
npm run demo:graph

# Node 单元测试
npm run test:graph

# 构建带插件的演示 wiki（输出到 demo/headless-graph-prerender/dist/index.html）
npm run build:graph-demo
```

也可以直接对演示 wiki 运行命令：

```bash
TIDDLYWIKI_PLUGIN_PATH=./plugins \
  npx tiddlywiki demo/headless-graph-prerender/wiki --prerender-graph
```

命令会把结果写入 `$:/temp/static-index/`：

| tiddler | 内容 |
| --- | --- |
| `summary` | 节点数、边数、词项数、片段数、耗时 |
| `graph.json` | `nodes[]` + 加权 `edges[]` |
| `terms.json` | `term -> [[title, tf], ...]` |
| `html/<encoded title>` | 每个条目的静态入链/出链 HTML 片段 |

## 索引模型

* 节点：非系统 tiddler（`$:/` 开头的不进图）。
* 显式边：`[[Target]]`、`[[text|Target]]`、`<$link to="Target">`，权重 `1.0`。
* transclusion：`{{Target}}` / `<$transclude>`，权重 `0.75`。
* 隐式边：标签，权重 `0.5`（同时作为带权反向链接）。
* `forwardMap`、`backlinkMap`、`termInvertedIndex` 都是 `Map`，查询走表而不是全库扫描。
* 文本分词：英文小写词 + 中文 bigram；不依赖词典。
* `hg-related`：TF-IDF cosine + 标签 Jaccard，默认排除已经直接相邻的条目。
* `hg-path`：BFS，默认无向、最大深度 4；`hg-path:8[Target]` 改深度，`hg-path:directed[Target]` 只走出链。

## 实测输出

在本机（macOS arm64 / Node 26.13.1 / TiddlyWiki 5.3.4）运行 `npm run demo:graph` 的一次输出（同一台机器上多次运行会在 40–90ms 之间波动）：

```text
prerender-graph: 1210 nodes, 1756 edges, 10100 terms, 1210 html fragments in 87ms (index 69ms, budget 1500ms)

=== headless-graph-prerender demo ===
tiddlers in wiki       : 1210
index nodes / edges     : 1210 / 1752
terms in inverted index : 10103
full rebuild            : 57.9 ms (budget 1500 ms)
single incremental edit : 0.5 ms (budget 15 ms)
--prerender-graph       : 87.2 ms

[hg-backlinks[0.5]] Synthetic 0001 -> ["Synthetic 0000"]
[hg-related[5]]     Synthetic 0001 -> ["Synthetic 0014","Synthetic 0105","Synthetic 0196","Synthetic 0287","Synthetic 0378"]
[hg-path]           0001 -> 0005   -> ["Synthetic 0001","Synthetic 0002","Synthetic 0003","Synthetic 0004","Synthetic 0005"]
[hg-orphans[]]      count=2 -> ["未连接笔记 A","未连接笔记 B"]
```

另外用仓库里真实的 `tiddlers/`（417 个文件，其中 138 个非系统条目）跑命令：

```text
prerender-graph: 138 nodes, 480 edges, 16110 terms, 138 html fragments in 110ms (index 103ms, budget 1500ms)
```

注意：

* 合成条目约 700 字符，带 8 个唯一 token；它们是用来压索引的，不代表真实笔记的文本分布。
* 真实 wiki 的 138 个条目有很多长代码笔记，词项数 16,110，比合成数据更能代表长文本。
* 这些数字是本机一次性测量，不是 CI 门槛；CI 里没有硬编码 1.5s/15ms 断言。

## 面板

```tw5
<$backlink-panel/>
<$backlink-panel tiddler="Demo - Home" limit="8"/>
<$backlink-panel mode="orphans" limit="10"/>
```

面板渲染入链（带权重）和 Top-N 潜在关联。索引在 `change` 事件后 300ms 刷新，面板只更新自己的 `innerHTML`；没有整页重绘。孤岛视图只读，不删除任何条目。

## 已知限制

* 只看静态 parse tree，宏/filter 动态生成的链接不会被捕获。
* 中文 bigram 有噪声，且没有停用词表之外的语义处理。
* 索引只在内存里，刷新后由 startup 重建；没有持久化，也没有和 `$:/temp/static-index/` 做恢复。
* `hg-related` 的候选集来自词项倒排，长文档 + 高频词时查询成本会上升；没有做 ANN 或提前截断。
* 没有处理插件/主题/语言 tiddler 的 shadow 关系；系统 tiddler 直接跳过。
* 没有为 TidGi 桌面版做插件打包，demo 分支只保证 `TIDDLYWIKI_PLUGIN_PATH=./plugins` 的加载方式可用。
