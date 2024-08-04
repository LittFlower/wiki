实际使用的是 Vim 的超集 Nvim。

# 配置结构

按照规范，Nvim 的配置目录在 `$HOME/.config/nvim` 里，目录结构如下：

```
nvim
├── init.lua
├── lazy-lock.json
└── lua
    ├── colorscheme.lua
    ├── config
    │   └── nvim-cmp.lua
    ├── keymaps.lua
    ├── lsp.lua
    ├── options.lua
    └── plugins.lua
```

其中 `init.lua` 存放 Nvim 的基本配置，一般用来包含引用模块文件；`Lazy-lock.json` 是插件 `Lazy.nvim` 产生的文件，不必理会；`lua/` 目录下是 Nvim 配置的所有模块：
- `keymaps.lua` 用于配置键盘快捷键绑定
- `options.lua` 用于配置选项
- `lsp.lua` 用于配置 Lsp
- `plugins.lua` 用于管理插件
- `colorscheme.lua` 用于配置主题
- `config` 目录下是各个插件的单独配置文件

# 基础配置

## 基础选项配置

这个工作主要由 `options.lua` 完成：

```lua
-- Hint: use `:h <option>` to figure out the meaning if needed
vim.opt.clipboard = 'unnamedplus' -- use system clipboard
vim.opt.completeopt = { 'menu', 'menuone', 'noselect' }
vim.opt.mouse = 'a' -- allow the mouse to be used in Nvim
vim.opt.autoread = true -- 被修改后自动同步 
vim.opt.completeopt = "menu,menuone,noselect,noinsert" -- 自动补全不自动选中
vim.opt.whichwrap = "<,>,[,]" -- vim 在行首/尾时可以左右
vim.opt.wildmenu = true -- 补全增强
vim.opt.pumheight = 7 -- 补全最多显示 7 行

-- backup
vim.opt.backup = false
vim.opt.writebackup = false
vim.opt.swapfile = false

-- Tab
vim.opt.tabstop = 4 -- number of visual spaces per TAB
vim.opt.softtabstop = 4 -- number of spacesin tab when editing
vim.opt.shiftwidth = 4 -- insert 4 spaces on a tab
vim.opt.expandtab = true -- tabs are spaces, mainly because of python

-- UI config
vim.opt.number = true -- show absolute number
vim.opt.relativenumber = true -- add numbers to each line on the left side
vim.opt.cursorline = true -- highlight cursor line underneath the cursor horizontally
vim.opt.splitbelow = true -- open new vertical split bottom
vim.opt.splitright = true -- open new horizontal splits right
vim.opt.termguicolors = true -- enable 24-bit RGB color in the TUI
vim.opt.showmode = true -- we are experienced, wo don't need the "-- INSERT --" mode hint
vim.opt.colorcolumn = "160" -- color line on code right
vim.opt.signcolumn = "yes" -- 显示左侧图标指示列
vim.opt.cmdheight = 1 -- 命令行行高为 2

-- Searching
vim.opt.incsearch = true -- search as characters are entered
vim.opt.hlsearch = true -- do not highlight matches
vim.opt.ignorecase = true -- ignore case in searches by default
vim.opt.smartcase = true -- but make it case sensitive if an uppercase is entered

```

## 按键映射

```lua
-- define common options
local opts = {
    noremap = true,      -- non-recursive
    silent = true,       -- do not show message
}

-----------------
-- Normal mode --
-----------------

-- Hint: see `:h vim.map.set()`
-- Better window navigation
-- vim.keymap.set('n', '<C-h>', '<C-w>h', opts)
-- vim.keymap.set('n', '<C-j>', '<C-w>j', opts)
-- vim.keymap.set('n', '<C-k>', '<C-w>k', opts)
-- vim.keymap.set('n', '<C-l>', '<C-w>l', opts)

vim.keymap.set('n', 'r', 'R', opts)

-- 分屏相关
vim.keymap.set('n', 'sv', ':vs<CR>', opts) -- 左右
vim.keymap.set('n', 'sh', ':sp<CR>', opts) -- 上下
vim.keymap.set('n', 'sw', '<C-w>c', opts) -- 关闭光标所在窗口
vim.keymap.set('n', 'so', '<C-w>o', opts) -- 关闭其他窗口

-- 切换窗口
vim.keymap.set('n', '<C-8>', '<C-w>k', opts)
vim.keymap.set('n', '<C-5>', '<C-w>j', opts)
vim.keymap.set('n', '<C-4>', '<C-w>h', opts)
vim.keymap.set('n', '<C-6>', '<C-w>l', opts)

-- 调整窗口比例
vim.keymap.set('n', '<A-S-Up>', ':resize +5<CR>', opts)
vim.keymap.set('n', '<A-S-Down>', ':resize -5<CR>', opts)
vim.keymap.set('n', '<A-S-Left>', ':vertical resize -5<CR>', opts)
vim.keymap.set('n', '<A-S-Right>', ':vertical resize +5<CR>', opts)

-- H 移动到行首，L 移动到行尾
vim.keymap.set('n', 'S-Right', '^', opts)
vim.keymap.set('n', 'S-Left', 'g_', opts)

-- 上下滚动浏览
vim.keymap.set('n', '<C-Down>', '6j', opts)
vim.keymap.set('n', '<C-Up>', '6k', opts)

-- 修改 Ctrl-u 和 Ctrl-d 的移动幅度 从默认的移动半瓶改为移动 9 行
vim.keymap.set('n', '<C-u>', '9k', opts)
vim.keymap.set('n', '<C-d>', '9j', opts)



-- 终端模式快捷键

-- <leader>t 开启终端
vim.keymap.set('n', '<C-t>', ':vsp | terminal<CR>i', opts) -- 左右
-- vim.keymap.set('n', '<leader>vt', ':sp | terminal<CR>', opt)

-- <Esc> 退出终端
vim.keymap.set('t', '<Esc>', '<C-\\><C-N>', opts)

-- 终端窗口中进行窗口切换
vim.keymap.set('t', '<C-S-Up>', [[ <C-\><C-N><C-w>k ]], opts)
vim.keymap.set('t', '<C-S-Down>', [[ <C-\><C-N><C-w>j ]], opts)
vim.keymap.set('t', '<C-S-Left>', [[ <C-\><C-N><C-w>h ]], opts)
vim.keymap.set('t', '<C-S-Right>', [[ <C-\><C-N><C-w>l ]], opts)



-----------------
-- Insert mode --
-----------------

-- 映射 jk 为 <Esc>
-- vim.keymap.set('i', 'jk', '<Esc>', opts)

-- 跳到行首行尾
vim.keymap.set('i', '<C-S-Left>', '<Esc>I', opts)
vim.keymap.set('i', '<C-S-Right>', '<Esc>A', opts)

-- 上下滚动浏览
vim.keymap.set('i', '<C-Down>', '<ESC>6ji', opts)
vim.keymap.set('i', '<C-Up>', '<ESC>6ki', opts)



-----------------
-- Visual mode --
-----------------

-- Hint: start visual mode with the same area as the previous area and the same mode
vim.keymap.set('v', '<', '<gv', opts)
vim.keymap.set('v', '>', '>gv', opts)
vim.keymap.set('v', 'S-Up', ":move '>+1<CR>gv-gv'", opts)
vim.keymap.set('v', 'S-Down', ":move '<-2<CR>gv-gv'", opts)

-- VISUAL 模式中粘贴的时候默认会复制被粘贴的文本 很反人类 不需要
vim.keymap.set('v', 'p', '"_dP', opts)

------------------
--- vim buffer ---
------------------
-- 左右 buffer 切换
vim.keymap.set("n", "<F1>", ":BufferLineCyclePrev<CR>", opts)
vim.keymap.set("n", "<F2>", ":BufferLineCycleNext<CR>", opts)
-- 关闭
--"moll/vim-bbye"
vim.keymap.set("n", "<C-w>", ":Bdelete!<CR>", opts)
-- vim.keymap.set("n", "<leader>bl", ":BufferLineCloseRight<CR>", opts)
-- vim.keymap.set("n", "<leader>bh", ":BufferLineCloseLeft<CR>", opts)
-- vim.keymap.set("n", "<leader>bc", ":BufferLinePickClose<CR>", opts)
-- define common options
local opts = {
    noremap = true,      -- non-recursive
    silent = true,       -- do not show message
}

-----------------
-- Normal mode --
-----------------

-- Hint: see `:h vim.map.set()`
-- Better window navigation
-- vim.keymap.set('n', '<C-h>', '<C-w>h', opts)
-- vim.keymap.set('n', '<C-j>', '<C-w>j', opts)
-- vim.keymap.set('n', '<C-k>', '<C-w>k', opts)
-- vim.keymap.set('n', '<C-l>', '<C-w>l', opts)

vim.keymap.set('n', 'r', 'R', opts)

-- 分屏相关
vim.keymap.set('n', 'sv', ':vs<CR>', opts) -- 左右
vim.keymap.set('n', 'sh', ':sp<CR>', opts) -- 上下
vim.keymap.set('n', 'sw', '<C-w>c', opts) -- 关闭光标所在窗口
vim.keymap.set('n', 'so', '<C-w>o', opts) -- 关闭其他窗口

-- 切换窗口
vim.keymap.set('n', '<C-8>', '<C-w>k', opts)
vim.keymap.set('n', '<C-5>', '<C-w>j', opts)
vim.keymap.set('n', '<C-4>', '<C-w>h', opts)
vim.keymap.set('n', '<C-6>', '<C-w>l', opts)

-- 调整窗口比例
vim.keymap.set('n', '<A-S-Up>', ':resize +5<CR>', opts)
vim.keymap.set('n', '<A-S-Down>', ':resize -5<CR>', opts)
vim.keymap.set('n', '<A-S-Left>', ':vertical resize -5<CR>', opts)
vim.keymap.set('n', '<A-S-Right>', ':vertical resize +5<CR>', opts)

-- H 移动到行首，L 移动到行尾
vim.keymap.set('n', 'S-Right', '^', opts)
vim.keymap.set('n', 'S-Left', 'g_', opts)

-- 上下滚动浏览
vim.keymap.set('n', '<C-Down>', '6j', opts)
vim.keymap.set('n', '<C-Up>', '6k', opts)

-- 修改 Ctrl-u 和 Ctrl-d 的移动幅度 从默认的移动半瓶改为移动 9 行
vim.keymap.set('n', '<C-u>', '9k', opts)
vim.keymap.set('n', '<C-d>', '9j', opts)



-- 终端模式快捷键

-- <leader>t 开启终端
vim.keymap.set('n', '<C-t>', ':vsp | terminal<CR>i', opts) -- 左右
-- vim.keymap.set('n', '<leader>vt', ':sp | terminal<CR>', opt)

-- <Esc> 退出终端
vim.keymap.set('t', '<Esc>', '<C-\\><C-N>', opts)

-- 终端窗口中进行窗口切换
vim.keymap.set('t', '<C-S-Up>', [[ <C-\><C-N><C-w>k ]], opts)
vim.keymap.set('t', '<C-S-Down>', [[ <C-\><C-N><C-w>j ]], opts)
vim.keymap.set('t', '<C-S-Left>', [[ <C-\><C-N><C-w>h ]], opts)
vim.keymap.set('t', '<C-S-Right>', [[ <C-\><C-N><C-w>l ]], opts)



-----------------
-- Insert mode --
-----------------

-- 映射 jk 为 <Esc>
-- vim.keymap.set('i', 'jk', '<Esc>', opts)

-- 跳到行首行尾
vim.keymap.set('i', '<C-S-Left>', '<Esc>I', opts)
vim.keymap.set('i', '<C-S-Right>', '<Esc>A', opts)

-- 上下滚动浏览
vim.keymap.set('i', '<C-Down>', '<ESC>6ji', opts)
vim.keymap.set('i', '<C-Up>', '<ESC>6ki', opts)



-----------------
-- Visual mode --
-----------------

-- Hint: start visual mode with the same area as the previous area and the same mode
vim.keymap.set('v', '<', '<gv', opts)
vim.keymap.set('v', '>', '>gv', opts)
vim.keymap.set('v', 'S-Up', ":move '>+1<CR>gv-gv'", opts)
vim.keymap.set('v', 'S-Down', ":move '<-2<CR>gv-gv'", opts)

-- VISUAL 模式中粘贴的时候默认会复制被粘贴的文本 很反人类 不需要
vim.keymap.set('v', 'p', '"_dP', opts)

------------------
--- vim buffer ---
------------------
-- 左右 buffer 切换
vim.keymap.set("n", "<F1>", ":BufferLineCyclePrev<CR>", opts)
vim.keymap.set("n", "<F2>", ":BufferLineCycleNext<CR>", opts)
-- 关闭
--"moll/vim-bbye"
vim.keymap.set("n", "<C-w>", ":Bdelete!<CR>", opts)
-- vim.keymap.set("n", "<leader>bl", ":BufferLineCloseRight<CR>", opts)
-- vim.keymap.set("n", "<leader>bh", ":BufferLineCloseLeft<CR>", opts)
-- vim.keymap.set("n", "<leader>bc", ":BufferLinePickClose<CR>", opts)
```


