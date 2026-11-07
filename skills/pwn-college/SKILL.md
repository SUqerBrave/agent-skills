---
name: pwn-college
description: pwn.college 学习助手。当用户提到 pwn.college、dojo 进度、学习进度、刷题进度、解题情况、CTF 学习、做pwn题、启动试题、开始挑战时使用。纯 Python 实现：查进度、列试题、启动 workspace、提交 flag、SSH 进容器，支持 agent 式全自动学习闭环。
allowed-tools: Bash(python:*), Bash(ssh:*), Read
---

# pwn.college 学习助手（纯 Python）

单文件脚本 `pwn_college.py`（与本 SKILL.md 同目录，仅用标准库）。原理：进度与试题均为服务端渲染 HTML（无对应 API），脚本用 urllib 带登录 cookie 抓取解析；启动/提交走 `/pwncollege_api/v1/`（带页面内嵌 CSRF nonce）。

## 命令一览

```sh
python pwn_college.py                            # dojo 总览（完成百分比排序）
python pwn_college.py setup                      # 首次: 交互式录凭据 (DPAPI/钥匙串加密)
python pwn_college.py <dojo>                     # 模块明细, 如 linux-luminarium
python pwn_college.py modules <dojo>             # 模块 slug 列表（模块名≠slug, 引用这里）
python pwn_college.py challenges <dojo> <module> # 试题列表 [x]/[ ] 解题状态
python pwn_college.py next <dojo>                # 按官方顺序下一个未解试题
python pwn_college.py start <dojo> <module> <challenge>         # 启动 workspace 容器
python pwn_college.py solve <dojo> <module> <challenge> <flag> # 提交 flag
python pwn_college.py ssh [远程命令...]           # SSH 进当前试题容器
```

## agent 式学习闭环

用户说"继续学/做下一题"时按此流程：

1. `python pwn_college.py next <dojo>` — 得到 module + challenge slug
2. `python pwn_college.py start <dojo> <module> <challenge>` — 启动容器（可能需 10-60s）
3. `python pwn_college.py ssh cat /challenge/<...>` 或读模块页描述，弄清题目要求
4. 在容器内完成动作/解题，**基础题固定套路**：
   - `/challenge/bin/<cmd>` 是 setuid 特权包装器（如 mv），按其报错提示执行正确动作
   - 动作正确后运行 `/challenge/check`（setuid），它会校验并**直接打印 flag**：`pwn.college{...}`
   - 高级题（pwn 类）：利用漏洞拿到 shell 后 `cat /flag`
5. `python pwn_college.py solve <dojo> <module> <challenge> "pwn.college{...}"` — 提交（返回 status: solved / already_solved / incorrect）
6. 重复 next。start 幂等，换题先 start 新题即可

Windows Git Bash 跑 ssh 子命令时远程命令若以 `/` 开头会被 MSYS 路径转换破坏，加 `MSYS_NO_PATHCONV=1` 前缀。

注意：module/challenge 一律用 slug（小写连字符），以 `modules`/`challenges` 输出为准，不要从显示名猜。SSH 私钥文件必须是 LF 行尾（CRLF 会导致 libcrypto 报错，`tr -d '\r'` 修复）。

## 登录与凭据（跨平台加密）

配置目录 `~/.config/pwn-progress/`（`PWNC_CONF_DIR` 可覆盖）：

| 平台 | 后端 | 依赖 |
|---|---|---|
| Windows | DPAPI 加密 `credentials.bin`（绑定当前用户） | 无 |
| Linux/macOS 桌面 | 系统钥匙串 | `pip install keyring` |
| headless | `PWNC_USER`/`PWNC_PASS` 环境变量（最高优先级）或 0600 明文文件 | 无 |

登录态 cookie 缓存 `cookies.txt`，失效自动重登。`user_agent` 用用户浏览器真实 UA 防 Cloudflare，缺省自动探测缓存，403 时提示更新。

SSH：默认 `~/.ssh/pwn.college.key` → `hacker@dojo.pwn.college:22`，可在 config.json 用 `ssh_key`/`ssh_user`/`ssh_host` 覆盖。SSH 前必须先 `start` 试题（容器绑定当前激活试题）。

安全约定：凭据只经用户手输给脚本，agent 不索要、不回显、不写入任何文件。

## 手动后备（浏览器在线时）

进度/试题也可用 opencli 在已登录页面解析（`opencli browser eval` + DOM 查询）；试题元素特征：`h4.challenge-name[data-challenge-id]` + 内层 `i.challenge-solved`。
